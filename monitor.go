package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// The health monitor checks every running tunnel once a minute. It sends a Telegram alert
// when one goes down (after two failed checks in a row, so a blip doesn't page you) and
// when it comes back, starts automatic failover after failoverAfter, and re-tests the
// original path of failed-over tunnels every failbackEvery.
const (
	monitorEvery = time.Minute
	monitorFails = 2
	// a hot-standby tunnel whose users' path stays dead this long with both servers
	// answering is applied again (at most once per hsRebuildEvery): the switcher can't help
	// when every path is gone (seen live: netherlands-iran rebooted and its paths never
	// came back — down 20 min until applied by hand)
	hsRebuildAfter = 5 * time.Minute
	hsRebuildEvery = 30 * time.Minute
)

var (
	hsRebuildMu   sync.Mutex
	hsRebuildLast = map[string]time.Time{} // tunnel id -> last automatic re-apply
)

// hsRebuildable: the check failed in a way a re-apply fixes — the switcher answered and the
// users' path is dead, or the switcher's files are gone — not just the panel failing to
// reach the switcher (a flaky SSH must never get a working tunnel rebuilt).
func hsRebuildable(reason string) bool {
	return strings.HasPrefix(reason, "tunnel link down") || strings.Contains(reason, "exited with status 3")
}

// hsRebuild applies a dead hot-standby tunnel again (its own method and family).
func (a *App) hsRebuild(t *Tunnel, reason string, down time.Duration) {
	hsRebuildMu.Lock()
	if time.Since(hsRebuildLast[t.ID]) < hsRebuildEvery {
		hsRebuildMu.Unlock()
		return
	}
	hsRebuildLast[t.ID] = time.Now()
	hsRebuildMu.Unlock()
	var name, mid, fam string
	a.store.View(func(*State) { name, mid, fam = t.Name, t.Active, t.Family })
	if mid == "" {
		return // stopped meanwhile
	}
	a.pushT(t, fmt.Sprintf("🔄 %s: down for %s with both servers answering (%s) — applying it again", name, shortDur(down), reason))
	if _, err := a.ApplyRoute(t, mid, fam); err != nil {
		a.pushT(t, fmt.Sprintf("❌ %s: could not apply it again — %v", name, err))
	}
}

type tunnelHealth struct {
	outageID        string
	fails           int
	alerted         bool
	downSince       time.Time
	reason          string
	lastOutage      time.Duration
	failoverStarted bool
}

// step records one check ("" = healthy) and returns "down" or "up" when an alert is due.
func (h *tunnelHealth) step(reason string, now time.Time) string {
	if reason != "" {
		h.fails++
		if h.fails == 1 {
			h.downSince = now
		}
		h.reason = reason
		if h.fails >= monitorFails && !h.alerted {
			h.alerted = true
			return "down"
		}
		return ""
	}
	was := h.alerted
	if h.fails > 0 {
		h.lastOutage = now.Sub(h.downSince)
	}
	h.fails, h.alerted, h.reason, h.failoverStarted = 0, false, "", false
	if was {
		return "up"
	}
	return ""
}

func (a *App) healthMonitor() {
	state := map[string]*tunnelHealth{}
	var mu sync.Mutex
	for {
		time.Sleep(monitorEvery)
		var ts []*Tunnel
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.Active != "" {
					ts = append(ts, t)
				}
			}
		})
		live := map[string]bool{}
		// tunnels being applied or failed over briefly show Active == "": keep their state
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if a.jobs.running(t.ID) != "" || a.jobs.running(failoverJobKey+t.ID) != "" {
					live[t.ID] = true
				}
			}
		})
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		for _, t := range ts {
			live[t.ID] = true
			if a.jobs.running(t.ID) != "" || a.jobs.running(failoverJobKey+t.ID) != "" {
				continue // being applied/stopped/tested/failed over right now
			}
			wg.Add(1)
			go func(t *Tunnel) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				reason := a.checkHealth(ctx, t)
				mu.Lock()
				defer mu.Unlock()
				h := state[t.ID]
				if h == nil {
					h = &tunnelHealth{}
					state[t.ID] = h
				}
				switch h.step(reason, time.Now()) {
				case "down":
					extra := ""
					if !t.NoFailover {
						extra = fmt.Sprintf("\nAutomatic failover starts if it is still down after %s.", failoverAfter)
					}
					cause := a.tunnelCause(t)
					h.outageID = newID()
					a.addOutage(Outage{ID: h.outageID, Kind: "tunnel", Target: t.ID, Name: t.Name, Start: h.downSince.Unix(), Reason: reason, Cause: cause})
					a.pushT(t, fmt.Sprintf("🔴 Tunnel DOWN: %s\n%s\n(%s → %s)\nsince %s (Tehran)\n%s%s", t.Name, reason, serverName(a, t.ServerID), foreignName(a, t), clock(h.downSince), cause, extra))
				case "up":
					now := time.Now()
					if h.outageID != "" {
						a.endOutage(h.outageID, now)
						h.outageID = ""
					}
					a.pushT(t, fmt.Sprintf("🟢 Tunnel back up: %s\ndown %s\n%s → %s (Tehran)", t.Name, shortDur(h.lastOutage), clock(now.Add(-h.lastOutage)), clock(now)))
				}
				switch {
				case t.HotStandby && reason != "" && hsRebuildable(reason) && !h.failoverStarted && time.Since(h.downSince) >= hsRebuildAfter &&
					a.serverReachable(t.ServerID) && (t.ForeignID == "" || a.serverReachable(t.ForeignID)) && !a.trafficFlowing(t.ID):
					// every path dead and the switcher can't help: build it again — unless users'
					// traffic is flowing both ways, which proves the switcher's checks wrong and a
					// re-apply would only cut them
					h.failoverStarted = true
					go a.hsRebuild(t, reason, time.Since(h.downSince))
				case t.HotStandby && reason == "" && len(a.hsRetryDue(t, time.Now())) > 0:
					// a healthy tunnel with a path that could not start: that one path is
					// tried again (hsretry.go) — the users stay where they are
					go a.hsRetryFailed(t)
				case t.HotStandby:
					// the switcher on the Iran server moves the users itself
				case reason != "" && !t.NoFailover && !h.failoverStarted && time.Since(h.downSince) >= failoverAfter && time.Now().After(a.failoverNotBefore(t.ID)):
					h.failoverStarted = true
					go a.Failover(t, reason)
				case reason == "" && t.Failover != nil && time.Since(time.Unix(t.Failover.LastCheck, 0)) >= failbackEvery:
					go a.Failback(t)
				}
			}(t)
		}
		wg.Wait()
		mu.Lock()
		for id := range state {
			if !live[id] {
				if h := state[id]; h.outageID != "" {
					a.endOutage(h.outageID, time.Now()) // stopped by hand while down
				}
				delete(state, id) // stopped or deleted: no alerts
			}
		}
		mu.Unlock()
	}
}

// healthReason turns a Health result into "" (healthy) or what is wrong.
func healthReason(ir, kh, link string) string {
	switch {
	case ir == "unreachable":
		return "Iran server unreachable"
	case ir != "active":
		return "Iran service " + ir
	case kh == "unreachable":
		return "foreign server unreachable"
	case kh != "active":
		return "foreign service " + kh
	case link == "down":
		return "tunnel link down (no traffic between the servers)"
	}
	return ""
}

// checkHealth runs one health check and stores the verdict for the cards and the bot.
func (a *App) checkHealth(ctx context.Context, t *Tunnel) string {
	reason := healthReason(a.Health(ctx, t))
	if reason != "" {
		reason += a.premiumLicenseNote(ctx, t, reason)
	}
	a.healthMu.Lock()
	if a.healthCache == nil {
		a.healthCache = map[string]string{}
	}
	a.healthCache[t.ID] = reason
	a.healthMu.Unlock()
	return reason
}

// clearHealth forgets the monitor's verdict on a tunnel whose method is being changed or
// stopped: the old method's "down" must not paint the new one red until the next check.
func (a *App) clearHealth(id string) {
	a.healthMu.Lock()
	delete(a.healthCache, id)
	a.healthMu.Unlock()
}

// cachedHealth is the monitor's last verdict: "ok", a reason, or "" when not checked yet.
func (a *App) cachedHealth(id string) (string, bool) {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	r, ok := a.healthCache[id]
	return r, ok
}

func foreignName(a *App, t *Tunnel) string {
	if t.ForeignID == "" {
		return "this panel host"
	}
	return serverName(a, t.ForeignID)
}

// premiumLicenseNote: a Backhaul Premium tunnel that is down says why when the core's own
// license check is the reason (it stops on a bad verdict, and the card only showed "failed").
func (a *App) premiumLicenseNote(ctx context.Context, t *Tunnel, reason string) string {
	var active string
	a.store.View(func(*State) { active = t.Active })
	if active != "premium" && active != "premium1" {
		return ""
	}
	var h Host
	switch {
	case strings.HasPrefix(reason, "Iran service"):
		if srv := a.store.Server(t.ServerID); srv != nil {
			h, _, _ = a.reach(ctx, srv, nil)
		}
	case strings.HasPrefix(reason, "foreign service"):
		h, _, _ = a.foreignHost(ctx, t, nil)
	}
	if h == nil {
		return ""
	}
	out, _ := h.Run(ctx, "journalctl -u "+unitName(t)+" -n 200 --no-pager -o cat 2>/dev/null | sed 's/\\x1b\\[[0-9;]*m//g' | grep -i -E 'licen[cs]e (ip|does not|has expired|is expired|is invalid|status unknown|issue)|invalid license' | tail -1 | sed 's/^.*\\] *//'", nil)
	if l := strings.TrimSpace(lastLine(out)); l != "" {
		return " — Backhaul Premium license: " + l
	}
	return ""
}
