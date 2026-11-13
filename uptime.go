package main

import (
	"sort"
	"time"
)

// Uptime on the Tunnels list and the Servers page comes from the outage log the monitors
// already keep (servermon.go, monitor.go) — no probe of its own. A tunnel's outages are its
// users' outages: the health check of a hot-standby tunnel asks the switcher whether the
// users' path works, and an outage needs two failed checks a minute apart, so a switch to
// another path (seconds) never makes one and never resets the uptime. A server's are the
// SSH monitor's (IPv4-only / IPv6-only drops don't count: the server was up). The log is
// capped and can be cleared, so State.OutagesFrom says how far back it is complete: with no
// outage since then, a target is "up at least since" that time.

// UpOutage is one outage of a target, for the Servers page's "last outages".
type UpOutage struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end,omitempty"` // 0 = still going on
	Why    string `json:"why"`           // reboot | network | ssh | panel (servers); tunnel
	Others int    `json:"others,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// UptimeView is a server's or tunnel's uptime as the UI shows it.
type UptimeView struct {
	Now    int64      `json:"now"`
	Down   bool       `json:"down"`
	Since  int64      `json:"since,omitempty"` // down: since; up: since the last outage ended (0 = none since From)
	From   int64      `json:"from"`            // the log is complete from here
	A24    float64    `json:"a24"`             // % of the last 24 h it was up (-1 = no history yet)
	A7     float64    `json:"a7"`              // and of the last 7 days
	N7     int        `json:"n7"`              // outages in the last 7 days
	Recent []UpOutage `json:"recent,omitempty"`
	Boot   int64      `json:"boot,omitempty"` // servers: when the machine last booted (resource reads)
}

const (
	day         = 24 * 3600
	upRecent    = 5
	upNetWindow = 90 // s: servers going down this close together = their network, not each
)

// spans returns target's outages of kind (oldest first) as [start, end] with open ones
// ending now, overlaps merged.
func spans(outs []Outage, kind, target string, now int64) [][2]int64 {
	var sp [][2]int64
	for _, o := range outs {
		if o.Kind != kind || o.Target != target {
			continue
		}
		if kind == "tunnel" && (o.Cause == "the panel host itself is offline" || o.Code == "panel" || o.Old == "probe") {
			continue // the panel was blind, not the users cut
		}
		e := o.End
		if e == 0 || e > now {
			e = now
		}
		if e < o.Start {
			e = o.Start
		}
		sp = append(sp, [2]int64{o.Start, e})
	}
	sort.Slice(sp, func(i, j int) bool { return sp[i][0] < sp[j][0] })
	var out [][2]int64
	for _, s := range sp {
		if n := len(out); n > 0 && s[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], s[1])
			continue
		}
		out = append(out, s)
	}
	return out
}

// avail is the % of [now-win, now] (from on: before it the log is not complete) the
// target was up; -1 when none of the window is known.
func avail(sp [][2]int64, win, from, now int64) float64 {
	lo := max(now-win, from)
	if now-lo <= 0 {
		return -1
	}
	var down int64
	for _, s := range sp {
		a, b := max(s[0], lo), min(s[1], now)
		if b > a {
			down += b - a
		}
	}
	return 100 * float64(now-lo-down) / float64(now-lo)
}

// uptimeOf computes a target's uptime from the outage log.
func uptimeOf(outs []Outage, kind, target string, from, now int64) *UptimeView {
	v := &UptimeView{Now: now, From: from}
	var open bool
	for _, o := range outs {
		if o.Kind == kind && o.Target == target && o.End == 0 && !(kind == "tunnel" && o.Cause == "the panel host itself is offline") {
			open = true
		}
	}
	sp := spans(outs, kind, target, now)
	if n := len(sp); n > 0 {
		last := sp[n-1]
		if open && last[1] >= now {
			v.Down, v.Since = true, last[0]
		} else {
			v.Since = last[1]
		}
	}
	v.A24, v.A7 = avail(sp, day, from, now), avail(sp, 7*day, from, now)
	for _, s := range sp {
		if s[1] > now-7*day {
			v.N7++
		}
	}
	return v
}

// serverUptime adds the machine's boot time and the last outages, each with a likely why:
// the machine rebooted (it booted inside the outage), several servers went at once (their
// network or provider), or only its SSH port stopped answering.
func serverUptime(outs []Outage, id string, from, now, boot int64) *UptimeView {
	v := uptimeOf(outs, "server", id, from, now)
	v.Boot = boot
	for i := len(outs) - 1; i >= 0 && len(v.Recent) < upRecent; i-- {
		o := outs[i]
		if o.Kind != "server" || o.Target != id {
			continue
		}
		u := UpOutage{Start: o.Start, End: o.End, Why: "ssh", Reason: o.Reason}
		end := o.End
		if end == 0 {
			end = now
		}
		for _, x := range outs {
			if x.Kind == "server" && x.Target != id && abs64(x.Start-o.Start) <= upNetWindow {
				u.Others++
			}
		}
		switch {
		case boot > 0 && boot >= o.Start-60 && boot <= end+120:
			u.Why = "reboot"
		case u.Others > 0:
			u.Why = "network"
		}
		v.Recent = append(v.Recent, u)
	}
	return v
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// bootTimes: when each server last booted, from the resource reads (resWatch, every minute).
func (a *App) bootTimes() map[string]int64 {
	out := map[string]int64{}
	if a.traffic == nil {
		return out
	}
	tm := a.traffic
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for id, r := range tm.res {
		if r != nil && r.Error == "" && r.Updated > 0 && r.Uptime > 0 {
			out[id] = r.Updated - r.Uptime
		}
	}
	return out
}

// outagesFrom is how far back the log is complete (store lock held).
func outagesFrom(st *State, now int64) int64 {
	if st.OutagesFrom > 0 {
		return st.OutagesFrom
	}
	from := now
	for _, o := range st.Outages {
		from = min(from, o.Start)
	}
	return from
}

// markOutagesFrom sets State.OutagesFrom once, on an older panel's log: its oldest entry
// (or now, on an empty log).
func (a *App) markOutagesFrom() {
	now := time.Now().Unix()
	_ = a.store.Update(func(st *State) error {
		if st.OutagesFrom == 0 {
			st.OutagesFrom = outagesFrom(st, now)
		}
		return nil
	})
}
