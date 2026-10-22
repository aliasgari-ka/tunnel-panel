package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// The health monitor checks every running tunnel once a minute and sends a Telegram
// alert when one goes down (after two failed checks in a row, so a blip doesn't page
// you) and again when it comes back. It only runs while a bot is configured.
const (
	monitorEvery = time.Minute
	monitorFails = 2
)

type tunnelHealth struct {
	fails      int
	alerted    bool
	downSince  time.Time
	reason     string
	lastOutage time.Duration
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
	h.fails, h.alerted, h.reason = 0, false, ""
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
		if a.settings().TelegramTok == "" {
			continue
		}
		var ts []*Tunnel
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.Active != "" {
					ts = append(ts, t)
				}
			}
		})
		live := map[string]bool{}
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		for _, t := range ts {
			live[t.ID] = true
			if a.jobs.running(t.ID) != "" {
				continue // being applied/stopped/tested right now
			}
			wg.Add(1)
			go func(t *Tunnel) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				ir, kh, link := a.Health(ctx, t)
				reason := ""
				switch {
				case ir == "unreachable":
					reason = "Iran server unreachable"
				case ir != "active":
					reason = "Iran service " + ir
				case kh == "unreachable":
					reason = "foreign server unreachable"
				case kh != "active":
					reason = "foreign service " + kh
				case link == "down":
					reason = "tunnel link down (no traffic between the servers)"
				}
				mu.Lock()
				defer mu.Unlock()
				h := state[t.ID]
				if h == nil {
					h = &tunnelHealth{}
					state[t.ID] = h
				}
				switch h.step(reason, time.Now()) {
				case "down":
					a.push(fmt.Sprintf("🔴 Tunnel DOWN: %s\n%s\n(%s → %s)", t.Name, reason, serverName(a, t.ServerID), foreignName(a, t)))
				case "up":
					a.push(fmt.Sprintf("🟢 Tunnel back up: %s (was down %s)", t.Name, h.lastOutage.Round(time.Minute)))
				}
			}(t)
		}
		wg.Wait()
		mu.Lock()
		for id := range state {
			if !live[id] {
				delete(state, id) // stopped or deleted: no alerts
			}
		}
		mu.Unlock()
	}
}

func foreignName(a *App, t *Tunnel) string {
	if t.ForeignID == "" {
		return "this panel host"
	}
	return serverName(a, t.ForeignID)
}
