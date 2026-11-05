package main

import (
	"context"
	"log"
	"net/http"
	"time"
)

// Every tunnel card asked for a live Health check on each page load and every 15 s: an SSH
// round trip to both servers per tunnel (plus the switcher's state for hot standby), so a
// reload showed the cards long before their status. The status endpoint now answers from
// the last check (the monitor's, once a minute, or an earlier page's) and refreshes it in
// the background; only a tunnel with no recent check waits for a live one.
const (
	healthFresh   = 90 * time.Second // a result this old is still shown
	healthRefresh = 12 * time.Second // older than this: checked again in the background
)

type healthSnap struct {
	active, ir, kh, link string
	at                   time.Time
}

func (a *App) keepHealth(id, active, ir, kh, link string) {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	if a.healthLast == nil {
		a.healthLast = map[string]*healthSnap{}
	}
	a.healthLast[id] = &healthSnap{active: active, ir: ir, kh: kh, link: link, at: time.Now()}
}

// recentHealth is Health, answered from a recent result when there is one.
func (a *App) recentHealth(ctx context.Context, t *Tunnel) (ir, kh, link string) {
	var mid string
	a.store.View(func(*State) { mid = t.Active })
	a.healthMu.Lock()
	s := a.healthLast[t.ID]
	if s == nil || s.active != mid || time.Since(s.at) > healthFresh {
		a.healthMu.Unlock()
		return a.Health(ctx, t)
	}
	refresh := time.Since(s.at) > healthRefresh && !a.healthBusy[t.ID]
	if refresh {
		if a.healthBusy == nil {
			a.healthBusy = map[string]bool{}
		}
		a.healthBusy[t.ID] = true
	}
	a.healthMu.Unlock()
	if refresh {
		go func() {
			defer func() { a.healthMu.Lock(); delete(a.healthBusy, t.ID); a.healthMu.Unlock() }()
			c, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			a.Health(c, t)
		}()
	}
	return s.ir, s.kh, s.link
}

// slowLog notes API calls that take long in the journal, so a slow page can be traced
// to the call that held it up.
func slowLog(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h(w, r)
		if d := time.Since(start); d > 3*time.Second {
			log.Printf("slow request %s %s: %.1fs", r.Method, r.URL.Path, d.Seconds())
		}
	}
}
