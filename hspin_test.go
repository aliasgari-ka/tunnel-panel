package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// pinHost plays the Iran server: the pin write answers OK, and the switcher's state shows
// the users on path 0 until moveAfter reads (never, if 0).
type pinHost struct {
	mu        sync.Mutex
	reads     int
	moveAfter int
}

func (h *pinHost) Label() string                               { return "tir" }
func (h *pinHost) WriteFile(string, []byte, os.FileMode) error { return nil }
func (h *pinHost) Run(_ context.Context, script string, _ func(string)) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if strings.Contains(script, "> pin") {
		return "OK\n", nil
	}
	h.reads++
	a := "0"
	if h.moveAfter > 0 && h.reads >= h.moveAfter {
		a = "1"
	}
	return "A " + a + " 1793215901\nM auto\nU active\n", nil
}

// "use" answers once the switcher has moved the users, and the panel's view shows it at once
// (the page reloads right after the press; a minute-old view showed them still on the old path).
func TestHSPinWaitsForMove(t *testing.T) {
	defer func(w time.Duration) { hsPinWait = w }(hsPinWait)
	hsPinWait = 4 * time.Second
	for _, c := range []struct {
		moveAfter int
		want      string
	}{{2, "users are on Paqet"}, {0, "hasn't moved the users"}} {
		dataDir = t.TempDir()
		st, _ := LoadStore(dataDir)
		tn := &Tunnel{ID: "aaa", Name: "t", ServerID: "ir", Active: "bp_reverse", Family: "v4", HotStandby: true,
			Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 1}, {Method: "paqet", Family: "v4", Index: 2}}}
		_ = st.Update(func(s *State) error {
			s.Servers = []*Server{{ID: "ir", Name: "ir"}}
			s.Tunnels = []*Tunnel{tn}
			return nil
		})
		h := &pinHost{moveAfter: c.moveAfter}
		a := &App{store: st, jobs: newJobs(), hostFor: func(*Server) Host { return h }}
		msg, err := a.hsPinTo(context.Background(), st.Tunnel("aaa"), "paqet|v4")
		if err != nil || !strings.Contains(msg, c.want) {
			t.Errorf("moveAfter %d: %q %v, want %q", c.moveAfter, msg, err, c.want)
		}
		if v := a.hsViewOf("aaa"); c.moveAfter > 0 && (v == nil || v.Active != 1) {
			t.Errorf("view not updated: %+v", v)
		}
	}
}
