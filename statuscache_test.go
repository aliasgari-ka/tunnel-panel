package main

import (
	"context"
	"testing"
	"time"
)

// The status of a tunnel card comes from a recent check without a new SSH round trip; a
// changed method or an old result is checked live.
func TestRecentHealth(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	tn := &Tunnel{ID: "t1", Name: "x", ServerID: "nope", Family: "v4", Ports: "443", Index: 1, Active: "gre"}
	_ = st.Update(func(s *State) error { s.Tunnels = []*Tunnel{tn}; return nil })
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	ctx := context.Background()

	a.keepHealth("t1", "gre", "active", "active", "up")
	if ir, kh, link := a.recentHealth(ctx, tn); ir != "active" || kh != "active" || link != "up" {
		t.Errorf("recent result not used: %s %s %s", ir, kh, link)
	}
	// another method now: the old verdict doesn't apply (the server is unknown → live check)
	a.keepHealth("t1", "wg", "active", "active", "up")
	if ir, _, _ := a.recentHealth(ctx, tn); ir == "active" {
		t.Errorf("result of another method used")
	}
	// too old: checked live
	a.keepHealth("t1", "gre", "active", "active", "up")
	a.healthLast["t1"].at = time.Now().Add(-2 * healthFresh)
	if ir, _, _ := a.recentHealth(ctx, tn); ir == "active" {
		t.Errorf("stale result used")
	}
	// a check cut off by its timeout is kept as unreachable (the next load answers at once);
	// one cut off because the page went away is not
	a.clearHealth("t1")
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	a.Health(cctx, tn)
	if a.healthLast["t1"] != nil {
		t.Errorf("a canceled check was kept")
	}
	dctx, dcancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer dcancel()
	a.Health(dctx, tn)
	if a.healthLast["t1"] == nil {
		t.Errorf("a timed-out check was not kept")
	}
	// Stop/apply forgets it
	a.keepHealth("t1", "gre", "active", "active", "up")
	a.clearHealth("t1")
	if a.healthLast["t1"] != nil {
		t.Errorf("clearHealth kept the result")
	}
}
