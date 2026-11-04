package main

import (
	"testing"
	"time"
)

// A tunnel whose route has only some methods switched on (the tunnel window's checklist)
// plans hot-standby paths for those and its own method, nothing else.
func TestHSPlanOnlyChosen(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "i", IPv4: "192.0.2.1", IPv6: "2001:db8::1"}, {ID: "k", IPv4: "192.0.2.2", IPv6: "2001:db8::2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "x", ServerID: "i", ForeignID: "k", Family: "v4", Ports: "443", Index: 3, HotStandby: true}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	on := map[string]bool{"gre|v4": true, "gre|v6": true, "bp_l3|v4": true, "golden|v4": true}
	var off []string
	for _, m := range methods {
		for _, f := range []string{"v4", "v6"} {
			if supportsFamily(m, f) && !on[m.ID+"|"+f] {
				off = append(off, m.ID+"|"+f)
			}
		}
	}
	a.setRouteSkipAll("i", "k", off)
	paths := a.hsPlan(st.Tunnel("x"), "frp", "v4")
	if len(paths) == 0 || paths[0].Method != "frp" {
		t.Fatalf("the tunnel's own method must come first: %v", paths)
	}
	for _, p := range paths[1:] {
		if !on[p.Method+"|"+p.Family] {
			t.Fatalf("path %s|%s was switched off but is planned: %v", p.Method, p.Family, paths)
		}
	}
	if len(paths) > 1+len(on) {
		t.Fatalf("%d paths planned, want at most %d", len(paths), 1+len(on))
	}
	a.setRouteSkipAll("i", "k", nil)
	if a.routeSkipped("i", "k", "frp", "v4") {
		t.Fatal("an empty list must switch every method back on")
	}
}

// A switch flipped while a job runs on the tunnel waits for that job instead of being
// dropped until the next Repair pass.
func TestHSSyncWaitsForJob(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Tunnels = []*Tunnel{{ID: "x", ServerID: "i", ForeignID: "k", Family: "v4", HotStandby: true}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	defer func(p time.Duration) { hsSyncPoll = p }(hsSyncPoll)
	hsSyncPoll = 10 * time.Millisecond
	j, err := a.jobs.start("x", "apply:gre")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { a.hsSyncPaths(st.Tunnel("x")); close(done) }()
	select {
	case <-done:
		t.Fatal("returned while the Start was still running")
	case <-time.After(100 * time.Millisecond):
	}
	a.jobs.done(j) // the Start ended without bringing the tunnel up: nothing left to do
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("still waiting after the job ended")
	}
}
