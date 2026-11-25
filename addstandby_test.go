package main

import (
	"strings"
	"testing"
	"time"
)

// AddStandby starts one path beside the running ones and is refused where it would do
// something else: on a path that already runs, on a tunnel without hot-standby paths, and
// for a method the route leaves out.
func TestAddStandby(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1", IPv6: "2001:db8::1"},
			{ID: "kh1", Name: "fi", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "fin", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443",
				Index: 1, Active: "bp_reverse", Selected: "bp_reverse", HotStandby: true,
				Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 1}}},
			{ID: "bbbbbbbbbbbb", Name: "plain", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "444", Index: 2},
		}
		s.RouteSkip = map[string][]string{routeKey("ir1", "kh1"): {"backhaul|v4"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}}
	tun := st.Tunnel("aaaaaaaaaaaa")

	if _, err := a.AddStandby(tun, "nope", "v4"); err == nil {
		t.Fatal("an unknown method was accepted")
	}
	if _, err := a.AddStandby(tun, "bp_reverse", "v4"); err == nil || !strings.Contains(err.Error(), "already runs") {
		t.Fatalf("a running path: %v, want it refused as already running", err)
	}
	if _, err := a.AddStandby(tun, "backhaul", "v4"); err == nil || !strings.Contains(err.Error(), "cannot run") {
		t.Fatalf("a method the route leaves out: %v, want it refused", err)
	}
	if _, err := a.AddStandby(st.Tunnel("bbbbbbbbbbbb"), "gre", "v4"); err == nil || !strings.Contains(err.Error(), "no hot-standby paths") {
		t.Fatalf("a tunnel without paths: %v, want it refused", err)
	}

	// an opt-in method picked by hand is started as a path, and the family defaults to the tunnel's
	j, err := a.AddStandby(tun, "bp2_rpck", "")
	if err != nil {
		t.Fatal(err)
	}
	s := j.snapshot()
	for i := 0; i < 200 && len(s.Lines) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
		s = j.snapshot()
	}
	if s.Kind != "switch" || len(s.Lines) == 0 || !strings.Contains(s.Lines[0], "starting only it") || !strings.Contains(s.Lines[0], "(v4)") {
		t.Fatalf("a %q job %q, want only that path started", s.Kind, s.Lines)
	}
	_, _ = a.jobs.cancel(j.ID) // it would try to reach the (test-net) servers
	for j.snapshot().Status == "running" {
		time.Sleep(10 * time.Millisecond)
	}
	// nothing moved: the tunnel's method and pin are what they were
	if tun.Active != "bp_reverse" || tun.HSPin != "" {
		t.Fatalf("the users were moved: active %q pin %q", tun.Active, tun.HSPin)
	}
}

// A method that needs time after its start says so, and only the v2 reverse PCK does.
func TestWarmupOnlyOnBackpack2PCK(t *testing.T) {
	for _, m := range methods {
		if (m.Warmup > 0) != (m.ID == "bp2_rpck") {
			t.Errorf("%s: warm-up %d s", m.ID, m.Warmup)
		}
	}
}
