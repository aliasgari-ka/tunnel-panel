package main

import (
	"testing"
	"time"
)

// A hot-standby path refused at apply is tried again once an hour while the tunnel is
// healthy — only that path, and only when the route still allows it. Before this, England's
// BackPack reverse stayed "failed" for good after one bad minute on the way.
func TestHSRetryDue(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	now := time.Now()
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1"},
			{ID: "kh1", Name: "uk", IPv4: "198.51.100.1", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1,
				Active: "gre", HotStandby: true, Paths: []HSPath{
					{Method: "gre", Family: "v4", Index: 1},
					{Method: "bp_reverse", Family: "v4", Index: 2, Failed: "the foreign server cannot open any TCP connection to Iran", FailedAt: now.Add(-2 * time.Hour).Unix()},
					{Method: "paqet", Family: "v4", Index: 3, Failed: "just now", FailedAt: now.Add(-10 * time.Minute).Unix()},
					{Method: "direct6", Family: "v6", Index: 4, Failed: "from before the stamp"},
				}},
			{ID: "bbbbbbbbbbbb", Name: "plain", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "444", Index: 5,
				Active: "gre", Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 6, Failed: "x", FailedAt: 1}}},
		}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}}

	due := a.hsRetryDue(st.Tunnel("aaaaaaaaaaaa"), now)
	got := map[string]bool{}
	for _, p := range due {
		got[p.String()] = true
	}
	if !got["bp_reverse|v4"] || !got["direct6|v6"] || got["paqet|v4"] || got["gre|v4"] || len(due) != 2 {
		t.Fatalf("due = %v, want the two old failures only", due)
	}
	if d := a.hsRetryDue(st.Tunnel("bbbbbbbbbbbb"), now); len(d) != 0 {
		t.Fatalf("a tunnel without hot standby has nothing to retry, got %v", d)
	}

	// a method left out on the route is not tried
	_ = st.Update(func(s *State) error {
		if s.RouteSkip == nil {
			s.RouteSkip = map[string][]string{}
		}
		s.RouteSkip[routeKey("ir1", "kh1")] = []string{"direct6|v6"}
		return nil
	})
	due = a.hsRetryDue(st.Tunnel("aaaaaaaaaaaa"), now)
	if len(due) != 1 || due[0].Method != "bp_reverse" {
		t.Fatalf("with Direct v6 left out on the route: due = %v, want BackPack reverse only", due)
	}

	// the retry is a "paths" job that touches nothing else when the servers don't answer:
	// the users' path and the running paths stay
	tun := st.Tunnel("aaaaaaaaaaaa")
	j, err := a.hsRetryFailed(tun)
	if err != nil || j == nil {
		t.Fatalf("retry job: %v %v", j, err)
	}
	if k := j.snapshot().Kind; k != "paths" {
		t.Fatalf("job kind %q, want paths", k)
	}
	for j.snapshot().Status == "running" {
		time.Sleep(10 * time.Millisecond)
	}
	st.View(func(*State) {
		if tun.Active != "gre" || len(tun.Paths) != 4 || tun.Paths[0].Method != "gre" {
			t.Fatalf("a failed retry changed the tunnel: active %s, paths %v", tun.Active, tun.Paths)
		}
	})
}
