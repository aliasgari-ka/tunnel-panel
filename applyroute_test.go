package main

import (
	"testing"
	"time"
)

// Choosing a hot-standby tunnel's own method while the switcher has its users on another
// path (auto mode moved them, nothing pinned) is an in-place switch, not a re-apply: the
// re-apply rebuilt the tunnel and cut everyone (seen live on تانل فنلاند). With the users
// already on it, the same press still means a re-apply.
func TestApplyOwnMethodSwitchesInPlace(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1", IPv6: "2001:db8::1"},
			{ID: "kh1", Name: "fi", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "fin", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443",
			Index: 1, Active: "bp_reverse", Selected: "bp_reverse", HotStandby: true, HSAuto: true,
			Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 1}, {Method: "direct6", Family: "v6", Index: 2}}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}}
	tun := st.Tunnel("aaaaaaaaaaaa")

	// auto mode has the users on Direct v6
	a.hsViews[tun.ID] = &hsView{Active: 1, Keys: []string{"bp_reverse|v4", "direct6|v6"}, OK: []bool{true, true}}
	j, err := a.ApplyRoute(tun, "bp_reverse", "v4")
	if err != nil {
		t.Fatal(err)
	}
	if k := j.snapshot().Kind; k != "switch" {
		t.Fatalf("own method while the users are elsewhere: a %q job, want an in-place switch", k)
	}
	for j.snapshot().Status == "running" {
		time.Sleep(10 * time.Millisecond)
	}

	// the users are on it already: that press is a re-apply
	a.hsViews[tun.ID] = &hsView{Active: 0, Keys: []string{"bp_reverse|v4", "direct6|v6"}, OK: []bool{true, true}}
	_ = st.Update(func(*State) error { tun.HSPin = ""; return nil })
	j2, err := a.ApplyRoute(tun, "bp_reverse", "v4")
	if err != nil {
		t.Fatal(err)
	}
	if k := j2.snapshot().Kind; k == "switch" {
		t.Fatalf("own method with the users already on it switched instead of re-applying")
	}
	_, _ = a.jobs.cancel(j2.ID) // it would try to reach the (test-net) servers
}
