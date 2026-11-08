package main

import "testing"

// A second failover whose working path is the tunnel's original one ends the failover: it
// stayed marked "on a backup", and an hour later Failback rebuilt the running path.
func TestFailoverLandsOnOriginal(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	orig := &FailoverState{Method: "gre", Family: "v4", Reason: "tunnel link down", Since: 1}
	tn := &Tunnel{ID: "aaa", Name: "t", Active: "gre", Family: "v4", Failover: orig}
	_ = st.Update(func(s *State) error { s.Tunnels = []*Tunnel{tn}; return nil })
	a := &App{store: st, jobs: newJobs()}

	if !a.failoverLanded(tn, orig, pathChoice{"gre", "v4"}) || tn.Failover != nil {
		t.Fatalf("back on the original path: still marked failed over (%+v)", tn.Failover)
	}
	// on a backup the original is kept for Failback
	tn.Failover = nil
	if a.failoverLanded(tn, orig, pathChoice{"gre", "v6"}) || tn.Failover != orig || orig.Since <= 1 {
		t.Fatalf("on a backup: failover %+v", tn.Failover)
	}
}
