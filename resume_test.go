package main

import (
	"encoding/json"
	"testing"
)

// The method being applied is kept in the state (it survives a restart) until the apply
// brings it up; a stop clears it too.
func TestApplyingMarker(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	tun := &Tunnel{ID: "t1", Name: "t", Family: "v4"}
	_ = st.Update(func(s *State) error { s.Tunnels = []*Tunnel{tun}; return nil })
	a := &App{store: st, jobs: newJobs()}

	a.setApplying(tun, "gre")
	a.setActive(tun, "") // the old method torn down: the tunnel is down mid-apply
	reloaded, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	var got Tunnel
	reloaded.View(func(s *State) { b, _ := json.Marshal(s.Tunnels[0]); _ = json.Unmarshal(b, &got) })
	if got.Applying != "gre" || got.Active != "" {
		t.Fatalf("after a restart mid-apply: applying %q active %q", got.Applying, got.Active)
	}
	a.setActive(tun, "gre")
	if tun.Applying != "" {
		t.Error("the marker stays after the method came up")
	}
	a.setApplying(tun, "gre")
	a.setApplying(tun, "") // what Stop and a failed apply do
	if tun.Applying != "" {
		t.Error("the marker stays after a stop / failure")
	}
}
