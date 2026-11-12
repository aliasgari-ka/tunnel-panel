package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A cleanup kept for a server that was deleted before the delete handler took cleanups
// along never runs (the monitor no longer watches that server) and held its tunnel numbers
// for good: loading the state drops it, and keeps those of servers that still exist.
func TestLoadStoreDropsOrphanCleanups(t *testing.T) {
	dir := t.TempDir()
	in := State{
		Servers: []*Server{{ID: "ir", Name: "iran", IPv4: "192.0.2.1"}},
		Cleanups: []Cleanup{
			{ServerID: "gone", TunnelID: "t1", Name: "old", Indices: []int{1, 2}},
			{ServerID: "ir", TunnelID: "t2", Name: "kept", Indices: []int{3}},
		},
	}
	data, _ := json.Marshal(in)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []Cleanup
	var next int
	st.View(func(s *State) { got = s.Cleanups; next = st.nextIndexLocked(s) })
	if len(got) != 1 || got[0].ServerID != "ir" {
		t.Fatalf("cleanups after load = %+v, want only the one for server ir", got)
	}
	if next != 1 {
		t.Fatalf("next index = %d, want 1 (freed by the dropped orphan)", next)
	}
	// and it is saved that way
	st2, _ := LoadStore(dir)
	st2.View(func(s *State) { got = s.Cleanups })
	if len(got) != 1 {
		t.Fatalf("reloaded cleanups = %+v", got)
	}
}
