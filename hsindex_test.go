package main

import (
	"testing"
	"time"
)

// Two jobs that choose a path index at the same moment must not get the same one: the
// state learns of a new path only when its job has deployed it (seen live: England's and
// the outbound tunnel's retries both took 13).
func TestHSFreeIndexHeldAcrossJobs(t *testing.T) {
	hsIdxMu.Lock()
	hsIdxHeld = map[int]time.Time{}
	hsIdxMu.Unlock()
	used := func() map[int]bool { return map[int]bool{1: true, 2: true} }
	a := hsFreeIndex(used()) // one job's view of the state
	b := hsFreeIndex(used()) // another job's, before the first wrote its path
	if a != 3 || b != 4 {
		t.Fatalf("got %d and %d, want 3 then 4", a, b)
	}
	// within one job the map it marks keeps the choice too
	u := used()
	if x, y := hsFreeIndex(u), hsFreeIndex(u); x == y || !u[x] || !u[y] {
		t.Fatalf("one job: %d %d (used %v)", x, y, u)
	}
}

// A new tunnel must not take an index a running paths job chose for a new path but has not
// saved yet (same tpN interface, subnet and ports).
func TestNextIndexSkipsHeld(t *testing.T) {
	hsIdxMu.Lock()
	hsIdxHeld = map[int]time.Time{}
	hsIdxMu.Unlock()
	defer func() {
		hsIdxMu.Lock()
		hsIdxHeld = map[int]time.Time{}
		hsIdxMu.Unlock()
	}()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Tunnels = []*Tunnel{{ID: "a", Index: 1, Paths: []HSPath{{Method: "gre", Family: "v4", Index: 1}}}}
		return nil
	})
	var held, idx int
	_ = st.Update(func(s *State) error { // as hsUpdatePathsRun picks it
		held = hsFreeIndex(map[int]bool{1: true})
		return nil
	})
	_ = st.Update(func(s *State) error { idx = st.nextIndexLocked(s); return nil })
	if held != 2 || idx == held {
		t.Fatalf("held %d, new tunnel got %d", held, idx)
	}
}
