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
