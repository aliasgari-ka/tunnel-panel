package main

import (
	"sync"
	"time"
)

// A path's index is chosen from what the state holds — but a job writes its paths to the
// state only once they are deployed, minutes later. Two jobs choosing at the same time
// took the same index (seen live: England's and the outbound tunnel's retries both got 13;
// two paths on one index share internal ports and tags). So a chosen index is held here
// for longer than any job runs.
var (
	hsIdxMu   sync.Mutex
	hsIdxHeld = map[int]time.Time{} // index -> when the hold ends
)

const hsIdxHold = 30 * time.Minute

// hsFreeIndex picks the lowest index that neither used nor a running job holds, marks it
// used and holds it (0: none left).
func hsFreeIndex(used map[int]bool) int {
	hsIdxMu.Lock()
	defer hsIdxMu.Unlock()
	now := time.Now()
	for n := 1; n < 250; n++ {
		if used[n] {
			continue
		}
		if until, ok := hsIdxHeld[n]; ok && now.Before(until) {
			continue
		}
		used[n] = true
		hsIdxHeld[n] = now.Add(hsIdxHold)
		return n
	}
	return 0
}
