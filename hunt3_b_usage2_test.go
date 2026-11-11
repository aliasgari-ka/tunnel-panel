package main

import (
	"testing"
	"time"
)

// recordLocked counts what a foreign server sent only over an interval its route's running
// tunnels were counted in too (the comment: "without this the bytes of a whole outage landed
// in one hour against none of the users'"). A tunnel that was stopped (Stop tears its
// counting chains down) and started again days later comes back with new marks of the same
// shape: usageMarksFit says "the parts were made again, count from zero" and the route stays
// pOK — so the peer counter is compared with its read from before the stop, and every byte
// the foreign server sent the Iran server while no tunnel ran there is booked and priced
// against the tunnel in the hours just before the restart.
func TestHunt3UsagePeerCountedAcrossStop(t *testing.T) {
	dataDir = t.TempDir()
	u := &usageLog{Last: map[string]*usageLast{}, Known: map[string]*usageTun{}}
	pair := map[string]string{"t1": "ir|fo"}
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, tehran)
	tr := func(mark string, d uint64) usageRead {
		return usageRead{"t", "t1", "e:" + mark, d, 0, [][2]uint64{{d, 0}}}
	}
	pr := func(d uint64) usageRead { return usageRead{"p", "ir|fo|192.0.2.9", "", d, 0, nil} }

	u.recordLocked(t0, []usageRead{tr("100", 0), pr(1000)}, pair)                       // baselines
	u.recordLocked(t0.Add(5*time.Minute), []usageRead{tr("100", 1000), pr(2000)}, pair) // counted
	// the tunnel is stopped: nothing on the route is read for two days. The foreign server
	// keeps sending the Iran server things (other panels' tunnels, backups, ...): 50 GB
	restart := t0.Add(48 * time.Hour)
	u.recordLocked(restart, []usageRead{tr("200", 0), pr(50e9)}, pair) // started again: new chains

	var peer uint64
	for _, b := range u.Buckets {
		if x := b.Peers["ir|fo"]; x != nil {
			peer += x.Down
		}
	}
	if peer > 1e6 {
		t.Errorf("%d bytes of the foreign server's traffic from the two days the tunnel was stopped were booked to the route (expected only the 1000 counted while it ran)", peer)
	}
}
