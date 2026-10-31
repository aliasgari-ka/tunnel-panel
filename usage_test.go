package main

import (
	"testing"
	"time"
)

// TestUsageDeltas: the first read only sets the baseline, increases add up, and a counter
// that went down (restarted) counts its whole new value.
func TestUsageDeltas(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Now()
	b := u.bucketLocked(now)
	u.addLocked(b, "t", "x", 1000, 100)
	if b.Tunnels["x"] != nil {
		t.Fatal("first read counted")
	}
	u.addLocked(b, "t", "x", 1500, 300)
	u.addLocked(b, "t", "x", 200, 50) // restarted
	if got := *b.Tunnels["x"]; got.Down != 700 || got.Up != 250 {
		t.Fatalf("got %+v, want 700/250", got)
	}
	u.addLocked(b, "s", "", 10, 10)
	u.addLocked(b, "s", "", 30, 15)
	if got := *b.Servers[""]; got.Down != 20 || got.Up != 5 {
		t.Fatalf("server got %+v", got)
	}
	if u.bucketLocked(now) != b || u.bucketLocked(now.Add(time.Hour)) == b {
		t.Fatal("hour buckets")
	}
	for i := 0; i < usageKeep+5; i++ {
		u.bucketLocked(now.Add(time.Duration(i+2) * time.Hour))
	}
	if len(u.Buckets) != usageKeep {
		t.Fatalf("kept %d buckets", len(u.Buckets))
	}
}
