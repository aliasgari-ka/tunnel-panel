package main

import (
	"testing"
	"time"
)

// TestUsageDeltas: the first read only sets the baseline, increases add up in both the hour
// and the day, and a counter that went down (restarted) counts its whole new value.
func TestUsageDeltas(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, tehran)
	u.addLocked(now, "t", "x", 1000, 100)
	if len(u.Buckets) != 0 && u.Buckets[0].Tunnels["x"] != nil {
		t.Fatal("first read counted")
	}
	u.addLocked(now, "t", "x", 1500, 300)
	u.addLocked(now.Add(2*time.Hour), "t", "x", 200, 50) // restarted
	if got := *u.Buckets[0].Tunnels["x"]; got.Down != 500 || got.Up != 200 {
		t.Fatalf("hour got %+v, want 500/200", got)
	}
	if len(u.Days) != 1 {
		t.Fatalf("%d days", len(u.Days))
	}
	if got := *u.Days[0].Tunnels["x"]; got.Down != 700 || got.Up != 250 {
		t.Fatalf("day got %+v, want 700/250", got)
	}
	u.addLocked(now, "s", "", 10, 10)
	u.addLocked(now, "s", "", 30, 15)
	if got := *u.Days[0].Servers[""]; got.Down != 20 || got.Up != 5 {
		t.Fatalf("server got %+v", got)
	}
	// a new day starts at Tehran's midnight
	u.hourLocked(now.Add(14 * time.Hour))
	if u.dayLocked(time.Date(2026, 11, 1, 23, 59, 0, 0, tehran)) != u.Days[0] || u.dayLocked(time.Date(2026, 11, 2, 0, 1, 0, 0, tehran)) == u.Days[0] {
		t.Fatal("day buckets")
	}
	for i := 0; i < usageKeep+5; i++ {
		u.hourLocked(now.Add(time.Duration(i+20) * time.Hour))
	}
	if len(u.Buckets) != usageKeep {
		t.Fatalf("kept %d hours", len(u.Buckets))
	}
}

// TestUsageFoldHours: a log saved before daily buckets gets its hours folded into days.
func TestUsageFoldHours(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	u := &usageLog{Last: map[string]*usageLast{}}
	h := time.Date(2026, 11, 1, 1, 0, 0, 0, tehran)
	u.Buckets = []*usageBucket{
		{Hour: h.Unix(), Tunnels: map[string]*UsageBytes{"x": {Down: 5, Up: 1}}, Servers: map[string]*UsageBytes{}},
		{Hour: h.Add(time.Hour).Unix(), Tunnels: map[string]*UsageBytes{"x": {Down: 7, Up: 2}}, Servers: map[string]*UsageBytes{}},
	}
	u.saveLocked()
	got := loadUsage()
	if len(got.Days) != 1 || got.Days[0].Tunnels["x"].Down != 12 || got.Days[0].Tunnels["x"].Up != 3 {
		t.Fatalf("days %+v", got.Days)
	}
}
