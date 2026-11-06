package main

import (
	"strings"
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

// TestUsagePaid: an Iran server with tunnels to two foreign servers pays each its own peer
// intake plus its users' upload; two tunnels on one pair split it by download; a bucket
// from before the peer counters splits the Iran card's intake (estimated).
func TestUsagePaid(t *testing.T) {
	pairs := map[string][2]string{"a": {"ir", "us"}, "b": {"ir", "fr"}, "c": {"ir", "fr"}}
	b := &usageBucket{
		Tunnels: map[string]*UsageBytes{"a": {Down: 1000, Up: 100}, "b": {Down: 300, Up: 10}, "c": {Down: 100, Up: 20}},
		Servers: map[string]*UsageBytes{"ir": {Down: 2000}},
		Peers:   map[string]*UsageBytes{"ir|us": {Down: 1100}, "ir|fr": {Down: 400}},
	}
	paid, est := usagePaid(b, pairs)
	if paid["a"] != 1200 || paid["b"] != 310 || paid["c"] != 120 || len(est) != 0 {
		t.Fatalf("paid %v est %v", paid, est)
	}
	b.Peers = nil
	paid, est = usagePaid(b, pairs)
	if !est["a"] || paid["a"]+paid["b"]+paid["c"] < 1990 || paid["a"] < paid["b"] {
		t.Fatalf("fallback paid %v est %v", paid, est)
	}
	// peer reads are kept per address and summed per pair
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, tehran)
	for _, ip := range []string{"1.1.1.1", "2a01::1"} {
		u.addLocked(now, "p", "ir|us|"+ip, 100, 10)
		u.addLocked(now, "p", "ir|us|"+ip, 150, 20)
	}
	if got := u.Buckets[0].Peers["ir|us"]; got == nil || got.Down != 100 || got.Up != 20 {
		t.Fatalf("peer bucket %+v", got)
	}
}

// TestPeerScript: one rule per foreign address, in the right iptables.
func TestPeerScript(t *testing.T) {
	s := peerScript(map[string]string{"1.2.3.4": "us", "2a01::1": "us"})
	for _, want := range []string{"tpp iptables 1.2.3.4", "tpp ip6tables 2a01::1", "tpp_chain iptables", "tpp_chain ip6tables"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if peerScript(nil) != "" {
		t.Fatal("empty")
	}
}

func TestUsageNicSetChange(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Now()
	u.addSrcLocked(now, "s", "ir", "nic eth0", 1000, 100)
	u.addSrcLocked(now, "s", "ir", "nic eth0", 1500, 200)
	u.addSrcLocked(now, "s", "ir", "nic eth0+eth1", 90000, 9000) // a second card: baseline only
	u.addSrcLocked(now, "s", "ir", "nic eth0+eth1", 90700, 9100)
	if x := u.Days[0].Servers["ir"]; x == nil || x.Down != 1200 || x.Up != 200 {
		t.Fatalf("got %+v, want 1200/200", x)
	}
}
