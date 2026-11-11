package main

import (
	"testing"
	"time"
)

// TestHSLinkTrafficProof: a hot-standby tunnel whose users' path fails the switcher's probe
// while it carries their traffic (Xe107 on Paqet-plus, 56 Mbit/s) is not "down"; the same
// failing probe with no data reaching the users still is.
func TestHSLinkTrafficProof(t *testing.T) {
	a := &App{traffic: newTrafficMon()}
	now := time.Now().Unix()
	set := func(down, up float64, at int64) {
		a.traffic.tunnels["x"] = &TrafficStat{ID: "x", Down: down, Up: up, Updated: at}
	}
	// TP ✓, Backhaul Premium ✕, BackPack ✓, Paqet-plus ✕ ← users
	v := &hsView{Active: 3, OK: []bool{true, false, true, false}}

	set(56.4e6, 20.9e6, now)
	if got := a.hsLink("x", v); got != "up" {
		t.Errorf("users' path carries 56 Mbit/s but the link is %q", got)
	}
	// a path that only answers handshakes locally (little data back) is still down
	set(40_000, 300_000, now)
	if got := a.hsLink("x", v); got != "down" {
		t.Errorf("handshake noise counted as a working link: %q", got)
	}
	// stale counters prove nothing
	set(56.4e6, 20.9e6, now-120)
	if got := a.hsLink("x", v); got != "down" {
		t.Errorf("stale traffic counted: %q", got)
	}
	// no counters at all (no page open): the switcher's verdict alone
	delete(a.traffic.tunnels, "x")
	if got := a.hsLink("x", v); got != "down" {
		t.Errorf("no traffic data, failing users' path: %q", got)
	}
	// the users' path passes its probe: up, whatever the standby paths do
	v.Active = 0
	if got := a.hsLink("x", v); got != "up" {
		t.Errorf("users on a working path: %q", got)
	}
	// switcher with no path chosen
	if got := a.hsLink("x", &hsView{Active: -1}); got != "down" {
		t.Errorf("no active path: %q", got)
	}
	if got := (&App{}).hsLink("x", &hsView{Active: 0, OK: []bool{true}}); got != "up" {
		t.Errorf("no traffic monitor: %q", got)
	}
}
