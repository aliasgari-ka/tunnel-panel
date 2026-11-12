package main

import (
	"math"
	"testing"
)

const tnow = int64(10_000_000)

func near(a, b float64) bool { return math.Abs(a-b) < 0.01 }

// No outage since the log began: up, "since" unknown (at least since From), 100 %.
func TestUptimeNoOutage(t *testing.T) {
	v := uptimeOf(nil, "tunnel", "t1", tnow-3*day, tnow)
	if v.Down || v.Since != 0 || v.A24 != 100 || v.A7 != 100 || v.N7 != 0 {
		t.Fatalf("%+v", v)
	}
}

// An outage resets "up since" to its end, and counts against the ranges it falls in.
func TestUptimeOutageResets(t *testing.T) {
	outs := []Outage{
		{Kind: "tunnel", Target: "t1", Start: tnow - 2*day, End: tnow - 2*day + 864}, // 1 % of a day, 2 d ago
		{Kind: "tunnel", Target: "t1", Start: tnow - 3600, End: tnow - 3600 + 864},   // 1 % of the last 24 h
		{Kind: "tunnel", Target: "other", Start: tnow - 600, End: tnow - 300},
		{Kind: "server", Target: "t1", Start: tnow - 100, End: tnow - 50},
	}
	v := uptimeOf(outs, "tunnel", "t1", tnow-30*day, tnow)
	if v.Down || v.Since != tnow-3600+864 {
		t.Fatalf("since %d, want %d (%+v)", v.Since, tnow-3600+864, v)
	}
	if !near(v.A24, 99) || !near(v.A7, 100-100*1728.0/(7*day)) || v.N7 != 2 {
		t.Fatalf("%+v", v)
	}
}

// A hot-standby tunnel whose users were moved between paths has no outage in the log (the
// health check asks the switcher about the users' path, and two failed checks a minute apart
// make an outage): its uptime runs on. Other tunnels' and server outages don't touch it, nor
// does a tunnel outage that only the panel's own lost internet made.
func TestUptimeIgnoresOthersAndPanelBlind(t *testing.T) {
	outs := []Outage{
		{Kind: "tunnel", Target: "t1", Start: tnow - 5*day, End: tnow - 5*day + 60},
		{Kind: "tunnel", Target: "t1", Start: tnow - 1000, End: tnow - 900, Cause: "the panel host itself is offline"},
		{Kind: "ssh-v4", Target: "t1/v4", Start: tnow - 500, End: tnow - 400},
	}
	v := uptimeOf(outs, "tunnel", "t1", tnow-30*day, tnow)
	if v.Down || v.Since != tnow-5*day+60 || v.A24 != 100 || v.N7 != 1 {
		t.Fatalf("%+v", v)
	}
}

// Down now: down since the open outage's start; it counts to now.
func TestUptimeDownNow(t *testing.T) {
	outs := []Outage{{Kind: "server", Target: "s", Start: tnow - 864}}
	v := uptimeOf(outs, "server", "s", tnow-30*day, tnow)
	if !v.Down || v.Since != tnow-864 || !near(v.A24, 99) {
		t.Fatalf("%+v", v)
	}
}

// The ranges only count the part of the window the log covers (cleared 12 h ago: 24 h is
// the last 12 h), and overlapping entries are not counted twice.
func TestUptimeRangesClampToFrom(t *testing.T) {
	outs := []Outage{
		{Kind: "tunnel", Target: "t", Start: tnow - 4320, End: tnow - 4320 + 432},
		{Kind: "tunnel", Target: "t", Start: tnow - 4320 + 100, End: tnow - 4320 + 432}, // overlaps
	}
	v := uptimeOf(outs, "tunnel", "t", tnow-day/2, tnow)
	if !near(v.A24, 99) || !near(v.A7, 99) || v.N7 != 1 {
		t.Fatalf("%+v", v)
	}
	if v := uptimeOf(nil, "tunnel", "t", tnow, tnow); v.A24 != -1 {
		t.Fatalf("no history: %+v", v)
	}
}

// Why a server went down: it booted inside the outage → reboot; others went at the same
// time → network; else its SSH port.
func TestServerUptimeWhy(t *testing.T) {
	outs := []Outage{
		{Kind: "server", Target: "a", Start: tnow - 9000, End: tnow - 8000},
		{Kind: "server", Target: "b", Start: tnow - 9030, End: tnow - 8500},
		{Kind: "server", Target: "a", Start: tnow - 5000, End: tnow - 4900},
		{Kind: "server", Target: "a", Start: tnow - 600, End: tnow - 400},
	}
	v := serverUptime(outs, "a", tnow-30*day, tnow, tnow-450)
	if len(v.Recent) != 3 || v.Recent[0].Why != "reboot" || v.Recent[1].Why != "ssh" || v.Recent[2].Why != "network" || v.Recent[2].Others != 1 {
		t.Fatalf("%+v", v.Recent)
	}
	if v.Boot != tnow-450 || v.Since != tnow-400 {
		t.Fatalf("%+v", v)
	}
}

// Trimming the log moves OutagesFrom to the newest dropped outage's end.
func TestTrimOutagesCut(t *testing.T) {
	var all []Outage
	for i := 0; i < maxOutageLogs+3; i++ {
		all = append(all, Outage{Kind: "tunnel", Start: int64(10 * i), End: int64(10*i + 5)})
	}
	out, cut := trimOutagesCut(all)
	if len(out) != maxOutageLogs || cut != 25 {
		t.Fatalf("len %d cut %d", len(out), cut)
	}
}
