package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWpNeed(t *testing.T) {
	cases := []struct {
		inf             map[string]string
		want            string
		carry, spare, g int
		used            bool
	}{
		{map[string]string{"ig": "proxy4", "google": "direct", "ytm": "ipv6"}, "", 0, 0, 0, false},
		// warp6: one account carries Instagram (own IPv6 each), whatever the load
		{map[string]string{"ig": "warp6", "google": "proxy1", "mode": "BALANCE", "wpeak": "9000"}, "", 1, 1, 0, true},
		// IPv4 balance: the 24 h peak decides
		{map[string]string{"ig": "warp", "mode": "BALANCE", "wpeak": "632"}, "", 1, 1, 0, true},
		{map[string]string{"ig": "warp", "mode": "BALANCE", "wpeak": "6000"}, "", 3, 1, 0, true},
		{map[string]string{"ig": "warp", "mode": "BALANCE", "wpeak": "999999"}, "", 8, 1, 0, true},
		// Google on WARP: its own on top; only Google: one other account beside them
		{map[string]string{"ig": "warp6", "google": "warp6", "gw": "6,7", "warps": "7"}, "", 1, 1, 2, true},
		{map[string]string{"ig": "proxy2", "google": "warp6", "gw": "2", "warps": "2"}, "", 1, 0, 2, true},
		// Instagram moved to a proxy by the repair, waiting to go back to WARP: the pool stays
		{map[string]string{"ig": "proxy4", "google": "direct"}, "warp6", 1, 1, 0, true},
		// another service on WARP
		{map[string]string{"ig": "proxy1", "spotify": "warp"}, "", 1, 1, 0, true},
	}
	for i, c := range cases {
		cr, sp, g, u := wpNeed(c.inf, c.want)
		if cr != c.carry || sp != c.spare || g != c.g || u != c.used {
			t.Errorf("case %d: got %d %d %d %v, want %d %d %d %v", i, cr, sp, g, u, c.carry, c.spare, c.g, c.used)
		}
	}
}

// the server of the screenshot: warp6, 1 working, 6 standbys on "different exit IP"
func TestWpPlanStandbys(t *testing.T) {
	now := time.Now().Unix()
	d := IgWarps{}
	for n := 1; n <= 7; n++ {
		w := IgWarp{N: n, State: "out", Why: "ip", ID: "a" + string(rune('0'+n)), Age: 86400}
		if n == 4 {
			w.State, w.Why = "ok", ""
		}
		d.Warps = append(d.Warps, w)
	}
	p := wpPlan(d, nil, 2, true, true, now)
	if p.Good != 1 || p.Untest != 6 || len(p.Test) != wpTestMax || len(p.Bad) != 0 || len(p.Extra) != 0 {
		t.Fatalf("untested: %+v", p)
	}
	// tested: 2 good, 3 read IR, 1 down
	res := map[int]string{1: "ok x DE FRA 1", 2: "no x IR AMS 1", 3: "ok x DE FRA 1", 5: "no x IR AMS 1", 6: "down - - - 1", 7: "no x IR AMS 1"}
	for i := range d.Warps {
		if r, ok := res[d.Warps[i].N]; ok {
			d.Warps[i].setTest(strings.Replace(r, " 1", " "+strconv.FormatInt(now, 10), 1))
		}
	}
	p = wpPlan(d, nil, 2, true, true, now)
	if p.Good != 3 || len(p.Bad) != 4 || len(p.Extra) != 1 || p.Extra[0].N != 3 {
		t.Fatalf("tested: good %d bad %d extra %+v", p.Good, len(p.Bad), p.Extra)
	}
	// a young account is never removed
	d.Warps[2].Age = 60
	if p = wpPlan(d, nil, 2, true, true, now); len(p.Extra) != 0 {
		t.Fatalf("young removed: %+v", p.Extra)
	}
	// Google's own are never judged
	if p = wpPlan(d, []int{6, 7}, 2, true, true, now); len(p.Bad) != 2 {
		t.Fatalf("google's own judged: %+v", p.Bad)
	}
	// a no-music country only matters with Instagram on WARP
	if p = wpPlan(d, nil, 2, true, false, now); len(p.Bad) != 1 {
		t.Fatalf("igOff bad: %+v", p.Bad)
	}
}

func TestIgParseWarpsPool(t *testing.T) {
	out := "W\tn=1\tep=e\told=\tkey=\tip=\tloc=\twarp=\tsel=\tselage=\tout=ip\tnew=\tfail=\tgcc=\tgccage=\tid=123456789\tage=7200\ttst=ok 2a09::1 DE FRA 1700000000\n" +
		"S\tactive=\tgact=\tsel=ok\tpoolip=2a09::2\tselago=30\tccstop=3600\tfnext=0\trejcc=IR\thour=4\tvia=1\n"
	d := igParseWarps(out)
	if len(d.Warps) != 1 || d.Warps[0].ID != "123456789" || d.Warps[0].Age != 7200 || d.Warps[0].Test != "ok" || d.Warps[0].TestCC != "DE" || d.Warps[0].TestAt != 1700000000 {
		t.Fatalf("warp: %+v", d.Warps)
	}
	if d.CCStop != 3600 || d.RejCC != "IR" || d.Hour != 4 || !d.Via {
		t.Fatalf("server: %+v", d)
	}
}

// WPDUMP=dir writes the two server scripts for a sandbox run (bash on Linux)
func TestWpDumpScripts(t *testing.T) {
	dir := os.Getenv("WPDUMP")
	if dir == "" {
		t.Skip("WPDUMP not set")
	}
	_ = os.WriteFile(filepath.Join(dir, "wptrim.sh"), []byte(wpTrimScript), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "wptest.sh"), []byte(wpTestScript), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "igwarps.sh"), []byte(igWarpScript), 0o644)
}
