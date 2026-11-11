package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Regression tests for the usage bugs found on 2026-11-11.

// A running tunnel missing one read (a read cut short) held its whole route back: the
// foreign server's bytes of that interval were dropped. Now they are kept for the next read.
func TestUsageHoldUnreadTunnel(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Unix(hourStart(time.Now()), 0).Add(10 * time.Minute)
	pairs := map[string]string{"a": "ir|de", "b": "ir|de"}
	round := func(at time.Time, pd uint64, tun map[string]uint64) {
		rs := []usageRead{{kind: "p", id: "ir|de|1.2.3.4", d: pd}}
		for id, d := range tun {
			rs = append(rs, usageRead{kind: "t", id: id, d: d})
		}
		u.recordLocked(at, rs, pairs)
	}
	round(now, 1000, map[string]uint64{"a": 100, "b": 100})
	round(now.Add(time.Minute), 1100, map[string]uint64{"a": 200}) // b's read was cut off
	round(now.Add(2*time.Minute), 1300, map[string]uint64{"a": 300, "b": 300})
	if got := u.Days[0].Peers["ir|de"]; got == nil || got.Down != 300 {
		t.Fatalf("from foreign %+v, want 300 (the held interval counted)", got)
	}
}

// A tunnel whose counters stay broken no longer stops its route from being counted.
func TestUsageStaleTunnelDoesNotBlockRoute(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Unix(hourStart(time.Now()), 0).Add(time.Minute)
	pairs := map[string]string{"a": "ir|de", "broken": "ir|de"}
	u.recordLocked(now, []usageRead{{kind: "p", id: "ir|de|1.2.3.4", d: 1000}, {kind: "t", id: "a", d: 100}}, pairs)
	for i := 1; i <= 4; i++ { // "broken" never read
		at := now.Add(time.Duration(i) * time.Minute)
		u.recordLocked(at, []usageRead{{kind: "p", id: "ir|de|1.2.3.4", d: 1000 + uint64(i)*100}, {kind: "t", id: "a", d: 100 + uint64(i)*90}}, pairs)
	}
	if got := u.Days[0].Peers["ir|de"]; got == nil || got.Down != 400 {
		t.Fatalf("from foreign %+v, want 400", got)
	}
}

// Counting chains made again (a new mark) grew past the last read before the next one: the
// delta was taken for an increase and the pair was not started again.
func TestUsageMarkRestart(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Unix(hourStart(time.Now()), 0).Add(time.Minute)
	pairs := map[string]string{"a": "ir|de"}
	rd := func(at time.Time, pd, d4, d6 uint64, ep string) {
		u.recordLocked(at, []usageRead{{kind: "p", id: "ir|de|1.2.3.4", d: pd},
			{kind: "t", id: "a", src: ep, d: d4 + d6, parts: [][2]uint64{{d4, 0}, {d6, 0}}}}, pairs)
	}
	rd(now, 1000, 500, 10, "e:1+1")
	rd(now.Add(time.Minute), 1700, 700, 10, "e:2+1") // v4 chains made again; already at 700
	x := u.Days[0].Tunnels["a"]
	if x.Down != 700 {
		t.Fatalf("tunnel %+v, want 700 (the re-made part's whole value)", x)
	}
	if p := u.Days[0].Peers["ir|de"]; p == nil || p.Down != 700 {
		t.Fatalf("peer %+v, want 700 (a marked restart keeps the route counted)", p)
	}
	// the first read with marks after an upgrade only sets a baseline
	u.Last["t:a"].Src = ""
	rd(now.Add(2*time.Minute), 1800, 800, 10, "e:2+1")
	if x := u.Days[0].Tunnels["a"]; x.Down != 700 {
		t.Fatalf("upgrade read counted: %+v", x)
	}
}

// One part's down went down while its up grew (restart): both directions count from zero.
func TestUsageRestartOneDirection(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Unix(hourStart(time.Now()), 0).Add(time.Minute)
	u.addPartsLocked(now, "t", "a", "", 1000, 50, [][2]uint64{{1000, 50}})
	u.addPartsLocked(now.Add(time.Minute), "t", "a", "", 10, 900, [][2]uint64{{10, 900}})
	if x := u.Days[0].Tunnels["a"]; x.Down != 10 || x.Up != 900 {
		t.Fatalf("got %+v, want 10/900", x)
	}
}

// A deleted or moved tunnel's past hours kept being priced on its current route (or not at all).
func TestUsagePricedOnBucketRoute(t *testing.T) {
	b := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Down: 100, Up: 10}, "b": {Down: 100, Up: 10}},
		Servers: map[string]*UsageBytes{},
		Peers:   map[string]*UsageBytes{"ir|de": {Down: 220}},
		Pairs:   map[string]string{"a": "ir|de", "b": "ir|de"}}
	// "a" is deleted, "b" now runs to fi
	paid, est := usagePaid(b, map[string][2]string{"b": {"ir", "fi"}})
	if paid["a"] != 120 || paid["b"] != 120 || est["a"] || est["b"] {
		t.Fatalf("paid %v est %v, want 120 each, measured", paid, est)
	}
	// a route with no foreign count in the bucket is estimated, not priced at its upload only
	b.Pairs["b"] = "ir|nl"
	paid, est = usagePaid(b, nil)
	if paid["b"] != 110 || !est["b"] {
		t.Fatalf("no peer row: paid %v est %v", paid, est)
	}
}

// An idle tunnel was charged an equal share of its server's card.
func TestUsageIdleTunnelNoCardShare(t *testing.T) {
	b := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {}, "b": {}},
		Servers: map[string]*UsageBytes{"ir": {Down: 1000}}}
	paid, _ := usagePaid(b, map[string][2]string{"a": {"ir", "de"}, "b": {"ir", "de"}})
	if paid["a"] != 0 || paid["b"] != 0 {
		t.Fatalf("idle tunnels paid %v", paid)
	}
}

// A damaged usage.json was replaced by an empty log on the next save: all history gone.
func TestUsageDamagedFileKept(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	u := &usageLog{Last: map[string]*usageLast{}}
	u.addLocked(time.Now(), "t", "a", 1, 1)
	u.addLocked(time.Now(), "t", "a", 101, 1)
	u.saveLocked()
	u.saveLocked() // the second save keeps the first as .bak
	if err := os.WriteFile(usagePath(), []byte(`{"buckets":[{`), 0o600); err != nil {
		t.Fatal(err)
	}
	v := loadUsage()
	if len(v.Days) != 1 || v.Days[0].Tunnels["a"].Down != 100 {
		t.Fatalf("history not taken from the backup: %+v", v.Days)
	}
	bad, _ := filepath.Glob(usagePath() + ".bad-*")
	if len(bad) != 1 {
		t.Fatalf("damaged file not set aside: %v", bad)
	}
}

// A bucket older than all kept (full list) was made and cut at once: its bytes were lost.
func TestBucketInOlderThanKept(t *testing.T) {
	var l []*usageBucket
	for i := 0; i < 3; i++ {
		bucketIn(&l, int64(100+i), 3)
	}
	b := bucketIn(&l, 50, 3)
	addBytes(b.Tunnels, "a", 5, 0)
	found := false
	for _, x := range l {
		if x.Tunnels["a"] != nil {
			found = true
		}
	}
	if !found || len(l) != 3 {
		t.Fatalf("bytes lost: %+v", l)
	}
}

// Stopping deletes the tunnel; the log keeps its route and owner while its bytes are kept.
func TestUsageKnowDeleted(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Now()
	u.addLocked(now, "t", "a", 1, 1)
	u.addLocked(now, "t", "a", 5, 1)
	u.knowLocked(map[string]*usageTun{"a": {Pair: "ir|de", Owner: "ali", Name: "x"}})
	u.knowLocked(map[string]*usageTun{})
	if k := u.Known["a"]; k == nil || k.Owner != "ali" {
		t.Fatalf("known %+v", u.Known)
	}
	if u.Last["t:a"] != nil {
		t.Fatal("a deleted tunnel's baseline kept")
	}
	u.Days, u.Buckets = nil, nil
	u.knowLocked(map[string]*usageTun{})
	if len(u.Known) != 0 {
		t.Fatal("a tunnel with no bytes left is still known")
	}
}

func TestFmtBytesRounding(t *testing.T) {
	for b, want := range map[uint64]string{
		1023:                "1023 B",
		1048500:             "1.0 MB", // 1023.9 KB
		1<<30 - 1:           "1.00 GB",
		1<<40 - 1<<20:       "1.00 TB",
		5 * 1 << 30:         "5.00 GB",
		1536:                "2 KB",
	} {
		if got := fmtBytes(b); got != want {
			t.Errorf("fmtBytes(%d) = %q, want %q", b, got, want)
		}
	}
}

// The counter lines with marks are parsed into totals, parts and the marks.
func TestTrafficParseMarks(t *testing.T) {
	a := &App{traffic: newTrafficMon()}
	a.trafficParse("ir", nil, "T a 30 3 ports 10/1+20/2 ep 111+222\nT b 5 6 iface tp3 ep 7\nT c 8 9 ep 0\nT d - - ports  ep \n")
	s := a.traffic.tunnels
	if s["a"].epoch != "e:111+222" || len(s["a"].parts) != 2 || s["a"].parts[1][0] != 20 {
		t.Fatalf("a: %+v", s["a"])
	}
	if s["b"].epoch != "e:7" || s["b"].Source != "iface" || s["b"].TotalDown != 5 {
		t.Fatalf("b: %+v", s["b"])
	}
	if s["c"].epoch != "e:0" || s["c"].TotalUp != 9 || len(s["c"].parts) != 1 {
		t.Fatalf("c: %+v", s["c"])
	}
	if s["d"].Error == "" {
		t.Fatalf("d: a failed listing must not read as a counter: %+v", s["d"])
	}
}

// fakeIptables puts an iptables on PATH that keeps chains as files and logs each -A; mode
// "fail" makes listings fail as when the xtables lock or the kernel refuses.
func fakeIptablesDir(t *testing.T) (dir string, env []string) {
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("bash"); err != nil {
			t.Skip("no bash")
		}
	}
	dir = t.TempDir()
	sc := `#!/bin/sh
st="$FAKE_DIR/chains"; mkdir -p "$st"
args="$*"; set -- $(echo "$args" | sed 's/-w //; s/-t mangle //')
case "$1" in
  -N) [ -e "$st/$2" ] && exit 1; : > "$st/$2";;
  -F) [ -e "$st/$2" ] || exit 1; : > "$st/$2";;
  -A) echo "$*" >> "$st/$2"; echo "$*" >> "$FAKE_DIR/adds";;
  -nL) [ -e "$st/$2" ] || exit 1;;
  -nvxL) [ "$FAKE_MODE" = fail ] && exit 1; [ -e "$st/$2" ] || exit 1
     echo "Chain $2"; echo " pkts bytes target"; n=$(wc -l < "$st/$2"); echo "  1 $((n*100)) x";;
  -S) case "$2" in
        PREROUTING|POSTROUTING|INPUT|OUTPUT) [ -e "$FAKE_DIR/jump_$2" ] && cat "$FAKE_DIR/jump_$2";;
        *) cat "$st/$2" 2>/dev/null;;
      esac;;
  -I) echo "-A $2 $3 $4" > "$FAKE_DIR/jump_$2";;
  -D) [ -e "$FAKE_DIR/jump_$2" ] || exit 1; rm -f "$FAKE_DIR/jump_$2";;
  -X) rm -f "$st/$2";;
  *) exit 1;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(sc), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, []string{"FAKE_DIR=" + dir, "TP_ACCT_DIR=" + filepath.ToSlash(filepath.Join(dir, "acct"))}
}

func runFakeIpt(t *testing.T, dir string, env []string, script string) string {
	cmd := exec.Command("bash", "-c", `PATH="`+filepath.ToSlash(dir)+`:$PATH"; `+
		`if command -v cygpath >/dev/null; then PATH="$(cygpath -u '`+dir+`'):$PATH"; fi; `+
		script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return string(out)
}

// A listing that failed printed 0 (the next read counted the chains' whole lifetime again),
// and a failed check made the hot-standby rules twice (every byte counted twice).
func TestAcctScriptsFailedListing(t *testing.T) {
	dir, env := fakeIptablesDir(t)
	tn := &Tunnel{ID: "hs1", Ports: "443"}
	first := runFakeIpt(t, dir, env, hsAcct(tn))
	if !strings.Contains(first, "T hs1 200 200 ep ") {
		t.Fatalf("first read: %q", first)
	}
	adds, _ := os.ReadFile(filepath.Join(dir, "adds"))
	n := strings.Count(string(adds), "\n")
	second := runFakeIpt(t, dir, env, hsAcct(tn))
	adds, _ = os.ReadFile(filepath.Join(dir, "adds"))
	if strings.Count(string(adds), "\n") != n {
		t.Fatalf("rules added again on the second read:\n%s", adds)
	}
	mark := strings.Fields(first)[5]
	if mark == "0" || strings.Fields(second)[5] != mark {
		t.Fatalf("mark %q then %q", first, second)
	}
	failed := runFakeIpt(t, dir, append(env, "FAKE_MODE=fail"), hsAcct(tn))
	if !strings.Contains(failed, "T hs1 - - ep ") {
		t.Fatalf("a failed listing read %q", failed)
	}
	pf := &Tunnel{ID: "pf1", Ports: "443"}
	out := runFakeIpt(t, dir, env, acctScript(pf))
	if !strings.Contains(out, "T pf1 200 200 ports 200/200 ep ") {
		t.Fatalf("port read: %q", out)
	}
	if err := os.WriteFile(filepath.Join(dir, "ip6tables"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out := runFakeIpt(t, dir, env, acctScript(pf)); !strings.Contains(out, "T pf1 200 200 ports 200/200 ep ") {
		t.Fatalf("a kernel without IPv6 tables stopped the count: %q", out)
	}
	out = runFakeIpt(t, dir, append(env, "FAKE_MODE=fail"), acctScript(pf))
	if !strings.Contains(out, "T pf1 - - ports") {
		t.Fatalf("failed port read: %q", out)
	}
}

// A range longer than the days kept dropped its latest days, not its oldest.
func TestUsageRangeKeepsEnd(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	u := &usageLog{Last: map[string]*usageLast{}, Known: map[string]*usageTun{"gone1": {Pair: "ir|de", Owner: "ali", Name: "old"}}}
	now := time.Now()
	u.bookLocked(now, "t", "gone1", 5, 5)
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub(), usage: u}, failures: map[string][]time.Time{}}
	_ = st.Update(func(x *State) error { x.Users = []User{{Username: "ali", Role: roleUser}}; return nil })
	get := func(q string) map[string]any {
		w := httptest.NewRecorder()
		s.usageGet(w, httptest.NewRequest("GET", "/api/usage?"+q, nil))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err, w.Body.String())
		}
		return m
	}
	m := get(fmt.Sprintf("from=%d&to=%d", now.Unix()-500*86400, now.Unix()))
	from, n := int64(m["from"].(float64)), int64(m["n"].(float64))
	if n != usageKeepDays || from+(n-1)*86400 != dayStart(now) {
		t.Fatalf("the range ends %v (n %d), not today", time.Unix(from+(n-1)*86400, 0), n)
	}
	// the signed-out caller sees no one's deleted tunnel
	if len(m["tunnels"].([]any)) != 0 {
		t.Fatalf("deleted tunnel shown to a stranger: %v", m["tunnels"])
	}
}
