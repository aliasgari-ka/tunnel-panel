package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Three paths: 0 fast (20 Mbit/s, 100 ms), 1 slow (2 Mbit/s, 10 ms — it answers pings first),
// 2 fast (16 Mbit/s, 60 ms). The users' path 0 drops twice. The first time nothing is known of
// the others, so the quickest to answer (path 1) is taken and measured; the second time the
// users must go to path 2, not to the slow one again.
func TestHSFailoverSkipsKnownSlowPath(t *testing.T) {
	log := runSlowSim(t, 0,
		// path 0 is down from its first speed test until path 1 is measured, and again after the way back
		`{ [ -f "$D/sp0" ] && [ ! -f "$D/sp1" ]; } || grep -q "switch 1 0" "$D/events.log" 2>/dev/null`,
		"p0", "switch 0 2")
	if !strings.Contains(log, " switch 0 1 ") || !strings.Contains(log, " switch 1 0 ") {
		t.Fatalf("want a first outage to path 1 and the way back to path 0:\n%s", log)
	}
	if !strings.Contains(log, " switch 0 2 ") || strings.Count(log, " switch 0 1 ") > 1 {
		t.Fatalf("the second outage must take the users to path 2, not to the slow path 1:\n%s", log)
	}
}

// The users are on the slow path 1 (chosen in the panel); it drops, they land on path 2, which
// measures 8× faster. Path 1 answering again must not take them back.
func TestHSNoWayBackToSlowPath(t *testing.T) {
	log := runSlowSim(t, 1,
		`[ -f "$D/sp1" ] && [ ! -f "$D/sp2" ]`,
		"p1", "works again, but it measured")
	if !strings.Contains(log, " switch 1 2 ") || !strings.Contains(log, "works again, but it measured") {
		t.Fatalf("want a move to path 2 and a note that the users stay there:\n%s", log)
	}
	if strings.Contains(log, " switch 2 1 ") {
		t.Fatalf("went back to the slow path:\n%s", log)
	}
}

// runSlowSim runs the switcher (auto mode, the users start on path pin) with a fake probe until
// events.log holds until (at most 60 s, then 3 s more). The path named downAddr is down while
// the shell test downIf holds; a speed test of path k leaves the file sp<k>. Returns events.log.
func runSlowSim(t *testing.T, pin int, downIf, downAddr, until string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the switcher for up to a minute")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	d := t.TempDir()
	w := func(name, body string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w("probe", `#!/bin/bash
D=$(dirname "$0"); addr=$4
case "$addr" in p0) rtt=100; kb=20000;; p1) rtt=10; kb=2000;; p2) rtt=60; kb=16000;; esac
case "$2" in
  check) if [ "$addr" = `+downAddr+` ] && { `+downIf+`; }; then echo down; else echo "ok $rtt 0 0"; fi;;
  speed) : > "$D/s${addr}"; echo $kb;;
esac
`)
	w("conf", "P="+filepath.ToSlash(filepath.Join(d, "probe"))+"\nN=3\nEVERY=1\nFAILS=3\nBACK=1\nPORTS=\"\"\nSBY=1\nSPMB=1\nSPEVERY=99999\nHOLD=1\nLOSSBAD=50\nSPMIN=1000\nPLANMAX=3\nGRACE=0\nSTEADY=1\nNOBACK=21600\nVERIFY=300\n")
	w("targets", "p0 h0\np1 h1\np2 h2\n")
	w("mode", "auto\n")
	w("pin", string(rune('0'+pin))+"\n")
	for _, f := range []string{"up-0.sh", "up-1.sh", "up-2.sh", "flush-0.sh", "flush-1.sh", "flush-2.sh", "base.sh"} {
		w(f, "#!/bin/bash\nexit 0\n")
	}
	w("switch.sh", hsSwitcher)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.ToSlash(filepath.Join(d, "switch.sh")))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(filepath.Join(d, "events.log")); return string(b) }
	for ctx.Err() == nil && !strings.Contains(read(), until) {
		time.Sleep(300 * time.Millisecond)
	}
	if ctx.Err() == nil {
		time.Sleep(3 * time.Second) // what it would do next (a wrong move back) shows up here
	}
	cancel()
	_ = cmd.Wait()
	return read()
}
