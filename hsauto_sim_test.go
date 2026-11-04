package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The switcher with a fake probe: path 1 looks better idle (lower ping, faster) than the
// users' path 0 measured under their traffic, so auto mode moves them — but under the users'
// traffic path 1 turns out slower than path 0 was. The check after the move must take them
// back, and not move them there again right away.
func TestHSAutoGoesBackFromWorsePath(t *testing.T) {
	log := runSwitcherSim(t, 2000)
	if !strings.Contains(log, "switch 0 1 auto:") || !strings.Contains(log, "switch 1 0 auto: back to path 0") {
		t.Fatalf("want a move to path 1 and back to path 0:\n%s", log)
	}
	if strings.Count(log, "switch 0 1") > 1 {
		t.Fatalf("moved to the worse path again:\n%s", log)
	}
}

// The same move where path 1 holds up under the users' traffic stays.
func TestHSAutoKeepsBetterPath(t *testing.T) {
	log := runSwitcherSim(t, 6000)
	if !strings.Contains(log, "switch 0 1 auto:") || strings.Contains(log, "switch 1 0") || !strings.Contains(log, "checked after the move") {
		t.Fatalf("want a move to path 1 that stays after its check:\n%s", log)
	}
}

// runSwitcherSim runs the switcher ~25 s; path 1 measures p1loaded kbit/s while it carries
// the users (path 0: 5000). Returns events.log.
func runSwitcherSim(t *testing.T, p1loaded int) string {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the switcher for ~25 s")
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
	// fake probe: check → "ok <rtt> 0 0"; speed → the path's loaded speed when it carries the
	// users (the switcher's "active" file), else its idle speed
	w("probe", `#!/bin/bash
D=$(dirname "$0"); addr=$4
case "$addr" in p0) rtt=100; idle=10000; loaded=5000;; p1) rtt=20; idle=10000; loaded=`+strconv.Itoa(p1loaded)+`;; esac
case "$2" in
  check) echo "ok $rtt 0 0";;
  speed) read -r a _ < "$D/active"; if [ "p$a" = "$addr" ]; then echo $loaded; else echo $idle; fi;;
esac
`)
	w("conf", "P="+filepath.ToSlash(filepath.Join(d, "probe"))+"\nN=2\nEVERY=1\nFAILS=3\nBACK=1\nPORTS=\"\"\nSBY=1\nSPMB=1\nSPEVERY=99999\nHOLD=1000\nLOSSBAD=50\nSPMIN=1000\nPLANMAX=3\nGRACE=0\nSTEADY=1\nNOBACK=21600\nVERIFY=3\n")
	w("targets", "p0 h0\np1 h1\n")
	w("mode", "auto\n")
	w("pin", "0\n")
	for _, f := range []string{"up-0.sh", "up-1.sh", "flush-0.sh", "flush-1.sh", "base.sh"} {
		w(f, "#!/bin/bash\nexit 0\n")
	}
	w("switch.sh", hsSwitcher)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "bash", filepath.ToSlash(filepath.Join(d, "switch.sh"))).Run()

	b, _ := os.ReadFile(filepath.Join(d, "events.log"))
	return string(b)
}
