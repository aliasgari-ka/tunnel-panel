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

// A rebuild wipes the switcher's directory: the new switcher starts with no "active" file and
// the panel's choice in pin.new (seen live 2026-11-14 on تانل آمریکا: pin = BackPack reverse,
// index 1). It must start the users on the chosen path, not on path 0 — there path 0 (Plain
// GRE) was dead, the users waited 34 s for the failover, which then took path 4 and the
// choice was never acted on.
func TestHSFreshStartOnPin(t *testing.T) {
	log := runFreshSim(t, 8*time.Second, []string{"p1", "p2"}, nil)
	if !strings.Contains(log, "switch -1 1 start") {
		t.Fatalf("want the users started on the chosen path 1:\n%s", log)
	}
	if strings.Contains(log, "switch -1 0") || strings.Contains(log, "switch 1 ") {
		t.Fatalf("users were put on another path:\n%s", log)
	}
}

// The chosen path doesn't answer yet when the switcher starts (its core still connecting),
// another one does: the users go to a working path at once (nobody is on any path yet, so no
// grace to wait out), and back to the chosen path as soon as it answers.
func TestHSFreshStartHealthyThenPin(t *testing.T) {
	log := runFreshSim(t, 12*time.Second, []string{"p2"}, func(d string) {
		time.Sleep(4 * time.Second)
		_ = os.WriteFile(filepath.Join(d, "up_p1"), nil, 0o644)
	})
	if !strings.Contains(log, "switch -1 1 start") {
		t.Fatalf("want the start on the chosen path 1:\n%s", log)
	}
	if !strings.Contains(log, "switch 1 2 ") {
		t.Fatalf("want an immediate move to the working path 2:\n%s", log)
	}
	if !strings.Contains(log, "switch 2 1 ") {
		t.Fatalf("want the users back on the chosen path 1 once it answers:\n%s", log)
	}
	// GRACE is 30 s in this run: the move happened before any failover could
	if strings.Contains(log, "down for") {
		t.Fatalf("waited for the failover grace instead of moving at the start:\n%s", log)
	}
}

// runFreshSim runs the switcher in a fresh directory (as after a rebuild) for dur: 3 paths,
// auto mode, pin.new = 1; the paths in up answer their checks (a file up_<addr> each, which
// later may create). Returns events.log.
func runFreshSim(t *testing.T, dur time.Duration, up []string, later func(dir string)) string {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the switcher for several seconds")
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
case "$2" in
  check) if [ -f "$D/up_$addr" ]; then echo "ok 100 0 0"; else echo down; fi;;
  speed) echo 5000;;
esac
`)
	w("conf", "P="+filepath.ToSlash(filepath.Join(d, "probe"))+"\nN=3\nEVERY=1\nFAILS=3\nBACK=600\nPORTS=\"\"\nSBY=1\nSPMB=1\nSPEVERY=99999\nHOLD=1000\nLOSSBAD=50\nSPMIN=1000\nPLANMAX=3\nGRACE=30\nSTEADY=1\nNOBACK=21600\nVERIFY=300\n")
	w("targets", "p0 h0\np1 h1\np2 h2\n")
	w("mode", "auto\n")
	w("pin.new", "1\n")
	for _, f := range []string{"up-0.sh", "up-1.sh", "up-2.sh", "flush-0.sh", "flush-1.sh", "flush-2.sh", "base.sh"} {
		w(f, "#!/bin/bash\nexit 0\n")
	}
	for _, p := range up {
		w("up_"+p, "")
	}
	w("switch.sh", hsSwitcher)

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	if later != nil {
		go later(d)
	}
	_ = exec.CommandContext(ctx, "bash", filepath.ToSlash(filepath.Join(d, "switch.sh"))).Run()

	b, _ := os.ReadFile(filepath.Join(d, "events.log"))
	return string(b)
}
