package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// nodirHost plays an Iran server whose switcher isn't there: every press fails.
type nodirHost struct{}

func (nodirHost) Label() string                               { return "tir" }
func (nodirHost) WriteFile(string, []byte, os.FileMode) error { return nil }
func (nodirHost) Run(context.Context, string, func(string)) (string, error) {
	return "NODIR\n", nil
}

// A press the switcher never took must not stay saved as the chosen path: the next re-apply
// would carry it out at some unrelated moment.
func TestHSPinFailedPressKeepsPin(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	tn := &Tunnel{ID: "aaa", Name: "t", ServerID: "ir", Active: "bp_reverse", Family: "v4", HotStandby: true, HSPin: "",
		Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 1}, {Method: "paqet", Family: "v4", Index: 2}}}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "ir"}}
		s.Tunnels = []*Tunnel{tn}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hostFor: func(*Server) Host { return nodirHost{} }}
	if _, err := a.hsPinTo(context.Background(), st.Tunnel("aaa"), "paqet|v4"); err == nil {
		t.Fatal("press on a server without a switcher succeeded")
	}
	if p := st.Tunnel("aaa").HSPin; p != "" {
		t.Fatalf("HSPin = %q after a failed press, want unchanged", p)
	}
}

// Teardown removes the unit's drop-ins (also when the unit file is gone) and BackPack's state.
func TestTeardownRemovesDropInsAndBackpackState(t *testing.T) {
	s := teardownScript(&Tunnel{ID: "f9665a1f5839x97", Index: 97})
	for _, want := range []string{"rm -rf /etc/systemd/system/$u.d", "rm -f /etc/backpack/tp-f9665a1f5839x97.*"} {
		if !strings.Contains(s, want) {
			t.Errorf("teardown lacks %q", want)
		}
	}
	// the drop-in removal sits outside the "unit file exists" test
	i, j := strings.Index(s, "  fi\n"), strings.Index(s, "rm -rf /etc/systemd/system/$u.d")
	if i < 0 || j < i {
		t.Errorf("drop-in removal only runs while the unit file exists:\n%s", s)
	}
}

// failHost fails every script that stops path x97 (the teardown doesn't reach its end).
type failHost struct{}

func (failHost) Label() string                               { return "kh" }
func (failHost) WriteFile(string, []byte, os.FileMode) error { return nil }
func (failHost) Run(_ context.Context, s string, _ func(string)) (string, error) {
	if strings.Contains(s, "x97") {
		return "", errors.New("ssh dropped")
	}
	return "TP-TEARDOWN-DONE\n", nil
}

// A path leaving t.Paths whose teardown didn't finish keeps a cleanup under its own id, and
// the cleanup is dropped once the tunnel lists that path again.
func TestTeardownPathsDefersFailedSide(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	tn := &Tunnel{ID: "f9665a1f5839", Name: "t", ServerID: "ir", ForeignID: "kh", Active: "gre", Family: "v4", HotStandby: true,
		Paths: []HSPath{{Method: "gre", Family: "v4", Index: 1}}}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "ir"}, {ID: "kh", Name: "kh"}}
		s.Tunnels = []*Tunnel{tn}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	a.teardownPaths(context.Background(), fakeHost{"TP-TEARDOWN-DONE"}, failHost{}, tn, []HSPath{{Method: "tpk", Family: "v4", Index: 97}})
	var got []Cleanup
	st.View(func(s *State) { got = append(got, s.Cleanups...) })
	if len(got) != 1 || got[0].ServerID != "kh" || got[0].TunnelID != "f9665a1f5839x97" || !strings.Contains(got[0].Script, "tp-f9665a1f5839x97.service") {
		t.Fatalf("cleanups = %+v, want one for the path on kh", got)
	}
	held := false
	st.View(func(s *State) { held = pendingIndices(s)[97] })
	if !held {
		t.Error("the path's number is not held while its leftovers wait")
	}
	if p, part := splitCleanupID("f9665a1f5839x97"); p != "f9665a1f5839" || part != "x97" {
		t.Errorf("splitCleanupID = %q %q", p, part)
	}
}

// Optimize sizes TCP memory and orphans by RAM and keeps the default socket buffer small.
func TestBuildSysctlTCPMemory(t *testing.T) {
	conf, _ := buildSysctl(OptimizeResult{RAMMB: 8192, CPUs: 4, BBR: true})
	for _, want := range []string{
		"net.ipv4.tcp_mem=262144 393216 524288",
		"net.ipv4.tcp_max_orphans=131072",
		"net.ipv4.tcp_orphan_retries=2",
		"net.core.rmem_default=262144",
		"net.core.wmem_default=262144",
	} {
		if !strings.Contains(conf, want+"\n") {
			t.Errorf("missing %q in\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "%!") {
		t.Errorf("format error in\n%s", conf)
	}
	if o := optzOverrides(conf); !strings.Contains(o, `net\.ipv4\.tcp_mem`) || strings.Contains(o, "nf_conntrack_max)") {
		t.Errorf("override check: %s", o)
	}
}

// The panel's sysctl files sort after other panels' (the last file wins at boot), and a
// tunnel start applies only them — "sysctl --system" re-applied the others' 256 MB buffers.
func TestSysctlOwnFilesLast(t *testing.T) {
	if strings.Contains(sysctlBBR, "sysctl --system") {
		t.Error("sysctlBBR still runs sysctl --system")
	}
	for _, f := range []string{"zzz-tunnel-panel-base.conf", "zzz-tunnel-panel-optz.conf", "zzz-tunnel-panel-ports.conf"} {
		if f < "zz-backpack.conf" || f < "99-zz-botping-gre.conf" {
			t.Errorf("%s sorts before other panels' files", f)
		}
	}
	if !strings.Contains(panelPortsSetup, "zzz-tunnel-panel-ports.conf") {
		t.Error("reserved ports still in a file that sorts early")
	}
	for _, m := range []string{"methods_backhaul.go", "methods_backpack.go"} {
		b, _ := os.ReadFile(m)
		if strings.Count(string(b), "skip_optz = true") != 2 {
			t.Errorf("%s: both sides should set skip_optz", m)
		}
	}
}

// The switcher, run for real with a fake probe: an outage moves the users off path 0, and
// once path 0 is stable again they go back to it — before, auto mode left them on the
// fallback for hours (NOBACK) or for good.
func TestHSSwitcherBackAfterOutage(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the switcher for ~20 s")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	d := t.TempDir()
	w := func(name, s string) { _ = os.WriteFile(filepath.Join(d, name), []byte(s), 0o755) }
	// probe check -addr X … → the content of st_X; probe speed -addr X → sp_X
	w("probe", `#!/bin/bash
a=""; while [ $# -gt 0 ]; do [ "$1" = -addr ] && a=$2; shift; done
cd "$(dirname "$0")"
if [ -f "q_$a" ]; then cat "q_$a"; exit 0; fi
cat "st_$a" 2>/dev/null || echo down
`)
	w("conf", "P="+filepath.ToSlash(filepath.Join(d, "probe"))+"\nN=3\nEVERY=1\nFAILS=2\nBACK=3\nPORTS=\"\"\nSBY=1\nSPMB=1\nSPEVERY=999999\nHOLD=1000\nLOSSBAD=50\nSPMIN=1\nPLANMAX=3\nGRACE=1\nSTEADY=1\nNOBACK=21600\n")
	w("targets", "p0\np1\np2\n")
	w("mode", "auto\n")
	w("base.sh", "true\n")
	for _, k := range []string{"0", "1", "2"} {
		w("up-"+k+".sh", "true\n")
		w("flush-"+k+".sh", "true\n")
	}
	w("active", "0 1\n")
	w("st_p0", "ok 50 1 0\n")
	w("st_p1", "down\n")
	w("st_p2", "ok 60 1 0\n")
	w("switch.sh", hsSwitcher)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, filepath.Join(d, "switch.sh"))
	cmd.Dir = d
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	events := func() string { b, _ := os.ReadFile(filepath.Join(d, "events.log")); return string(b) }
	wait := func(what string, ok func(string) bool) {
		for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(300 * time.Millisecond) {
			if ok(events()) {
				return
			}
		}
		t.Fatalf("%s did not happen; events:\n%s", what, events())
	}
	time.Sleep(2 * time.Second)
	w("st_p0", "down\n") // path 0 drops
	wait("failover to path 2", func(e string) bool { return strings.Contains(e, " switch 0 2 path 0 down") })
	w("st_p0", "ok 50 1 0\n") // and comes back
	wait("back to path 0", func(e string) bool { return strings.Contains(e, " switch 2 0 back to path 0 after its outage") })
}
