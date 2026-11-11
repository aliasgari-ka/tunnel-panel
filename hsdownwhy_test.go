package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A path the switcher has down shows when it went down and why: its core's state on the
// Iran server or the last error it logged. Seen live (Finland, Backhaul Premium ipx/tun):
// the page showed a bare ✕ with no latency and no reason, and it read as a panel bug.
func TestHSReadDownReason(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	tn := &Tunnel{ID: "fin", Name: "t", ServerID: "ir", Active: "bp_reverse", Family: "v4", HotStandby: true,
		Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 65}, {Method: "premium", Family: "v4", Index: 57},
			{Method: "tpk", Family: "v4", Index: 58}, {Method: "tpk_rev", Family: "v4", Index: 63}}}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "ir"}}
		s.Tunnels = []*Tunnel{tn}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	out := "A 0 1794393513\nM auto\n" +
		"S 0 ok 1794393000 98 - 21589\n" +
		"S 1 down 1794350000 - - -\n" +
		"S 2 down 1794432342 - - -\n" +
		"S 3 down 1794432342 - - -\n" +
		"U active\n" +
		"W 1 active \n" +
		"W 2 failed 11-Nov [ERROR] dial 65.109.179.143:443: connection refused token=abcd1234\n" +
		"W 3 active 11-Nov [WARN] Heartbeat timeout\n"
	v, _, err := a.hsRead(context.Background(), fakeHost{out}, tn, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Changed) != 4 || v.Changed[1] != 1794350000 || v.Changed[0] != 1794393000 {
		t.Errorf("changed = %v", v.Changed)
	}
	if v.Why[0] != "" {
		t.Errorf("a working path has no reason: %q", v.Why[0])
	}
	if v.Why[1] != "running on the Iran server, but no answer comes through it" {
		t.Errorf("why[1] = %q", v.Why[1])
	}
	w := v.Why[2]
	if !strings.HasPrefix(w, "its core on the Iran server is failed — ") || strings.Contains(w, "65.109.179.143") || strings.Contains(w, "abcd1234") {
		t.Errorf("why[2] = %q (state first, no address, no secret)", w)
	}
	if v.Why[3] != "last error: 11-Nov [WARN] Heartbeat timeout" {
		t.Errorf("why[3] = %q", v.Why[3])
	}
}

// the shell part reports only the paths that are down, one W line each
func TestHSWhyScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	tn := &Tunnel{ID: "fin"}
	good := []HSPath{{Method: "a", Index: 65}, {Method: "b", Index: 57}, {Method: "c", Index: 58}}
	s := hsWhyScript(tn, good)
	for _, u := range []string{"0:tp-finx65.service", "1:tp-finx57.service", "2:tp-finx58.service"} {
		if !strings.Contains(s, u) {
			t.Errorf("script misses %s", u)
		}
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "status"), []byte("0 ok 1 2 - -\n1 down 5 - - -\n2 ok 1 3 - -\n"), 0o644)
	cmd := exec.Command("bash", "-c", "systemctl() { return 1; }; "+s)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if got := strings.TrimSpace(string(b)); got != "W 1 none" {
		t.Errorf("got %q, want only the down path", got)
	}
	if hsWhyScript(tn, nil) != "" {
		t.Error("no paths, no script")
	}
}
