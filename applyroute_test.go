package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Choosing a hot-standby tunnel's own method while the switcher has its users on another
// path (auto mode moved them, nothing pinned) is an in-place switch, not a re-apply: the
// re-apply rebuilt the tunnel and cut everyone (seen live on تانل فنلاند). With the users
// already on it, the same press still means a re-apply.
func TestApplyOwnMethodSwitchesInPlace(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1", IPv6: "2001:db8::1"},
			{ID: "kh1", Name: "fi", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "fin", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443",
			Index: 1, Active: "bp_reverse", Selected: "bp_reverse", HotStandby: true, HSAuto: true,
			Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 1}, {Method: "direct6", Family: "v6", Index: 2}}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}}
	tun := st.Tunnel("aaaaaaaaaaaa")

	// auto mode has the users on Direct v6
	a.hsViews[tun.ID] = &hsView{Active: 1, Keys: []string{"bp_reverse|v4", "direct6|v6"}, OK: []bool{true, true}}
	j, err := a.ApplyRoute(tun, "bp_reverse", "v4")
	if err != nil {
		t.Fatal(err)
	}
	if k := j.snapshot().Kind; k != "switch" {
		t.Fatalf("own method while the users are elsewhere: a %q job, want an in-place switch", k)
	}
	for j.snapshot().Status == "running" {
		time.Sleep(10 * time.Millisecond)
	}

	// the users are on it already: that press is a re-apply
	a.hsViews[tun.ID] = &hsView{Active: 0, Keys: []string{"bp_reverse|v4", "direct6|v6"}, OK: []bool{true, true}}
	_ = st.Update(func(*State) error { tun.HSPin = ""; return nil })
	j2, err := a.ApplyRoute(tun, "bp_reverse", "v4")
	if err != nil {
		t.Fatal(err)
	}
	if k := j2.snapshot().Kind; k == "switch" {
		t.Fatalf("own method with the users already on it switched instead of re-applying")
	}
	_, _ = a.jobs.cancel(j2.ID) // it would try to reach the (test-net) servers
}

// A method the route allows that isn't running as a path (it failed, or was turned on for the
// route since) starts only that path: the rebuild it used to be restarted every path and cut
// all users. One the route leaves out is still a full apply.
func TestApplyStartsOnlyTheNewPath(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1", IPv6: "2001:db8::1"},
			{ID: "kh1", Name: "fi", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "fin", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443",
			Index: 1, Active: "bp_reverse", Selected: "bp_reverse", HotStandby: true,
			Paths: []HSPath{{Method: "bp_reverse", Family: "v4", Index: 1}, {Method: "gre", Family: "v4", Index: 2, Failed: "timeout"}}}}
		s.RouteSkip = map[string][]string{routeKey("ir1", "kh1"): {"backhaul|v4"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}}
	tun := st.Tunnel("aaaaaaaaaaaa")
	wait := func(j *Job) {
		_, _ = a.jobs.cancel(j.ID) // it would try to reach the (test-net) servers
		for j.snapshot().Status == "running" {
			time.Sleep(10 * time.Millisecond)
		}
	}

	for _, mid := range []string{"gre", "icmp"} { // failed on the last apply / never a path
		j, err := a.ApplyRoute(tun, mid, "v4")
		if err != nil {
			t.Fatal(err)
		}
		s := j.snapshot()
		for i := 0; i < 200 && len(s.Lines) == 0; i++ {
			time.Sleep(5 * time.Millisecond)
			s = j.snapshot()
		}
		if s.Kind != "switch" || len(s.Lines) == 0 || !strings.Contains(s.Lines[0], "starting only it") {
			t.Fatalf("%s: a %q job %q, want only that path started", mid, s.Kind, s.Lines)
		}
		wait(j)
	}
	j, err := a.ApplyRoute(tun, "backhaul", "v4")
	if err != nil {
		t.Fatal(err)
	}
	if k := j.snapshot().Kind; k == "switch" {
		t.Fatalf("a method the route leaves out was added as a path")
	}
	wait(j)
}

// A switcher deployed with paths added or removed comes back on the users' path, not on
// whatever path now has its old index.
func TestHSKeepActive(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	run := func(keys, keysNew, active string) string {
		w := func(n, c string) {
			if c == "" {
				_ = os.Remove(filepath.Join(dir, n))
				return
			}
			_ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644)
		}
		w("keys", keys)
		w("keys.new", keysNew)
		w("active", active)
		if out, err := exec.Command(bash, "-c", hsKeepActive(filepath.ToSlash(dir))).CombinedOutput(); err != nil || len(out) > 0 {
			t.Fatalf("%v %s", err, out)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "keys")); string(b) != keysNew {
			t.Errorf("keys not renewed: %q", b)
		}
		b, err := os.ReadFile(filepath.Join(dir, "active"))
		if err != nil {
			return "gone"
		}
		return strings.TrimSpace(string(b))
	}
	if got := run("a|v4\nb|v4\nc|v6\n", "a|v4\nc|v6\nd|v4\n", "2 1700"); got != "1 1700" {
		t.Errorf("a path removed before the users' one: active %q, want 1", got)
	}
	if got := run("a|v4\nb|v4\n", "a|v4\nc|v6\n", "1 1700"); got != "gone" {
		t.Errorf("the users' path removed: active %q, want none", got)
	}
	if got := run("", "a|v4\nb|v4\n", "1 1700"); got != "1 1700" {
		t.Errorf("from before keys existed: active %q, want it kept", got)
	}
}
