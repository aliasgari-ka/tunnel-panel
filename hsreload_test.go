package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func hsReloadTunnel() (*App, *Tunnel) {
	st := &Store{S: State{Servers: []*Server{
		{ID: "ir", Name: "ir", IPv4: "192.0.2.1", IPv6: "2001:db8::1", Role: "iran"},
		{ID: "kh", Name: "kh", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign"},
	}}}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443,8443", Index: 1,
		Active: "gre", Selected: "gre", HotStandby: true, Secrets: map[string]string{"psk": "x"}, Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1},
			{Method: "paqet", Family: "v4", Index: 2},
			{Method: "bp_reverse", Family: "v4", Index: 3},
			{Method: "direct6", Family: "v6", Index: 4},
			{Method: "wg", Family: "v4", Index: 5},
		}}
	st.S.Tunnels = []*Tunnel{tn}
	return &App{store: st}, tn
}

// The switcher's files render to the same bytes every time, and taking one path out of the
// list changes only the list files: every other path's own files stay byte for byte (they
// were named by index, so all after the removed one changed — 19 of 22 files rewritten).
func TestHSSwitcherRenderDeterministic(t *testing.T) {
	a, tn := hsReloadTunnel()
	for _, m := range methods {
		if !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(m.ID) {
			t.Fatalf("method id %q can't name a switcher file", m.ID)
		}
	}
	p1, p2 := a.hsSwitcherPlan(tn, tn.Paths), a.hsSwitcherPlan(tn, tn.Paths)
	if len(p1.Files) != len(p2.Files) || p1.Setup != p2.Setup || renderUnit(p1.Unit) != renderUnit(p2.Unit) {
		t.Fatal("two renders differ")
	}
	for k, f := range p1.Files {
		if g, ok := p2.Files[k]; !ok || !bytes.Equal(f.Content, g.Content) || f.Mode != g.Mode {
			t.Fatalf("%s differs between two renders", k)
		}
		if strings.HasSuffix(k, ".new") {
			t.Errorf("%s is used up on the server: as a file it is rewritten every time", k)
		}
	}
	// the batch script itself is the same bytes too
	b1, _ := splitBatch(p1.Files)
	b2, _ := splitBatch(p2.Files)
	if writeBatchScript(b1) != writeBatchScript(b2) {
		t.Fatal("the write script differs between two renders")
	}
	// paqet (2nd of 5) removed: only conf (N) and targets change; base.sh only for an L3 path
	left := append(append([]HSPath(nil), tn.Paths[:1]...), tn.Paths[2:]...)
	p3 := a.hsSwitcherPlan(tn, left)
	var changed []string
	for k, f := range p3.Files {
		if g, ok := p1.Files[k]; !ok || !bytes.Equal(f.Content, g.Content) {
			changed = append(changed, filepath.Base(k))
		}
	}
	sort.Strings(changed)
	for _, c := range changed {
		if c != "conf" && c != "targets" && c != "base.sh" {
			t.Errorf("removing one path rewrote %s (changed: %v)", c, changed)
		}
	}
	if len(changed) > 3 || len(p3.Files) != len(p1.Files)-2 {
		t.Errorf("changed %v; %d files, want %d", changed, len(p3.Files), len(p1.Files)-2)
	}
	if !strings.Contains(p3.Setup, "'gre|v4' 'bp_reverse|v4' 'direct6|v6' 'wg|v4' > ") {
		t.Errorf("keys.new in the setup: %q", p3.Setup)
	}
	s := hsReloadScript(tn, p3.Setup, left)
	if strings.Contains(s, "up-paqet.v4.sh") || !strings.Contains(s, "up-gre.v4.sh") || !strings.Contains(s, hsSwitcherSum) {
		t.Error("the reload script keeps the wrong path files or doesn't check the script's sum")
	}
}

// The running switcher takes a new path list on SIGHUP: no restart, each path's state follows
// it to its new index, the users stay on their path. When their path is the one removed, it
// moves them to another one and clears the old one's connections.
func TestHSSwitcherReload(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the switcher for a few seconds")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for _, c := range []struct {
		name, keys2, wantActive, wantSwitch string
		wantFlush                           bool
	}{
		// users on b (index 1); a, before it, removed: b is index 0 now, nobody moves
		{"before-users", "b|v4\nc|v4\n", "0", "", false},
		// the users' b removed: moved to another path (c, index 1, or a, 0), b's connections cleared
		{"users-path", "a|v4\nc|v4\n", "", "left the list", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := t.TempDir()
			w := func(name, body string) {
				if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			w("probe", "#!/bin/bash\ncase \"$2\" in check) echo \"ok 20 0 0\";; speed) echo 5000;; esac\n")
			conf := func(n int) string {
				return "P=" + filepath.ToSlash(filepath.Join(d, "probe")) + "\nN=" + string(rune('0'+n)) + "\nEVERY=1\nFAILS=3\nBACK=1\nPORTS=\"\"\nSBY=1\nSPMB=1\nSPEVERY=99999\nHOLD=1000\nLOSSBAD=50\nSPMIN=1\nPLANMAX=3\nGRACE=0\nSTEADY=1\nNOBACK=21600\n"
			}
			w("conf", conf(3))
			w("targets", "pa ha\npb hb\npc hc\n")
			w("keys", "a|v4\nb|v4\nc|v4\n")
			w("mode", "manual\n")
			w("pin", "1\n")
			w("active", "1 1700000000\n")
			for _, p := range []string{"a", "b", "c"} {
				w("up-"+p+".v4.sh", "#!/bin/bash\necho up-"+p+" >> calls\n")
				w("flush-"+p+".v4.sh", "#!/bin/bash\necho flush-"+p+" >> calls\n")
			}
			w("base.sh", "#!/bin/bash\nexit 0\n")
			w("switch.sh", hsSwitcher)
			var tg []string
			for _, k := range strings.Fields(c.keys2) {
				tg = append(tg, "p"+k[:1]+" h"+k[:1])
			}
			// the new list as the panel's setup leaves it, then the panel's HUP
			w("run.sh", `cd "$(dirname "$0")"
bash switch.sh & sp=$!
sleep 3
read -r rp rs < running; [ "$rp" = "$sp" ] && echo "RUNNING-PID-OK"
cp conf2 conf; cp targets2 targets; cp keys2 keys; echo 0 > pin.new
echo 42 > reload.req; kill -HUP $sp
for i in $(seq 100); do [ -s reload.done ] && break; sleep 0.1; done
sleep 3
kill -0 $sp && echo "STILL-RUNNING"
kill $sp; wait $sp 2>/dev/null
echo "DONE $(cat reload.done)"
`)
			w("conf2", conf(2))
			w("targets2", strings.Join(tg, "\n")+"\n")
			w("keys2", c.keys2)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, bash, filepath.ToSlash(filepath.Join(d, "run.sh"))).CombinedOutput()
			calls, _ := os.ReadFile(filepath.Join(d, "calls"))
			ev, _ := os.ReadFile(filepath.Join(d, "events.log"))
			act, _ := os.ReadFile(filepath.Join(d, "active"))
			o := string(out)
			if !strings.Contains(o, "DONE 42 ok") || !strings.Contains(o, "STILL-RUNNING") {
				t.Fatalf("reload not answered or the switcher died:\n%s\nevents:\n%s", o, ev)
			}
			if !strings.Contains(o, "RUNNING-PID-OK") {
				t.Errorf("running file doesn't name the switcher's pid:\n%s", o)
			}
			a := strings.Fields(string(act))
			if c.wantActive != "" && (len(a) == 0 || a[0] != c.wantActive) {
				t.Errorf("active %q, want %s\ncalls:\n%s\nevents:\n%s", act, c.wantActive, calls, ev)
			}
			if c.wantActive != "" && (len(a) < 2 || a[1] != "1700000000") {
				t.Errorf("active %q: the time the users went there was lost", act)
			}
			moves := strings.Count(string(ev), " switch ")
			if c.wantSwitch == "" {
				if moves != 0 || strings.Contains(string(calls), "up-a") || strings.Contains(string(calls), "up-c") || strings.Contains(string(calls), "flush") {
					t.Errorf("users moved:\ncalls:\n%s\nevents:\n%s", calls, ev)
				}
			} else if !strings.Contains(string(ev), c.wantSwitch) || strings.Contains(string(ev), "chosen in the panel") {
				t.Errorf("want one move off the removed path:\n%s", ev)
			}
			if got := strings.Contains(string(calls), "flush-b"); got != c.wantFlush {
				t.Errorf("flush of the removed users' path: %v, want %v\n%s", got, c.wantFlush, calls)
			}
			if _, err := os.Stat(filepath.Join(d, "pin.new")); err == nil {
				t.Error("pin.new not taken")
			}
		})
	}
}

// The panel's side of a reload, through bash with a stub systemctl: a switcher running this
// script is sent SIGHUP and answers (no restart); the files of a path gone are deleted. One
// running another script (here: its "running" sum differs) is restarted instead.
func TestHSReloadScript(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the switcher for a few seconds")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	_, tn := hsReloadTunnel()
	for _, stale := range []bool{false, true} {
		d := t.TempDir()
		ds := filepath.ToSlash(d)
		w := func(name, body string) {
			_ = os.MkdirAll(filepath.Dir(filepath.Join(d, name)), 0o755)
			if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		w("probe", "#!/bin/bash\ncase \"$2\" in check) echo \"ok 20 0 0\";; speed) echo 5000;; esac\n")
		w("bin/systemctl", `#!/bin/bash
D=`+ds+`
case "$1" in
  show) case "$3" in MainPID) cat $D/mainpid;; NeedDaemonReload) echo no;; esac;;
  is-active) [ "$2" = -q ] || echo active;;
  *) echo "$*" >> $D/systemctl.log;;
esac
exit 0
`)
		w("bin/journalctl", "#!/bin/bash\nexit 0\n")
		conf := "P=" + ds + "/probe\nN=%d\nEVERY=1\nFAILS=3\nBACK=1\nPORTS=\"\"\nSBY=1\nSPMB=1\nSPEVERY=99999\nHOLD=1000\nLOSSBAD=50\nSPMIN=1\nPLANMAX=3\nGRACE=0\nSTEADY=1\nNOBACK=21600\n"
		w("conf", strings.Replace(conf, "%d", "3", 1))
		w("targets", "pa ha\npb hb\npc hc\n")
		w("keys", "a|v4\nb|v4\nc|v4\n")
		w("mode", "manual\n")
		w("active", "1 1700000000\n")
		for _, p := range []string{"a", "b", "c"} {
			w("up-"+p+".v4.sh", "#!/bin/bash\necho up-"+p+" >> calls\n")
			w("flush-"+p+".v4.sh", "#!/bin/bash\nexit 0\n")
		}
		w("up-0.sh", "#!/bin/bash\nexit 0\n") // named by index, from tp-switcher 13
		w("base.sh", "#!/bin/bash\nexit 0\n")
		w("switch.sh", hsSwitcher)
		paths := []HSPath{{Method: "b", Family: "v4"}, {Method: "c", Family: "v4"}}
		setup := "cd " + ds + "\nprintf 'N=2\\n' >> conf\nprintf 'pb hb\\npc hc\\n' > targets\nprintf 'b|v4\\nc|v4\\n' > keys\n"
		script := hsReloadScript(tn, setup, paths)
		script = strings.ReplaceAll(script, shq(probeBin), shq(ds+"/probe"))
		script = strings.ReplaceAll(script, shq(hsDir(tn)), shq(ds))
		w("reload.sh", script)
		fake := ""
		if stale {
			fake = "echo \"$sp 0000\" > running; "
		}
		w("run.sh", `cd "$(dirname "$0")"; export PATH="$PWD/bin:$PATH"
bash switch.sh & sp=$!; echo $sp > mainpid
sleep 3; `+fake+`
t0=$(date +%s%N); bash reload.sh; echo "EXIT $? after $(( ($(date +%s%N) - t0) / 1000000 )) ms"
sleep 1; kill $sp 2>/dev/null; wait $sp 2>/dev/null
`)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		out, _ := exec.CommandContext(ctx, bash, filepath.ToSlash(filepath.Join(d, "run.sh"))).CombinedOutput()
		cancel()
		o := string(out)
		sl, _ := os.ReadFile(filepath.Join(d, "systemctl.log"))
		want := "TP-SW reload"
		if stale {
			want = "TP-SW restart"
		}
		t.Logf("stale=%v: %s", stale, strings.TrimSpace(o))
		if !strings.Contains(o, want) || !strings.Contains(o, "EXIT 0") {
			t.Fatalf("stale=%v: want %q:\n%s\nsystemctl: %s", stale, want, o, sl)
		}
		if restarted := strings.Contains(string(sl), "restart "); restarted != stale {
			t.Errorf("stale=%v: restarted %v (%s)", stale, restarted, sl)
		}
		for _, f := range []string{"up-a.v4.sh", "flush-a.v4.sh", "up-0.sh"} {
			if _, err := os.Stat(filepath.Join(d, f)); err == nil {
				t.Errorf("stale=%v: %s of a path no longer on the list kept", stale, f)
			}
		}
		if _, err := os.Stat(filepath.Join(d, "up-b.v4.sh")); err != nil {
			t.Errorf("a path's files deleted: %v", err)
		}
	}
}

// Removing a path by hand: one switcher update on the Iran server, then that path's teardown
// on both servers — nothing for the other paths, no new path, a short log ending "done in".
func TestHSRemoveIsLight(t *testing.T) {
	hsOnly = []string{"gre", "wg", "paqet"}
	defer func() { hsOnly = nil }()
	ir, kh := &h2Host{name: "ir"}, &h2Host{name: "kh"}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1,
		Active: "gre", Selected: "gre", HotStandby: true, Options: map[string]map[string]string{"wg": {"mtu": "1300"}},
		OptsManual: map[string][]string{"wg": {"mtu"}}, Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1}, {Method: "paqet", Family: "v4", Index: 2}, {Method: "wg", Family: "v4", Index: 3}}}
	a, st := h2App(t, tn, ir, kh)
	a.hsViews[tn.ID] = &hsView{Active: 0, Keys: []string{"gre|v4", "paqet|v4", "wg|v4"}, OK: []bool{true, true, true}}
	j, err := a.hsRemovePath(tn, "paqet", "v4")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	s := j.snapshot()
	if s.Status != "ok" || !strings.Contains(s.Lines[len(s.Lines)-1], "done in ") {
		t.Fatalf("job %s:\n%s", s.Status, strings.Join(s.Lines, "\n"))
	}
	t.Log("\n" + strings.Join(s.Lines, "\n"))
	if len(s.Lines) > 5 {
		t.Errorf("a long log for one path:\n%s", strings.Join(s.Lines, "\n"))
	}
	for _, h := range []*h2Host{ir, kh} {
		for _, r := range h.snapshot() {
			if strings.Contains(r, "systemctl disable --now") && (strings.Contains(r, tn.ID+"x1") || strings.Contains(r, tn.ID+"x3") || strings.Contains(r, "tp-"+tn.ID+".service")) {
				t.Errorf("%s: another path was stopped:\n%s", h.name, r)
			}
		}
	}
	if kr := kh.snapshot(); len(kr) != 1 || !strings.Contains(kr[0], tn.ID+"x2") {
		t.Errorf("foreign server: want only paqet's teardown, got %d runs", len(kr))
	}
	st.View(func(*State) {
		if len(tn.Paths) != 2 || tn.Options["wg"]["mtu"] != "1300" || len(tn.OptsManual["wg"]) != 1 || tn.Active != "gre" {
			t.Errorf("after the removal: paths %v options %v manual %v active %s", tn.Paths, tn.Options, tn.OptsManual, tn.Active)
		}
	})
}
