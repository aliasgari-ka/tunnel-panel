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

// bug hunt 2026-11-12 (Backhaul Premium ipx outage): the fixes for the 7 confirmed bugs.

func hsTestApp(t *testing.T, tn *Tunnel) *App {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "ir"}, {ID: "kh", Name: "kh"}}
		s.Tunnels = []*Tunnel{tn}
		return nil
	})
	return &App{store: st, jobs: newJobs()}
}

// 1. A path that started and then went down is restarted (only its core), never the users'
// path, with a back-off that doubles while it stays down and is forgotten once it is up.
func TestHSKickDue(t *testing.T) {
	tn := &Tunnel{ID: "x1", Name: "t", ServerID: "ir", ForeignID: "kh", Active: "gre", Family: "v4", HotStandby: true,
		Paths: []HSPath{{Method: "gre", Family: "v4", Index: 10}, {Method: "premium", Family: "v4", Index: 11}, {Method: "tpk", Family: "v4", Index: 12}}}
	a := hsTestApp(t, tn)
	now := time.Unix(1_800_000_000, 0)
	v := &hsView{Active: 0, Keys: []string{"gre|v4", "premium|v4", "tpk|v4"}, OK: []bool{true, false, false},
		Changed: []int64{now.Unix() - 99999, now.Unix() - 7200, now.Unix() - 600}}
	keys := func(ps []HSPath) (s []string) {
		for _, p := range ps {
			s = append(s, p.Method)
		}
		return
	}
	if got := keys(a.hsKickDue(tn, v, now)); len(got) != 1 || got[0] != "premium" {
		t.Fatalf("due = %v, want [premium] (tpk down only 10 min, gre up)", got)
	}
	v.OK[2] = true // tpk came back: only premium is followed from here
	if a.hsKickNoted(tn, "premium|v4", now) != 1 {
		t.Fatal("first restart not counted")
	}
	if got := a.hsKickDue(tn, v, now.Add(59*time.Minute)); len(got) != 0 {
		t.Errorf("restarted again within the hour: %v", keys(got))
	}
	if got := a.hsKickDue(tn, v, now.Add(61*time.Minute)); len(got) != 1 {
		t.Errorf("not due an hour after the first restart: %v", keys(got))
	}
	a.hsKickNoted(tn, "premium|v4", now.Add(61*time.Minute))
	if got := a.hsKickDue(tn, v, now.Add(61*time.Minute+119*time.Minute)); len(got) != 0 {
		t.Errorf("the second gap is two hours: %v", keys(got))
	}
	if hsKickGap(10) != hsKickMax {
		t.Errorf("gap after 10 restarts = %v, want the cap %v", hsKickGap(10), hsKickMax)
	}
	// the users' path is never restarted, even when it is down
	v2 := &hsView{Active: 1, Keys: v.Keys, OK: []bool{true, false, true}, Changed: v.Changed}
	if got := a.hsKickDue(tn, v2, now.Add(48*time.Hour)); len(got) != 0 {
		t.Errorf("the users' path was due: %v", keys(got))
	}
	// up again: the restarts are forgotten
	v3 := &hsView{Active: 0, Keys: v.Keys, OK: []bool{true, true, true}, Changed: v.Changed}
	a.hsKickDue(tn, v3, now)
	if a.hsKickNoted(tn, "premium|v4", now) != 1 {
		t.Error("a path that came back kept its restart count")
	}
	// an apply in progress: nothing
	_ = a.store.Update(func(*State) error { tn.Applying = "gre"; return nil })
	if got := a.hsKickDue(tn, v, now.Add(72*time.Hour)); len(got) != 0 {
		t.Errorf("due during an apply: %v", keys(got))
	}
}

// 1/2. The restart touches only that path's unit, and a server without it is no error.
func TestHSRestartScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	tn := &Tunnel{ID: "x1"}
	s := hsRestartScript(tn, HSPath{Method: "premium", Family: "v4", Index: 11})
	for _, c := range []struct{ fake, want string }{
		{`systemctl() { [ "$1" = restart ] && echo "restart $2"; return 0; }`, "restart tp-x1x11.service\nTP-RESTARTED"},
		{`systemctl() { return 1; }`, "TP-NO-UNIT"},
	} {
		b, _ := exec.Command("bash", "-c", c.fake+"\n"+s).CombinedOutput()
		if strings.TrimSpace(string(b)) != c.want {
			t.Errorf("got %q, want %q", b, c.want)
		}
	}
}

// 2. Apply on a path that runs but is down restarts it first: hsPathDown sees it.
func TestHSPathDown(t *testing.T) {
	tn := &Tunnel{ID: "x1", Name: "t", ServerID: "ir", Active: "gre", Family: "v4", HotStandby: true,
		Paths: []HSPath{{Method: "gre", Family: "v4", Index: 10}, {Method: "premium", Family: "v4", Index: 11}}}
	a := hsTestApp(t, tn)
	a.hsViews = map[string]*hsView{"x1": {Active: 0, Keys: []string{"gre|v4", "premium|v4"}, OK: []bool{true, false}}}
	if p, down := a.hsPathDown(tn, "premium", "v4"); !down || p.Index != 11 {
		t.Errorf("premium: %+v down=%v, want index 11 down", p, down)
	}
	if _, down := a.hsPathDown(tn, "gre", "v4"); down {
		t.Error("gre is up")
	}
}

// 5. While a "paths" job redeploys the switcher, t.Paths has the new order and the old
// switcher still runs: its indices are read in its own order (keys), not the panel's.
func TestHSReadSwitcherOrder(t *testing.T) {
	tn := &Tunnel{ID: "x1", Name: "t", ServerID: "ir", Active: "gre", Family: "v4", HotStandby: true,
		Paths: []HSPath{{Method: "gre", Family: "v4", Index: 10}, {Method: "tpk", Family: "v4", Index: 12}}}
	a := hsTestApp(t, tn)
	// the old switcher: [gre, premium (dropped meanwhile), tpk]; the users are on tpk
	out := "K gre|v4 premium|v4 tpk|v4 \nA 2 1794393513\nM auto\n" +
		"S 0 ok 1 90 - -\nS 1 down 5 - - -\nS 2 ok 1 80 - -\nU active\nW 1 active [WARN] Heartbeat timeout\n"
	v, _, err := a.hsRead(context.Background(), fakeHost{out}, tn, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) != 3 || v.Keys[1] != "premium|v4" || v.Keys[2] != "tpk|v4" {
		t.Fatalf("keys = %v, want the switcher's order", v.Keys)
	}
	if !v.OK[2] || v.OK[1] || v.Why[2] != "" || !strings.Contains(v.Why[1], "Heartbeat timeout") {
		t.Errorf("ok=%v why=%q: the down mark and the reason belong to premium, not tpk", v.OK, v.Why)
	}
	if v.Active != 2 || v.Paths[v.Active] != (HSPath{Method: "tpk", Family: "v4"}).label() {
		t.Errorf("users on %d %v, want tpk", v.Active, v.Paths)
	}
}

// 5. The reason script goes by key: a keys file in another order than the panel's still
// asks each path's own unit.
func TestHSWhyScriptByKey(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	good := []HSPath{{Method: "gre", Family: "v4", Index: 10}, {Method: "tpk", Family: "v4", Index: 12}}
	s := hsWhyScript(&Tunnel{ID: "x1"}, good)
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "keys"), []byte("tpk|v4\ngre|v4\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "status"), []byte("0 down 5 - - -\n1 ok 1 - - -\n"), 0o644)
	fake := `systemctl() { case "$1" in cat) return 0;; is-active) echo "active-$2";; show) echo;; esac; }
`
	cmd := exec.Command("bash", "-c", fake+s)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if got := strings.TrimSpace(string(b)); got != "W 0 active-tp-x1x12.service" {
		t.Errorf("got %q, want switcher index 0 = tpk's unit", got)
	}
}

// 6. Secrets: whole words, quoted values, values after a plain space; no more cut-up
// hostnames and "tokenizer".
func TestHSRedact(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`[ERROR] handshake failed: bad psk "S3cr3t PSK"`, `[ERROR] handshake failed: bad psk ***`},
		{`[ERROR] auth failed, token S3cr3tTok rejected`, `[ERROR] auth failed, token *** rejected`},
		{`[ERROR] token=abcd1234 bad`, `[ERROR] token=*** bad`},
		{`[ERROR] license_key: ZZZ-123`, `[ERROR] license_key: ***`},
		{`[ERROR] tokenizer: unexpected EOF`, `[ERROR] tokenizer: unexpected EOF`},
		{`dial tcp: lookup license1.example.com: no such host`, `dial tcp: lookup license1.example.com: no such host`},
		{`[INFO] License is valid`, `[INFO] License is valid`},
	} {
		if got := hsRedact(c.in); got != c.want {
			t.Errorf("hsRedact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 7. A chosen path the switcher refused is said, and in auto mode the 📌 goes.
func TestHSRefusedPin(t *testing.T) {
	tn := &Tunnel{ID: "x1", Name: "t", ServerID: "ir", Active: "gre", Family: "v4", HotStandby: true, HSPin: "premium|v4",
		Paths: []HSPath{{Method: "gre", Family: "v4", Index: 10}, {Method: "premium", Family: "v4", Index: 11}}}
	a := hsTestApp(t, tn)
	good := hsGood(tn)
	e := "1794393600 keep 0 0 path 1 chosen in the panel doesn't answer — staying"
	if k := hsRefusedPin(e); k != 1 {
		t.Fatalf("refused index = %d", k)
	}
	if _, msg := hsEventText(tn, good, e); !strings.Contains(msg, "Backhaul Premium") || !strings.Contains(msg, "doesn't answer") || !strings.Contains(msg, "stay on Plain GRE") {
		t.Errorf("message = %q", msg)
	}
	if _, msg := hsEventText(tn, good, "1794393600 keep 0 0 compared paths: none clearly better"); msg != "" {
		t.Errorf("an ordinary keep is not reported: %q", msg)
	}
	v := &hsView{Active: 0, Auto: true, Keys: []string{"gre|v4", "premium|v4"}, OK: []bool{true, false}}
	a.hsReport(tn, v, []string{e})
	if tn.HSPin != "" {
		t.Errorf("auto mode: the refused choice still pinned (%q)", tn.HSPin)
	}
	// manual mode keeps it: the switcher goes back to the chosen path once it answers
	_ = a.store.Update(func(*State) error { tn.HSPin, tn.HSSeen = "premium|v4", 0; return nil })
	v.Auto = false
	a.hsReport(tn, v, []string{e})
	if tn.HSPin != "premium|v4" {
		t.Error("manual mode: the choice was dropped")
	}
}
