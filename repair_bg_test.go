package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The background run does what cuts nobody, never what moves users, and an item it fixed that
// comes back the same day waits for the admin instead of being done over and over.
func TestRepairBgAllow(t *testing.T) {
	var b repairBgState
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, tehran)
	sw := RepairItem{Kind: rkSwitcher, Impact: impBlip, Text: "switcher v13 → v14 (renewed in place)"}
	re := RepairItem{Kind: rkReapply, Impact: impUsers, Text: "3 of 8 paths down", Ask: askRebuild}
	if ok, why := b.allow("", "t1", sw, now); !ok {
		t.Fatalf("a blip item was not allowed: %s", why)
	}
	if ok, _ := b.allow("", "t1", re, now); ok {
		t.Fatal("a re-apply that cuts users ran in the background")
	}
	if ok, _ := b.allow(repairAutoOff, "t1", RepairItem{Kind: rkMemory, Impact: impNone}, now); ok {
		t.Fatal("off still allowed an item")
	}
	sw.Status = "done"
	left := re
	left.Status, left.Why = "left", "needs your OK: users are cut or moved"
	run := &RepairRun{Tunnels: []*RepairTunnel{{ID: "t1", Name: "find", Result: "fixed", Results: []RepairItem{sw, left}}, {ID: "t2", Name: "ok one", Result: "fine"}}}
	if !b.record(run, now) {
		t.Fatal("a run that fixed something counted as nothing")
	}
	if ok, why := b.allow("", "t1", sw, now.Add(2*time.Hour)); ok || !strings.Contains(why, "came back") {
		t.Fatalf("the same fix ran again the same day: %v %q", ok, why)
	}
	if ok, _ := b.allow("", "t1", sw, now.Add(25*time.Hour)); !ok {
		t.Fatal("the fix stayed blocked after a day")
	}
	if ok, _ := b.allow("", "t2", sw, now.Add(time.Hour)); !ok {
		t.Fatal("another tunnel's fix was blocked")
	}
	if b.record(&RepairRun{Tunnels: []*RepairTunnel{{ID: "t2", Name: "x", Result: "fine"}}}, now) {
		t.Fatal("an all-fine run counted as something")
	}

	// the summary: one message after 09:00 Tehran, then nothing that day
	if m := b.summary(time.Date(2026, 11, 15, 8, 0, 0, 0, tehran)); m != "" {
		t.Fatalf("summary before 09:00: %q", m)
	}
	m := b.summary(time.Date(2026, 11, 15, 9, 1, 0, 0, tehran))
	for _, want := range []string{"1 fixed", "1 wait for your OK", "✅ find — switcher v13", "✋ find — 3 of 8 paths down — " + askRebuild} {
		if !strings.Contains(m, want) {
			t.Errorf("summary lacks %q:\n%s", want, m)
		}
	}
	if m := b.summary(time.Date(2026, 11, 15, 15, 0, 0, 0, tehran)); m != "" {
		t.Fatalf("a second summary the same day: %q", m)
	}
	b.record(run, now)
	if m := b.summary(time.Date(2026, 11, 16, 9, 0, 0, 0, tehran)); m == "" {
		t.Fatal("no summary the next day")
	}
	if m := b.summary(time.Date(2026, 11, 17, 9, 0, 0, 0, tehran)); m != "" {
		t.Fatalf("a summary of nothing: %q", m)
	}
}

// memCurrentTest: a unit the panel wrote (settings in the unit file, no drop-in) is current —
// it was reported "missing" after every switcher renewal; an older unit without them, or a
// drop-in with older values, still needs them.
func TestMemCurrentTest(t *testing.T) {
	sh, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		f := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(f)
	}
	fresh := write("fresh.service", renderUnit(Unit{Desc: "x", ExecStart: "/bin/true"}))
	old := write("old.service", "[Unit]\nDescription=x\n\n[Service]\nExecStart=/bin/true\n")
	tuned := write("tuned.service", "[Unit]\nDescription=x\n\n[Service]\nExecStart=/bin/true\n")
	write("tuned.service.d/90-tunnel-panel-memory.conf", goMemDropIn)
	stale := write("stale.service", renderUnit(Unit{Desc: "x", ExecStart: "/bin/true"}))
	write("stale.service.d/90-tunnel-panel-memory.conf", "[Service]\nEnvironment=GOGC=50\nEnvironment=GOMEMLIMIT=128MiB\n")
	if !strings.Contains(renderUnit(Unit{Desc: "x", ExecStart: "/bin/true"}), goMemEnv) {
		t.Fatal("renderUnit no longer carries goMemEnv: memCurrentTest would call every new unit current wrongly")
	}
	for f, want := range map[string]bool{fresh: true, old: false, tuned: true, stale: false} {
		out, _ := exec.Command(sh, "-c", "f="+shq(f)+"\nif "+memCurrentTest()+"; then echo YES; else echo NO; fi").CombinedOutput()
		if got := strings.TrimSpace(string(out)) == "YES"; got != want {
			t.Errorf("%s: current=%v, want %v (%s)", filepath.Base(f), got, want, out)
		}
	}
}
