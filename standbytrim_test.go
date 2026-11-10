package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStandbyUseTrim(t *testing.T) {
	day := int64(86400)
	cases := []struct {
		name string
		u    standbyUse
		want string // a word of the reason, "" = leave it
	}{
		{"idle and small", standbyUse{anonMB: 20, cpu: 0, kbit: 2, up: day}, ""},
		{"1.5 GB with no traffic (BackPack, xe108)", standbyUse{anonMB: 1510, cpu: 0, kbit: 1, up: 13 * day}, "1510 MB"},
		{"spinning with no traffic (emulated TP Reverse)", standbyUse{anonMB: 148, cpu: 97, kbit: 0, up: 2 * day}, "97%"},
		{"big but users' open connections still on it", standbyUse{anonMB: 900, cpu: 20, kbit: 4000, up: day}, ""},
		{"busy CPU with traffic", standbyUse{anonMB: 100, cpu: 80, kbit: 250000, up: day}, ""},
		{"big right after a restart: no loop", standbyUse{anonMB: 400, cpu: 0, kbit: 0, up: 600}, ""},
		{"an emulated core's 190 MB is its normal size", standbyUse{anonMB: 190, cpu: 2, kbit: 4, up: day}, ""},
	}
	for _, c := range cases {
		got := c.u.trim()
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: trim() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseStandbyUse(t *testing.T) {
	out := "noise\nSU tp-ab12x8.service 1510 0 1 1128000\nSU tp-ab12x92.service 692 0 4 201000\nSU broken 1 2\nSU tp-x.service a 0 0 0\n"
	want := []standbyUse{
		{unit: "tp-ab12x8.service", anonMB: 1510, cpu: 0, kbit: 1, up: 1128000},
		{unit: "tp-ab12x92.service", anonMB: 692, cpu: 0, kbit: 4, up: 201000},
	}
	if got := parseStandbyUse(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("parseStandbyUse = %+v, want %+v", got, want)
	}
}

func TestStandbyUnits(t *testing.T) {
	tn := &Tunnel{ID: "ab12", Name: "x", Active: "bp_reverse", Family: "v4"}
	good := []HSPath{{Method: "bp_reverse", Family: "v4", Index: 8}, {Method: "tpk", Family: "v6", Index: 91}, {Method: "tpk_rev", Family: "v6", Index: 92}}
	keys := []string{"bp_reverse|v4", "tpk|v6", "tpk_rev|v6"}
	now := int64(1_000_000)
	// the users are on tpk v6: the other two are standby
	got := standbyUnits(tn, good, &hsView{Active: 1, Keys: keys, Read: now - 30}, now)
	if want := []string{"tp-ab12x8.service", "tp-ab12x92.service"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("standby units = %v, want %v", got, want)
	}
	for name, v := range map[string]*hsView{
		"no view":                 nil,
		"old view":                {Active: 1, Keys: keys, Read: now - standbyViewAge - 1},
		"users' path not known":   {Active: -1, Keys: keys, Read: now},
		"active beyond the paths": {Active: 3, Keys: keys, Read: now},
	} {
		if got := standbyUnits(tn, good, v, now); got != nil {
			t.Errorf("%s: %v, want nothing touched", name, got)
		}
	}
}

// trimHost answers the measuring script with out and records every other script.
type trimHost struct {
	out string
	ran []string
}

func (h *trimHost) Label() string { return "KH" }
func (h *trimHost) Run(_ context.Context, script string, _ func(string)) (string, error) {
	if strings.Contains(script, "snap()") {
		return h.out, nil
	}
	h.ran = append(h.ran, script)
	return "", nil
}
func (h *trimHost) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestStandbyTrimHost(t *testing.T) {
	h := &trimHost{out: "SU tp-ab12x8.service 1510 0 1 1128000\nSU tp-ab12x90.service 13 0 6 201000\nSU tp-ab12x92.service 692 0 4 201000\nSU tp-ab12x93.service 800 30 90000 201000\n"}
	done := standbyTrimHost(context.Background(), h, []string{"tp-ab12x8.service", "tp-ab12x90.service", "tp-ab12x92.service", "tp-ab12x93.service"})
	want := []string{"systemctl restart 'tp-ab12x8.service'", "systemctl restart 'tp-ab12x92.service'"}
	if !reflect.DeepEqual(h.ran, want) {
		t.Fatalf("restarted %v, want %v", h.ran, want)
	}
	if len(done) != 2 || !strings.Contains(done[0], "1510 MB") {
		t.Fatalf("report = %v", done)
	}
	// nothing to look at: the host isn't even asked
	h2 := &trimHost{}
	if standbyTrimHost(context.Background(), h2, nil) != nil || len(h2.ran) != 0 {
		t.Fatal("no units must mean no work")
	}
}

// the scripts must at least parse (bash -n); skipped where there is no bash.
func TestLeanScriptsParse(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for name, s := range map[string]string{
		"standbyUse": standbyUseScript([]string{"tp-ab12x8.service", "tp-ab12x92.service"}),
		"housekeep":  journalCap + leanHost,
	} {
		f := filepath.Join(t.TempDir(), name+".sh")
		if err := os.WriteFile(f, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", name, err, out)
		}
		if p := os.Getenv("TP_DUMP_SCRIPTS"); p != "" {
			_ = os.WriteFile(filepath.Join(p, name+".sh"), []byte(s), 0o600)
		}
	}
	if !strings.Contains(standbyUseScript([]string{"tp-a.service", "tp-b.service"}), "us='tp-a.service tp-b.service'") {
		t.Error("the units aren't passed to the script")
	}
	// huge pages are only ever moved from always to madvise, and fwupd only stops on a VM
	if !strings.Contains(leanHost, `grep -q '\[always\]'`) || !strings.Contains(leanHost, "systemd-detect-virt -q") {
		t.Error("leanHost lost a guard")
	}
}
