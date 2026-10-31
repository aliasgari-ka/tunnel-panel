package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeApt stands in for apt-get and dpkg: "apt-get check" fails until $D/fixed exists;
// MODE says what fixes it (dpkg = dpkg --configure -a, apt = apt-get -f install) and
// whether the dry run would remove a package (remove). Every call is logged.
const fakeApt = `#!/bin/bash
echo "$(basename $0) $*" >> $D/calls
case "$(basename $0) $1" in
  "apt-get check") [ -f $D/fixed ] && exit 0; echo "E: Unmet dependencies."; exit 100;;
  "dpkg --force-confold") [ "$MODE" = dpkg ] && touch $D/fixed; exit 0;;
  "apt-get -s")
    echo "Inst libstdc++6 [12-20220319] (12.3.0)"
    [ "$MODE" = remove ] && echo "Remv libfoo [1.0]"
    exit 0;;
  "apt-get -f") touch $D/fixed; exit 0;;
esac
exit 0
`

func TestAptFix(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	for _, c := range []struct {
		mode, wantOut, wantCall, notCall string
		ok                               bool
	}{
		{"healthy", "", "apt-get check", "apt-get -f", true},
		{"dpkg", "finished an interrupted package configuration", "dpkg --force-confold --configure -a", "apt-get -f", true},
		{"apt", "repairing it, nothing is removed: libstdc++6", "apt-get -f install -y", "", true},
		{"remove", "would remove: libfoo", "apt-get -s -f install", "apt-get -f", false},
	} {
		d := t.TempDir()
		for _, n := range []string{"apt-get", "dpkg"} {
			if err := os.WriteFile(filepath.Join(d, n), []byte(fakeApt), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if c.mode == "healthy" {
			os.WriteFile(filepath.Join(d, "fixed"), nil, 0o644)
		}
		dir := filepath.ToSlash(d)
		cmd := exec.Command(bash, "-c", "set -e\n"+aptFix+"if tp_apt_fix; then echo RC0; else echo RC1; fi")
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "D="+dir, "MODE="+c.mode)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.mode, err, out)
		}
		calls, _ := os.ReadFile(filepath.Join(d, "calls"))
		o, cl := string(out), string(calls)
		if !strings.Contains(o, c.wantOut) || strings.Contains(o, "RC0") != c.ok {
			t.Errorf("%s: output %q", c.mode, o)
		}
		if !strings.Contains(cl, c.wantCall) || (c.notCall != "" && strings.Contains(cl, c.notCall)) {
			t.Errorf("%s: calls %q", c.mode, cl)
		}
	}
	for name, s := range map[string]string{"prepScript": prepScript, "wgSetup": wgSetup} {
		if !strings.Contains(s, "tp_apt_fix || true") || !strings.Contains(s, "tp_apt_fix() {") {
			t.Errorf("%s doesn't repair apt before installing", name)
		}
	}
}
