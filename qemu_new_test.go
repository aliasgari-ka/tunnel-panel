package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The wrapper prefers the panel's qemu 10 next to the core and falls back to the distro's.
func TestQemuWrapper(t *testing.T) {
	w := qemuWrapper("/opt/tpk/tpk-agent", "tpk-agent")
	for _, want := range []string{"#!/bin/sh\n", "Q='/opt/tpk/qemu-x86_64'\n", `[ -x "$Q" ] || Q=$(command -v qemu-x86_64-static || command -v qemu-x86_64)`, `exec "$Q" '/opt/tpk/tpk-agent'.amd64 "$@"`, qemuNew.Mark} {
		if !strings.Contains(w, want) {
			t.Errorf("wrapper lacks %q:\n%s", want, w)
		}
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	// run it with a fake core dir: the local qemu wins when it is executable
	d := t.TempDir()
	dest := filepath.ToSlash(filepath.Join(d, "core"))
	q := filepath.Join(d, "qemu-x86_64")
	_ = os.WriteFile(q, []byte("#!/bin/sh\necho local \"$@\"\n"), 0o755)
	_ = os.WriteFile(filepath.Join(d, "core.amd64"), nil, 0o755)
	out, err := exec.Command(sh, "-c", qemuWrapper(dest, "x"), "w", "tunnel", "c.json").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "local "+dest+".amd64 tunnel c.json" {
		t.Errorf("wrapper ran %q (%v)", out, err)
	}
}

// The install script is pinned (both hashes, the version's file), arm64 only, never fails
// the apply and backs off after a failed download.
func TestQemuNewScript(t *testing.T) {
	s := qemuNewScript("/opt/tpk/qemu-x86_64")
	for _, want := range []string{qemuNew.DebSHA, qemuNew.BinSHA, "qemu-user_10.0.13+ds-0+deb13u1_arm64.deb", `[ "$(uname -m)" = aarch64 ] || exit 0`, ".unreachable", "21600", `mv -f "$Q.new" "$Q"`} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "exit 1") {
		t.Error("the qemu 10 install must never fail the apply")
	}
	if len(qemuNew.DebSHA) != 64 || len(qemuNew.BinSHA) != 64 || len(qemuNew.URLs) < 2 {
		t.Error("bad pin")
	}
}
