package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Dropping paths keeps the users on their path, whichever place it moves to.
func TestHSActiveRemap(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	ps := func(keys ...string) (out []HSPath) {
		for _, k := range keys {
			m, f, _ := strings.Cut(k, "|")
			out = append(out, HSPath{Method: m, Family: f})
		}
		return out
	}
	before := ps("gre|v4", "bp_reverse|v4", "ipsec6|v6", "icmp|v4", "paqet|v4", "paqet|v6")
	after := ps("gre|v4", "bp_reverse|v4", "ipsec6|v6", "icmp|v4", "paqet|v6")
	for _, c := range []struct{ was, want string }{
		{"5 1793215901", "4 1793215901"}, // Paqet v6 moves up a place
		{"1 1793215901", "1 1793215901"}, // before the dropped path: unchanged
		{"4 1793215901", ""},             // the users' path itself was dropped: the first path
	} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "active"), []byte(c.was+"\n"), 0o644)
		if out, err := exec.Command(bash, "-c", "set -e\n"+hsActiveRemap(filepath.ToSlash(dir), before, after)).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		b, _ := os.ReadFile(filepath.Join(dir, "active"))
		if got := strings.TrimSpace(string(b)); got != c.want {
			t.Errorf("active %q → %q, want %q", c.was, got, c.want)
		}
	}
	// no active file yet: nothing to do, and no error under set -e
	if out, err := exec.Command(bash, "-c", "set -e\n"+hsActiveRemap(filepath.ToSlash(t.TempDir()), before, after)).CombinedOutput(); err != nil {
		t.Fatalf("no active file: %v: %s", err, out)
	}
}

// Uploads of one file at the same moment (parallel jobs on one server) all succeed.
func TestUploadSideBySide(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	path := filepath.ToSlash(filepath.Join(t.TempDir(), "lib", "tp-probe"))
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		go func() {
			c := exec.Command(sh, "-c", uploadCmd(path, 0o755))
			c.Stdin = strings.NewReader(strings.Repeat("x", 4<<20))
			if out, err := c.CombinedOutput(); err != nil {
				errs <- fmt.Errorf("%v: %s", err, out)
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < 6; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if b, err := os.ReadFile(path); err != nil || len(b) != 4<<20 {
		t.Fatalf("stored %d bytes, %v", len(b), err)
	}
	if left, _ := filepath.Glob(path + ".tp-tmp*"); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}
