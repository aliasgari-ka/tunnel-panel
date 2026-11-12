package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The batched writer through a real bash (LocalHost): only changed files written, one
// summary line, the script after the files, failures told apart.
func TestRunWithFilesLocal(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	if out, err := exec.Command("bash", "-c", "command -v base64 && command -v sha256sum").CombinedOutput(); err != nil {
		t.Skipf("no base64/sha256sum: %s", out)
	}
	dir := filepath.ToSlash(t.TempDir())
	bin := []byte{0, 1, 2, 0xff, '\n', '\'', '"', '$', '`', '\\'}
	files := map[string]FileSpec{
		dir + "/a/b/conf":   {Content: []byte("P=1\nTP.EOF\n'quoted' $HOME `x`\n"), Mode: 0o644},
		dir + "/switch.sh":  {Content: []byte("#!/bin/bash\necho hi\n"), Mode: 0o755},
		dir + "/bin":        {Content: bin, Mode: 0o600},
		dir + "/empty":      {Content: nil, Mode: 0o644},
		dir + "/with space": {Content: bytes.Repeat([]byte("x"), 1000), Mode: 0o644},
	}
	run := func(script string) ([]string, string, error) {
		var mu sync.Mutex
		var lines []string
		out, err := runWithFiles(context.Background(), LocalHost{}, files, script, func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})
		return lines, out, err
	}
	lines, out, err := run("echo setup-ran")
	if err != nil {
		t.Fatalf("first run: %v (%s)", err, out)
	}
	if strings.Contains(out, batchMark) {
		t.Errorf("marker lines left in the output: %q", out)
	}
	j := strings.Join(lines, "\n")
	if !strings.Contains(j, "setup-ran") || !strings.Contains(j, "wrote 5 changed file(s) of 5") {
		t.Errorf("log: %q", j)
	}
	for p, f := range files {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, f.Content) {
			t.Errorf("%s: %q, %v; want %q", p, got, err, f.Content)
		}
	}
	lines, _, err = run("")
	if err != nil || !strings.Contains(strings.Join(lines, "\n"), "files up to date (5, none changed)") {
		t.Errorf("second run: %v %q", err, lines)
	}
	files[dir+"/switch.sh"] = FileSpec{Content: []byte("#!/bin/bash\necho new\n"), Mode: 0o755}
	lines, _, err = run("exit 0\necho never")
	if j := strings.Join(lines, "\n"); err != nil || !strings.Contains(j, "wrote 1 changed file(s) of 5 (switch.sh)") || strings.Contains(j, "never") {
		t.Errorf("one changed: %v %q", err, lines)
	}
	// the script failing is not a write failure
	_, _, err = run("echo boom; exit 3")
	var we *fileWriteError
	if err == nil || errors.As(err, &we) {
		t.Errorf("script failure: %v", err)
	}
	// a write that can't happen (its directory is a file) fails as a write, before the script
	files[dir+"/bin/x"] = FileSpec{Content: []byte("x"), Mode: 0o644}
	lines, _, err = run("echo should-not-run")
	if err == nil || !errors.As(err, &we) || !strings.Contains(err.Error(), "bin/x") || strings.Contains(strings.Join(lines, "\n"), "should-not-run") {
		t.Errorf("write failure: %v %q", err, lines)
	}
}

// batchFake is a host whose Run only records scripts; nob64 makes it answer as a host
// without base64 would.
type batchFake struct {
	mu     sync.Mutex
	runs   []string
	writes []string
	nob64  bool
}

func (h *batchFake) Label() string     { return "IR" }
func (h *batchFake) batchWrites() bool { return true }
func (h *batchFake) Run(_ context.Context, s string, log func(string)) (string, error) {
	h.mu.Lock()
	h.runs = append(h.runs, s)
	h.mu.Unlock()
	if h.nob64 && strings.Contains(s, "base64 -d") {
		log(batchMark + "NOB64")
		return batchMark + "NOB64\n", errors.New("exit status 72")
	}
	out := ""
	if strings.Contains(s, "echo "+batchMark+"OK") {
		out = batchMark + "OK\n"
	}
	return out + "ran\n", nil
}
func (h *batchFake) WriteFile(p string, _ []byte, _ os.FileMode) error {
	h.mu.Lock()
	h.writes = append(h.writes, p)
	h.mu.Unlock()
	return nil
}

func TestRunWithFilesOneRoundTrip(t *testing.T) {
	files := map[string]FileSpec{}
	for _, n := range []string{"switch.sh", "conf", "up-0.sh", "up-1.sh", "flush-0.sh", "flush-1.sh", "targets"} {
		files["/etc/tunnel-panel/t/x/"+n] = FileSpec{Content: []byte(n), Mode: 0o644}
	}
	big := bytes.Repeat([]byte("b"), batchMaxFile+1)
	files["/usr/local/bin/big"] = FileSpec{Content: big, Mode: 0o755}
	h := &batchFake{}
	if _, err := runWithFiles(context.Background(), h, files, "set -e\necho setup", func(string) {}); err != nil {
		t.Fatal(err)
	}
	if len(h.runs) != 1 || !strings.HasSuffix(h.runs[0], "set -e\necho setup") {
		t.Fatalf("want one run ending in the setup, got %d", len(h.runs))
	}
	if len(h.writes) != 1 || h.writes[0] != "/usr/local/bin/big" {
		t.Errorf("only the big file goes alone: %v", h.writes)
	}
	// no base64 on the host: every file one by one, then the setup on its own
	h = &batchFake{nob64: true}
	if _, err := runWithFiles(context.Background(), h, files, "echo setup", func(string) {}); err != nil {
		t.Fatal(err)
	}
	if len(h.writes) != len(files) || len(h.runs) != 2 || h.runs[1] != "echo setup" {
		t.Errorf("fallback: %d writes, runs %q", len(h.writes), h.runs)
	}
}

// A deploy is two round trips (files + setup, unit + restart; one more for the CPU and
// installed sums when it has binaries), however many files; it was one per file + 3.
func TestDeploySwitcherRoundTrips(t *testing.T) {
	tn := &Tunnel{ID: "rt", Name: "rt", Family: "v4", Ports: "443", Index: 7, Secrets: map[string]string{}}
	p := SidePlan{Files: map[string]FileSpec{}, Setup: "true", Unit: Unit{Desc: "x", ExecStart: "/bin/true"}}
	for i := 0; i < 20; i++ {
		p.Files["/etc/tunnel-panel/t/rt/f"+string(rune('a'+i))] = FileSpec{Content: []byte("x"), Mode: 0o644}
	}
	h := &batchFake{}
	a := &App{}
	j := &Job{}
	if err := a.deploy(context.Background(), j, "IR", labeled{h, "IR"}, tn, p); err != nil {
		t.Fatal(err)
	}
	if len(h.runs) != 2 || len(h.writes) != 0 {
		t.Errorf("want 2 runs and no single writes (no artifacts in this plan), got %d runs, %d writes", len(h.runs), len(h.writes))
	}
	if !canBatch(labeled{LocalHost{}, "KH"}) || canBatch(labeled{&lcHost{}, "KH"}) {
		t.Error("labeled must pass on whether its host batches")
	}
}
