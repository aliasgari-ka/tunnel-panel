package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The switcher script must at least parse (the auto logic is exercised in the netns e2e).
func TestHSSwitcherSyntax(t *testing.T) {
	p := filepath.Join(t.TempDir(), "switch.sh")
	_ = os.WriteFile(p, []byte(hsSwitcher), 0o755)
	if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}
