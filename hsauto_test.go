package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Repair renews a switcher by this line: it must be the script's own.
func TestHSSwitcherVersion(t *testing.T) {
	if !strings.HasPrefix(hsSwitcherVersion, "# tp-switcher ") {
		t.Fatalf("version line %q", hsSwitcherVersion)
	}
	if !strings.Contains(hsSwitcher, "\n"+hsSwitcherVersion+"\n") {
		t.Fatalf("%q is not a line of the switcher", hsSwitcherVersion)
	}
}
