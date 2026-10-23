package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The ipx emulation check (box64 for the amd64 Premium core on ARM) is valid shell and
// fetches the panel release's box64 through the configured download prefix.
func TestIPXEmuCheckScript(t *testing.T) {
	if ipxEmuCheck("tcpmux", "") != "" {
		t.Error("non-ipx modes need no emulator check")
	}
	s := ipxEmuCheck("ipx", "https://ghproxy.example/")
	if !strings.Contains(s, "'https://ghproxy.example/"+box64Release+"'") || !strings.Contains(s, ".sha256'") {
		t.Errorf("box64 download URL not in the script:\n%s", s)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader("set -e\n" + s)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v %s", err, out)
	}
}
