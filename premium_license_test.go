package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The license check reads the core's verdict from its journal (a fake journalctl here).
func TestPremiumLicenseCheck(t *testing.T) {
	cases := []struct {
		log, want string
		ok        bool
	}{
		{"23-Oct 14:36:58 [INFO] License is valid", "license: valid", true},
		{"\x1b[90m23-Oct\x1b[0m [\x1b[31mERROR\x1b[0m] License IP mismatch", "license problem: License IP mismatch", false},
		{"[ERROR] License has expired", "License has expired", false},
		{"[ERROR] License does not exist", "License does not exist", false},
		{"[INFO] control channel established successfully", "no license verdict", true},
	}
	for _, c := range cases {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/sh\nprintf '%s\\n' "+shq(c.log)+"\n"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho\n"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "sleep"), []byte("#!/bin/sh\n"), 0o755) // no real waiting
		cmd := exec.Command("bash", "-c", "UNIT=tp-x.service\n"+premiumLicenseCheck)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if (err == nil) != c.ok || !strings.Contains(string(out), c.want) {
			t.Errorf("log %q: ok=%v out=%q", c.log, err == nil, out)
		}
	}
}
