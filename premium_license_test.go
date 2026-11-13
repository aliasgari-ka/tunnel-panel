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
		// up with no verdict: done at once instead of after 15 s (the v2 core never logs one)
		{"[INFO] control channel established successfully", "core up: control channel established", true},
		{"13-Nov 00:09:15 [INFO] starting 2 workers with channel size 10000", "core up: starting 2 workers", true},
		{"[INFO] ♥️ Health service connected to 10.10.57.1:40228", "core up: ♥️ Health service connected", true},
		{"[INFO] Applying kernel tuning profile: BALANCED", "no license verdict", true},
		// a bad verdict next to the start line still fails the apply
		{"[INFO] starting 2 workers\n[ERROR] License IP mismatch", "license problem: License IP mismatch", false},
		// bad verdicts that used to pass with a note blaming the server's DNS (bug hunt 2026-11-12)
		{"[ERROR] License rejected", "license problem: License rejected", false},
		{"[ERROR] License status is unknown", "license problem: License status is unknown", false},
		{"[ERROR] Unknown license status", "license problem: Unknown license status", false},
		{"[ERROR] Invalid license or IP address", "license problem: Invalid license or IP address", false},
		{"[ERROR] License server returned failure", "license server is failing", false},
		{"[ERROR] License verification API failed", "license server is failing", false},
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
