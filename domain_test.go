package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Domains are checked and normalised; the unit's --tls (and --addr) are rewritten in place.
func TestPanelDomains(t *testing.T) {
	if d, err := normDomains(" TunnelPanel.Example.co , 1-2-3-4.sslip.io "); err != nil || d != "tunnelpanel.example.co,1-2-3-4.sslip.io" {
		t.Errorf("normDomains: %q %v", d, err)
	}
	for _, bad := range []string{"", "not a domain", "x;rm -rf /", "a..b.com", "http://a.com"} {
		if _, err := normDomains(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	panelUnit = filepath.Join(t.TempDir(), "tunnel-panel.service")
	unit := "[Service]\nExecStart=/usr/local/bin/tunnel-panel --addr 0.0.0.0:8088 --agent-addr 0.0.0.0:7020 --data /etc/tunnel-panel --tls \"152-53-86-103.sslip.io\"\nRestart=always\n"
	_ = os.WriteFile(panelUnit, []byte(unit), 0o644)
	_ = setUnitDomains("tunnelpanel.example.co,152-53-86-103.sslip.io") // (daemon-reload fails off a real host)
	b, _ := os.ReadFile(panelUnit)
	if !strings.Contains(string(b), `--tls "tunnelpanel.example.co,152-53-86-103.sslip.io"`) || !strings.Contains(string(b), "--addr 0.0.0.0:443") || strings.Count(string(b), "--tls") != 1 {
		t.Errorf("unit after the change:\n%s", b)
	}
	// a unit without --tls gets one
	_ = os.WriteFile(panelUnit, []byte("[Service]\nExecStart=/usr/local/bin/tunnel-panel --addr 0.0.0.0:8088\n"), 0o644)
	_ = setUnitDomains("panel.example.org")
	b, _ = os.ReadFile(panelUnit)
	if !strings.Contains(string(b), `ExecStart=/usr/local/bin/tunnel-panel --addr 0.0.0.0:443 --tls "panel.example.org"`) {
		t.Errorf("unit without --tls:\n%s", b)
	}
	if got := splitDomains("a.com"); len(got) != 1 || got[0] != "a.com" {
		t.Errorf("splitDomains: %v", got)
	}
}
