package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The flush scripts parse, and do what they say for both kinds of path.
func TestHSFlushScripts(t *testing.T) {
	tn := &Tunnel{ID: "x1", Name: "x", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443,8443", Index: 3,
		Options: map[string]map[string]string{}, Secrets: map[string]string{}}
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.1"}
	l3 := hsFlush(tn, HSPath{Method: "gre", Family: "v4", Index: 3}, srv, fsrv, Settings{})
	fw := hsFlush(tn, HSPath{Method: "backhaul", Family: "v4", Index: 7}, srv, fsrv, Settings{})
	down := hsSelectDown(tn)
	for name, sc := range map[string]string{"l3": l3, "fw": fw, "down": down} {
		p := filepath.Join(t.TempDir(), name+".sh")
		_ = os.WriteFile(p, []byte(sc), 0o755)
		if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s\n%s", name, err, out, sc)
		}
	}
	if !strings.Contains(l3, "--ctreplsrc 10.10.3.2") || !strings.Contains(l3, "conntrack -D --reply-src 10.10.3.2") {
		t.Errorf("L3 flush:\n%s", l3)
	}
	if !strings.Contains(fw, "ss -K -t state established '( sport = :50140 or sport = :50141 )'") {
		t.Errorf("forwarder flush:\n%s", fw)
	}
	if !strings.Contains(down, "tp-hsflush-x1") {
		t.Errorf("selector down doesn't remove the reset rules:\n%s", down)
	}
}
