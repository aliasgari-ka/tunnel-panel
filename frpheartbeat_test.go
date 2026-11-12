package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Seen live 2026-11-12 on NL1's FRP path (and every other FRP path, all their runs): frps
// logged "heartbeat timeout" exactly 90 s after every login, dropped the control link and
// all its proxies, and frpc logged in again — 542 times in 14 h. frps had heartbeatTimeout
// = 90 while frpc, with tcpMux on (frp's default), sends no pings unless told to. Both ends
// now carry the same heartbeat numbers.
func TestFRPHeartbeatBothEnds(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	for _, proto := range []string{"tcp", "websocket", "quic", "kcp"} {
		tn := &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "443", Index: 3,
			Options: map[string]map[string]string{"frp": {"protocol": proto}}, Secrets: map[string]string{}}
		ir, kh, err := buildPlans(methodFRP, tn, srv, fsrv, Settings{})
		if err != nil {
			t.Fatal(err)
		}
		frps := string(ir.Files[tunnelDir(tn)+"/frps.toml"].Content)
		frpc := string(kh.Files[tunnelDir(tn)+"/frpc.toml"].Content)
		if !strings.Contains(frps, "transport.heartbeatTimeout = 90\n") {
			t.Errorf("%s: frps.toml lacks the heartbeat timeout:\n%s", proto, frps)
		}
		for _, want := range []string{"transport.heartbeatInterval = 30\n", "transport.heartbeatTimeout = 90\n"} {
			if !strings.Contains(frpc, want) {
				t.Errorf("%s: frpc.toml lacks %q:\n%s", proto, want, frpc)
			}
		}
		// the settings sit in frpc's top table, before the first [[proxies]]
		if i, j := strings.Index(frpc, "heartbeatInterval"), strings.Index(frpc, "[[proxies]]"); j < 0 || i > j {
			t.Errorf("%s: the heartbeat isn't in frpc's top table:\n%s", proto, frpc)
		}
	}
	if frpHeartbeatTimeout < 3*frpHeartbeatInterval {
		t.Errorf("timeout %d s must outlast three pings of %d s", frpHeartbeatTimeout, frpHeartbeatInterval)
	}
}

// a W line's error carries its time: a minutes-old error says how old it is, and an error
// long gone doesn't read as why the path is down now
func TestHSWhyTextAt(t *testing.T) {
	now := time.Unix(1794450000, 0)
	line := "2026-11-12 00:13:52.861 [W] [server/control.go:655] [11b0c795b4c543de] heartbeat timeout"
	at := func(d time.Duration) string { return "@" + strconv.FormatInt(now.Add(-d).Unix(), 10) }
	words := func(d time.Duration) []string { return append([]string{at(d)}, strings.Fields(line)...) }

	got := hsWhyTextAt("active", words(30*time.Second), now)
	if !strings.HasPrefix(got, "last error: 2026-11-12 00:13:52.861 [W]") || !strings.Contains(got, "stopped hearing each other") || !strings.Contains(got, "FRP's control link got no ping") {
		t.Errorf("fresh: %q", got)
	}
	if got := hsWhyTextAt("active", words(5*time.Minute), now); !strings.HasPrefix(got, "last error (5 min ago): 2026-11-12") {
		t.Errorf("5 min: %q", got)
	}
	if got := hsWhyTextAt("active", words(2*time.Hour+5*time.Minute), now); !strings.HasPrefix(got, "running on the Iran server, but no answer comes through it — its last error was 2 h 5 min ago: 2026-11-12") {
		t.Errorf("2 h: %q", got)
	}
	if got := hsWhyTextAt("failed", words(3*24*time.Hour), now); !strings.HasPrefix(got, "its core on the Iran server is failed — 2026-11-12") || !strings.HasSuffix(got, "(3 days ago)") {
		t.Errorf("failed: %q", got)
	}
	// no time (an older switcher script, or the line had none): as before
	if got, want := hsWhyTextAt("active", strings.Fields(line), now), hsWhyText("active", line); got != want {
		t.Errorf("no time: %q, want %q", got, want)
	}
	if got := hsWhyTextAt("none", nil, now); got != "" {
		t.Errorf("none: %q", got)
	}
}

// the script turns journalctl's short-unix lines into "@<time> <message>" (host and
// unit name cut off), so the page can tell how old the error is
func TestHSWhyScriptCarriesTime(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	log := `1794445922.816000 tunnel4-out-netherland frps[423251]: 2026-11-12 00:12:22.816 [I] [server/service.go:885] client login info
1794446032.861000 tunnel4-out-netherland frps[423251]: 2026-11-12 00:13:52.861 [W] [server/control.go:655] [11b0c795b4c543de] heartbeat timeout
1794446033.410000 tunnel4-out-netherland frps[423251]: 2026-11-12 00:13:53.410 [I] [server/service.go:885] client login info
`
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "status"), []byte("0 down 5 - - -\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "log"), []byte(log), 0o644)
	s := hsWhyScript(&Tunnel{ID: "x"}, []HSPath{{Method: "frp", Index: 95}})
	fake := `systemctl() { case "$1" in is-active) echo active;; show) echo inv1;; esac; return 0; }
journalctl() { cat log; }
`
	cmd := exec.Command("bash", "-c", fake+s)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	got := strings.TrimSpace(string(b))
	if want := "W 0 active @1794446032 2026-11-12 00:13:52.861 [W] [server/control.go:655] [11b0c795b4c543de] heartbeat timeout"; got != want {
		t.Fatalf("W line = %q, want %q", got, want)
	}
	f := strings.Fields(got)
	why := hsWhyTextAt(f[2], f[3:], time.Unix(1794446032, 0).Add(20*time.Minute))
	if !strings.HasPrefix(why, "running on the Iran server, but no answer comes through it — its last error was 20 min ago:") || strings.Contains(why, "netherland") {
		t.Errorf("why = %q", why)
	}
}
