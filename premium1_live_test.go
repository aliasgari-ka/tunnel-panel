package main

// Backhaul Premium v1 with the panel's own configs and the real v1.0.2 arm64 core, both
// ends on this host under qemu-aarch64 (as on an amd64 server). Needs qemu-aarch64-static
// and internet (the core checks its licence online). Run with TP_PREMIUM1_LIVE=1.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPremiumV1Live(t *testing.T) {
	if os.Getenv("TP_PREMIUM1_LIVE") == "" {
		t.Skip("set TP_PREMIUM1_LIVE=1 (qemu-aarch64-static, internet)")
	}
	core, err := helperBytes("backhaul_premium_v1", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bp1")
	_ = os.WriteFile(bin, core, 0o755)
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 1<<20))) }))
	defer svc.Close()
	svcPort := svc.Listener.Addr().String()[strings.LastIndex(svc.Listener.Addr().String(), ":")+1:]
	for _, tr := range []string{"tcpmux", "tcp", "wsmux"} {
		ir := &Server{ID: "ir", IPv4: "127.0.0.1"}
		kh := &Server{ID: "kh", IPv4: "127.0.0.1", Role: "foreign"}
		tn := &Tunnel{ID: "p1" + tr, Name: "v1", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "47141=" + svcPort, Index: 61,
			Options: map[string]map[string]string{"premium1": {"transport": tr}}, Secrets: map[string]string{}}
		irP, khP, err := buildPlans(methodPremiumV1, tn, ir, kh, Settings{})
		if err != nil {
			t.Fatal(err)
		}
		cfg := tunnelDir(tn) + "/backhaul.toml"
		irC, khC := filepath.Join(dir, tr+"-ir.toml"), filepath.Join(dir, tr+"-kh.toml")
		_ = os.WriteFile(irC, irP.Files[cfg].Content, 0o600)
		_ = os.WriteFile(khC, khP.Files[cfg].Content, 0o600)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		s := exec.CommandContext(ctx, "qemu-aarch64-static", bin, "-c", irC)
		c := exec.CommandContext(ctx, "qemu-aarch64-static", bin, "-c", khC)
		var slog, clog strings.Builder
		s.Stdout, s.Stderr, c.Stdout, c.Stderr = &slog, &slog, &clog, &clog
		_ = s.Start()
		time.Sleep(2 * time.Second)
		_ = c.Start()
		got := 0
		for k := 0; k < 15 && got != 1<<20; k++ {
			time.Sleep(time.Second)
			if resp, err := http.Get("http://127.0.0.1:47141/"); err == nil {
				b := make([]byte, 2<<20)
				n, _ := ioReadFull(resp.Body, b)
				resp.Body.Close()
				got = n
			}
		}
		cancel()
		_ = s.Wait()
		_ = c.Wait()
		if got == 1<<20 {
			t.Logf("✓ Premium v1 %s: 1 MB through the tunnel (panel configs, v1.0.2 arm64 core under qemu-aarch64)", tr)
		} else {
			t.Errorf("Premium v1 %s: got %d bytes\nserver: %s\nclient: %s", tr, got, tail(slog.String()), tail(clog.String()))
		}
	}
}

func ioReadFull(r interface{ Read([]byte) (int, error) }, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func tail(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > 6 {
		l = l[len(l)-6:]
	}
	return strings.Join(l, "\n")
}
