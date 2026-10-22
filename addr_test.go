package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeHost struct{ out string }

func (f fakeHost) Label() string { return "IR" }
func (f fakeHost) Run(context.Context, string, func(string)) (string, error) {
	return f.out, nil
}
func (f fakeHost) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestDetectAddrs(t *testing.T) {
	cases := []struct{ out, v4, v6 string }{
		{"V4=185.10.20.30\nV6=2a01:4f8:1:2::5\n", "185.10.20.30", "2a01:4f8:1:2::5"},
		{"V4=10.0.0.5\nV6=\nPUB4=5.6.7.8\n", "5.6.7.8", ""},
		{"V4=10.0.0.5\nV6=fd42:1::1\nPUB4=\n", "", ""},
		{"V4=100.70.1.1\nV6=fe80::1\nPUB4=garbage\n", "", ""},
	}
	for _, c := range cases {
		v4, v6 := detectAddrs(context.Background(), fakeHost{c.out})
		if v4 != c.v4 || v6 != c.v6 {
			t.Errorf("%q: got %q %q, want %q %q", c.out, v4, v6, c.v4, c.v6)
		}
	}
}

func TestWithTail(t *testing.T) {
	out := "Oct 22 10:00:00 h backhaul[12]: FATAL bad port 0\nunit tp-x.service: failed\n"
	err := withTail(errString("Process exited with status 1"), out)
	if err == nil || err.Error() != "Process exited with status 1 — FATAL bad port 0" {
		t.Fatalf("got %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRankBench(t *testing.T) {
	rs := []BenchResult{
		{Method: "a", OK: true, DownMbps: 20, UpMbps: 10, Mbps: 15, RTTms: 110},
		{Method: "b", OK: false, Error: "x"},
		{Method: "s", Skipped: true},
		{Method: "c", OK: true, DownMbps: 200, UpMbps: 80, Mbps: 140, RTTms: 115},
	}
	rankBench(rs)
	if rs[0].Method != "c" || !rs[0].Recommended || rs[1].Method != "a" || rs[0].Score <= rs[1].Score {
		t.Fatalf("bad ranking: %+v", rs)
	}
	if rs[2].Method != "b" || rs[3].Method != "s" {
		t.Fatalf("failed should precede skipped: %+v", rs)
	}
}

func TestAcctScriptAndRates(t *testing.T) {
	tn := &Tunnel{ID: "abc123", Ports: "443,8080=80,2000-2010,[::1]:8443", Index: 3}
	sc := acctScript(tn)
	for _, want := range []string{"--dport 443", "--sport 80", "--dport 2000:2010", "--dport 8443", `echo "T abc123 $d $u"`} {
		if want == "--sport 80" {
			continue // listen side is 8080; the rule matches the Iran-facing port
		}
		if !strings.Contains(sc, want) {
			t.Errorf("script lacks %q:\n%s", want, sc)
		}
	}
	if !strings.Contains(sc, "--sport 8080") {
		t.Errorf("expected Iran-facing port 8080 counted")
	}
	tm := newTrafficMon()
	now := time.Now()
	s := tm.stat(tm.tunnels, "x")
	tm.update(s, "ports", "1000", "500", now)
	tm.update(s, "ports", "1251000", "125500", now.Add(2*time.Second))
	if s.Down != 5e6 || s.Up != 5e5 || len(s.Hist) != 1 {
		t.Fatalf("rates: %+v", s)
	}
	tm.update(s, "ports", "10", "10", now.Add(4*time.Second)) // counter reset
	if s.Down != 0 || s.TotalDown != 10 {
		t.Fatalf("reset: %+v", s)
	}
	tm.update(s, "ports", "-", "-", now.Add(6*time.Second))
	if s.Error == "" {
		t.Fatal("expected error for missing counters")
	}
}

func TestWithProbePort(t *testing.T) {
	tn := &Tunnel{Ports: "443", Index: 2, Options: map[string]map[string]string{}}
	if got := withProbePort(methodByID["backhaul"], tn); got != "443,40010" {
		t.Fatalf("backhaul: %q", got)
	}
	if got := withProbePort(methodByID["gre"], tn); got != "443" {
		t.Fatalf("gre: %q", got)
	}
	tn.Ports = "40010"
	if got := withProbePort(methodByID["frp"], tn); got != "40010" {
		t.Fatalf("dedupe: %q", got)
	}
}

func TestPMTU(t *testing.T) {
	limit := 1372 // largest IP packet that passes
	run := func(_ Host, sh string) string {
		var s int
		if i := strings.Index(sh, "-s "); i >= 0 {
			fmt.Sscanf(sh[i+3:], "%d", &s)
		}
		if s+28 <= limit {
			return "y"
		}
		return ""
	}
	got := pmtu(run, nil, "10.0.0.2", 1400)
	if got > limit || got < limit-8 {
		t.Fatalf("pmtu = %d, want ~%d", got, limit)
	}
	if pmtu(run, nil, "x", 1300) != 1300 {
		t.Fatal("full size should pass")
	}
	if fp := firstPorts("443,2000-2010=3000-3010,127.0.0.1:8443=9000", 5); len(fp) != 3 || fp[1].listen != "2000" || fp[1].dst != "3000" || fp[2].listen != "8443" || fp[2].dst != "9000" {
		t.Fatalf("firstPorts: %+v", fp)
	}
}

func TestGoldenKeyAndUnitHooks(t *testing.T) {
	tn := &Tunnel{ID: "g1", Name: "g", Family: "v4", Ports: "443", Index: 5, Options: map[string]map[string]string{}}
	ir, kh, err := buildPlans(methodByID["golden"], tn, &Server{IPv4: "192.0.2.1"}, &Server{IPv4: "192.0.2.2"}, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []SidePlan{ir, kh} {
		if k := p.Files[tunnelDir(tn)+"/golden.key"]; len(k.Content) != 32 {
			t.Fatalf("golden key is %d bytes", len(k.Content))
		}
		u := renderUnit(p.Unit)
		if !strings.Contains(u, "ExecStartPre=-/etc/tunnel-panel/t/g1/fw-in-up.sh") || !strings.Contains(u, "ExecStopPost=-/etc/tunnel-panel/t/g1/fw-in-down.sh") {
			t.Fatalf("unit lacks firewall hooks:\n%s", u)
		}
	}
	if !bytes.Contains(ir.Files[tunnelDir(tn)+"/fw-in-up.sh"].Content, []byte("-s 192.0.2.2 -j ACCEPT")) ||
		!bytes.Contains(ir.Files[tunnelDir(tn)+"/fw-in-up.sh"].Content, []byte("--dport 443 -j ACCEPT")) ||
		bytes.Contains(kh.Files[tunnelDir(tn)+"/fw-in-up.sh"].Content, []byte("--dport 443")) {
		t.Fatal("inbound rules wrong")
	}
}

func TestJobCancel(t *testing.T) {
	js := newJobs()
	j, _ := js.start("t1", "apply")
	ctx, cancel := j.context(time.Minute)
	defer cancel()
	if _, err := js.start("t1", "apply"); err == nil {
		t.Fatal("second job should be refused while one runs")
	}
	if js.running("t1") != j.ID {
		t.Fatal("running() wrong")
	}
	js.cancel(j.ID)
	if ctx.Err() == nil || js.running("t1") != "" {
		t.Fatal("cancel did not end the context / free the tunnel")
	}
	j.finish("error")
	if j.snapshot().Status != "cancelled" {
		t.Fatal("status should stay cancelled")
	}
	if _, err := js.start("t1", "apply"); err != nil {
		t.Fatal("tunnel should be free after cancel")
	}
	js.done(j) // the old goroutine's deferred done must not free the new job
	if js.running("t1") == "" {
		t.Fatal("old job's done() released the new job")
	}
}

func TestMonitorStep(t *testing.T) {
	h := &tunnelHealth{}
	t0 := time.Now()
	seq := []struct {
		reason, want string
	}{{"", ""}, {"link down", ""}, {"", ""}, {"link down", ""}, {"link down", "down"}, {"link down", ""}, {"", "up"}, {"", ""}}
	for i, s := range seq {
		if got := h.step(s.reason, t0.Add(time.Duration(i)*time.Minute)); got != s.want {
			t.Fatalf("step %d (%q): got %q want %q", i, s.reason, got, s.want)
		}
	}
	if h.lastOutage != 3*time.Minute {
		t.Fatalf("outage = %v", h.lastOutage)
	}
}
