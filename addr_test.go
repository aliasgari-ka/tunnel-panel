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

func TestFailoverCandidates(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "i", IPv4: "192.0.2.1", IPv6: "2001:db8::1"}, {ID: "k", IPv4: "192.0.2.2", IPv6: "2001:db8::2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "x", ServerID: "i", ForeignID: "k", Family: "v6", Active: "gre", Ports: "443", Index: 3}}
		s.BenchHistory = []BenchRecord{{IranID: "i", ForeignID: "k", Family: "v4", Results: []BenchResult{
			{Method: "frp", OK: true, Score: 90}, {Method: "bp_reverse", OK: true, Score: 150}, {Method: "golden", OK: false}}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	c := a.failoverCandidates(st.Tunnel("x"))
	if len(c) < 4 || c[0] != (pathChoice{"bp_reverse", "v4"}) || c[1] != (pathChoice{"frp", "v4"}) {
		t.Fatalf("bench winners must come first: %v", c)
	}
	if c[2].family != "v4" {
		t.Fatalf("the other family (v4) should come next after bench results: %v", c[2])
	}
	for _, p := range c {
		if p.method == "gre" && p.family == "v6" {
			t.Fatal("current path must be excluded")
		}
		if p.method == "spoof" || (p.method == "golden" && p.family == "v6") || (p.method == "direct6" && p.family == "v4") {
			t.Fatalf("impossible candidate %v", p)
		}
	}
	// a v4-only pair never gets v6 candidates
	_ = st.Update(func(s *State) error { s.Servers[0].IPv6 = ""; return nil })
	for _, p := range a.failoverCandidates(st.Tunnel("x")) {
		if p.family == "v6" {
			t.Fatalf("v6 candidate without IPv6 on Iran: %v", p)
		}
	}
}

func TestNormIP(t *testing.T) {
	cases := []struct {
		in   string
		v6   bool
		want string
		bad  bool
	}{
		{" 2A01:4F8:0:1::0001/64 ", true, "2a01:4f8:0:1::1", false},
		{"[2001:db8::5]", true, "2001:db8::5", false},
		{"fe80::1%eth0", true, "", true},
		{"185.1.2.3", true, "", true},
		{"185.1.2.3/32", false, "185.1.2.3", false},
		{"2001:db8::1", false, "", true},
		{"", true, "", false},
		{"not-an-ip", false, "", true},
	}
	for _, c := range cases {
		got, err := normIP(c.in, c.v6)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("normIP(%q, v6=%v) = %q, %v", c.in, c.v6, got, err)
		}
	}
}

func TestPortClash(t *testing.T) {
	st := &State{Tunnels: []*Tunnel{
		{ID: "a", Name: "usa", ServerID: "ir", ForeignID: "k1", Ports: "443,2000-2010", Index: 4, Active: "gre"},
		{ID: "b", Name: "rev", ServerID: "ir", ForeignID: "k2", Ports: "9000", Index: 6, Active: "backhaul",
			Options: map[string]map[string]string{"backhaul": {"tunnel_port": "8443"}}},
		{ID: "c", Name: "other-iran", ServerID: "ir2", ForeignID: "k1", Ports: "443", Index: 7, Active: "gre"},
	}}
	cases := []struct {
		t    *Tunnel
		want string // substring of the error, "" = no clash
	}{
		{&Tunnel{ID: "x", ServerID: "ir", Ports: "443", Index: 9, Selected: "gre"}, `"usa"`},      // same forwarded port
		{&Tunnel{ID: "x", ServerID: "ir", Ports: "8443=443", Index: 9, Selected: "gre"}, `"rev"`}, // hits rev's tunnel port
		{&Tunnel{ID: "x", ServerID: "ir", Ports: "2005", Index: 9, Selected: "gre"}, `"usa"`},     // inside a range
		{&Tunnel{ID: "x", ServerID: "ir", Ports: "444=443", Index: 9, Selected: "gre"}, ""},       // mapped: fine
		{&Tunnel{ID: "x", ServerID: "ir2b", Ports: "443", Index: 9, Selected: "gre"}, ""},         // another Iran server
		{&Tunnel{ID: "a", ServerID: "ir", Ports: "443", Index: 4, Selected: "gre"}, ""},           // itself
		{&Tunnel{ID: "x", ServerID: "ir", Ports: "7000", Index: 9, Selected: "backhaul",
			Options: map[string]map[string]string{"backhaul": {"tunnel_port": "443"}}}, `"usa"`}, // reverse port on a forwarded one
	}
	for i, c := range cases {
		err := portClash(st, c.t, "")
		switch {
		case c.want == "" && err != nil:
			t.Errorf("case %d: unexpected clash: %v", i, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("case %d: want clash with %s, got %v", i, c.want, err)
		}
	}
}

func TestFixIPv6(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", IPv6: "a05:9080:0:308:216:3eff:fe19:31d8"}} // first digit lost
		return nil
	})
	a := &App{store: st}
	h := fakeHost{"2a05:9080:0:308:216:3eff:fe19:31d8\nfd42:5::1\nV4=\nV6=2a05:9080:0:308:216:3eff:fe19:31d8\n"}
	if n := a.fixIPv6(context.Background(), h, "ir", "a05:9080:0:308:216:3eff:fe19:31d8"); n == "" {
		t.Fatal("not corrected")
	}
	if got := st.Server("ir").IPv6; got != "2a05:9080:0:308:216:3eff:fe19:31d8" {
		t.Fatalf("IPv6 now %q", got)
	}
	if n := a.fixIPv6(context.Background(), h, "ir", "2a05:9080:0:308:216:3eff:fe19:31d8"); n != "" {
		t.Fatalf("a correct address was changed: %s", n)
	}
}
