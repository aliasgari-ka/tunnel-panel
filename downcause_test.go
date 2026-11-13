package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// The cause finder on real samples: each case is what a server's two scripts printed (log
// lines taken from the live cores, addresses swapped for documentation ones), and the cause
// the panel must name.

const dcNow = 1794481700 // 2026-11-12 11:08:20 UTC

func dcSides(ir, kh string) *dcInput {
	in := &dcInput{Method: "tpk", Family: "v4", Title: "TP Tunnel", Proto: "tunnel", ProbePort: 49036, FwdPort: 51079,
		Internal: [2]int{51060, 51079}, DownAt: dcNow - 600, Now: time.Unix(dcNow, 0),
		IR: newDCSide("Iran server", "سرور ایران", "iran2", "198.51.100.20"),
		KH: newDCSide("foreign server", "سرور خارج", "nl", "192.0.2.10")}
	dcParse(in.IR, ir)
	dcParse(in.KH, kh)
	return in
}

const dcActive = "P ActiveState=active\nP SubState=running\nP NRestarts=0\nSINCE 1794467477\nPING small 0\nPING big 0\nMEM 800000 2000000\nLOAD 0.20 2\n"

func dcCheck(t *testing.T, in *dcInput, code, side string, must ...string) *DownCause {
	t.Helper()
	c := dcClassify(in).cause("x|v4", in)
	if c.Code != code || c.Side != side {
		t.Fatalf("cause = %s/%s %q, want %s/%s\nevidence: %q", c.Code, c.Side, c.Text, code, side, c.Evidence)
	}
	all := c.Text + "\n" + c.TextFa + "\n" + strings.Join(c.Evidence, "\n")
	for _, m := range must {
		if !strings.Contains(all, m) {
			t.Errorf("%s: %q missing from\n%s", code, m, all)
		}
	}
	// no full address of either server, no secret
	for _, bad := range []string{"192.0.2.10", "198.51.100.20", "S3cr3t"} {
		if strings.Contains(all, bad) {
			t.Errorf("%s: %q leaked into\n%s", code, bad, all)
		}
	}
	if c.TextFa == "" || c.Text == "" {
		t.Errorf("%s: a language is missing", code)
	}
	return c
}

// 2026-11-12, tunnel "nl", TP Tunnel (v4): the foreign client lost its six sessions at
// 10:58:51 and never dialled again; Iran kept listening and nl reached its port in 103 ms.
// The client (an x86 build under qemu on ARM) also crashed 96 times that day.
func TestDownCauseStuckClient(t *testing.T) {
	ir := dcActive + `FWD 1
ST LISTEN *:40212 *:*
ST LISTEN *:40214 *:*
ST LISTEN *:51060 *:*
ST LISTEN *:51079 *:*
J @1794481131 2026/11/12 10:58:51 session down from 198.51.100.20:15544
J @1794481132 2026/11/12 10:58:52 session down from 198.51.100.20:15604
J @1794481585 2026/11/12 11:06:25 mem: heap 1 MB in use (1 MB held), stacks 0 MB, goroutines 7, from OS 12 MB, procs 1
PANICS 0
`
	kh := `P ActiveState=active
P SubState=running
P NRestarts=35
SINCE 1794480680
EMU
PROBE 1
PING small 0
PING big 0
J @1794480676 panic: runtime error: invalid memory address or nil pointer dereference
J @1794480676 [signal SIGSEGV: segmentation violation code=0x1 addr=0x7 pc=0x52372f]
J @1794480676 tp-bd3645802156x53.service: Main process exited, code=exited, status=2/INVALIDARGUMENT
J @1794480680 Started TP Tunnel nl · TP Tunnel (v4).
J @1794480680 2026/11/12 11:51:20 congestion control "bbr" not available (invalid argument); using the system default
J @1794480681 2026/11/12 11:51:21 session up to 192.0.2.10:40212
J @1794480980 2026/11/12 11:56:20 mem: heap 1 MB in use (1 MB held), stacks 0 MB, goroutines 45, from OS 12 MB, procs 1
PANICS 96
R 40212 0 103
R 40214 0 101
`
	c := dcCheck(t, dcSides(ir, kh), "stuck", "foreign",
		"foreign server (nl)", "192.0.x.x:40212", "103 ms", "the core is stuck", "crashed 96 times", "emulation", "گیر کرده")
	if !c.Restart {
		t.Error("a stuck core should offer a restart")
	}
}

// the same core in a crash loop: the unit restarts and its last panic says why
func TestDownCauseCrashLoop(t *testing.T) {
	kh := `P ActiveState=activating
P SubState=auto-restart
P NRestarts=12
J @1794481690 panic: runtime error: invalid memory address or nil pointer dereference
J @1794481690 tp-x.service: Main process exited, code=exited, status=2/INVALIDARGUMENT
`
	dcCheck(t, dcSides(dcActive+"FWD 1\n", kh), "core_down", "foreign", "keeps crashing and restarting (12 restarts)", "the core crashed", "panic: runtime error")
}

// 2026-11-11: the IG agent's REDIRECT of tcp 80/443 on the foreign servers took Backhaul
// Premium's handshake-less 443 carrier. With the panel's NOTRACK fix it no longer counts.
func TestDownCauseNATRedirect(t *testing.T) {
	ir := dcActive + "FWD 1\nST LISTEN 0.0.0.0:443 *:*\n"
	kh := dcActive + `PROBE 1
ST ESTAB 198.51.100.20:443 192.0.2.10:443
NAT -A OUTPUT -j IGPX
NAT -A IGPX -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 12346
R 443 0 90
`
	in := dcSides(ir, kh)
	in.Method, in.Title = "premium", "Backhaul Premium"
	dcCheck(t, in, "nat", "foreign", "catches TCP port 443", "chain IGPX: tcp 80,443 → REDIRECT 12346")

	in = dcSides(ir, kh+"RAW -A OUTPUT -d 192.0.2.10/32 -p tcp -m tcp --dport 443 -j CT --notrack\n")
	in.Method, in.Title = "premium", "Backhaul Premium"
	if c := dcClassify(in); c.code == "nat" {
		t.Fatal("a port the panel exempted with NOTRACK isn't caught by the REDIRECT")
	}
}

// FRP refusing the token is a cause on its own, whatever the connection looks like
func TestDownCauseFRPAuth(t *testing.T) {
	kh := dcActive + `PROBE 1
J @1794481650 2026-11-12 11:07:30.112 [W] [client/service.go:295] login to server failed: authorization failed token=S3cr3tTok
`
	in := dcSides(dcActive+"FWD 1\nST LISTEN *:7000 *:*\n", kh)
	in.Method, in.Title = "frp", "FRP"
	c := dcCheck(t, in, "auth", "foreign", "keys or tokens don't match", "authorization failed")
	if c.Restart {
		t.Error("a key mismatch is fixed by re-applying, not by a restart")
	}
}

// Backhaul's client can't open TCP to Iran: SYN-SENT, the log's i/o timeout, the connect
// test times out — the route (or Iran's filter) drops it
func TestDownCauseBlocked(t *testing.T) {
	ir := dcActive + "FWD 1\nST LISTEN *:3080 *:*\nUFW Status: inactive\n"
	kh := dcActive + `PROBE 1
ST SYN-SENT 198.51.100.20:51234 192.0.2.10:3080
J @1794481600 11-Nov 21:55:40 [ERROR] failed to dial tunnel server 192.0.2.10:3080: dial tcp 192.0.2.10:3080: i/o timeout
R 3080 124 4001
`
	in := dcSides(ir, kh)
	in.Method, in.Title = "backhaul", "Backhaul"
	dcCheck(t, in, "blocked", "route", "can't reach Iran server 192.0.x.x:3080", "times out", "timed out (4 s)", "i/o timeout")
}

func TestDownCausePortInUse(t *testing.T) {
	ir := `P ActiveState=failed
P SubState=failed
P NRestarts=5
FWD 0
J @1794481600 2026/11/12 11:06:40 listen tcp :40212: bind: address already in use
`
	dcCheck(t, dcSides(ir, dcActive+"PROBE 1\n"), "core_down", "iran", "has stopped (failed)", "already taken", "address already in use")
}

func TestDownCausePaqetLoss(t *testing.T) {
	kh := dcActive + "PROBE 1\nJ @1794481650 2026-11-11 22:29:37.434 [WARN] [ALERT] BOTTLENECK: packet_loss  82.4% retransmission (>5%). Causes: pcap buffer overflow\n"
	in := dcSides(dcActive+"FWD 1\n", kh)
	in.Method, in.Title = "paqet", "Paqet"
	dcCheck(t, in, "paqet_loss", "route", "82.4% retransmission")
}

// GRE: Iran's interface sends, the foreign one receives nothing
func TestDownCauseL3Drop(t *testing.T) {
	ir := dcActive + "IF up 100 200\nIF2 100 205\nINNER 100\n"
	kh := dcActive + "PROBE 1\nIF up 50 60\nIF2 50 60\n"
	in := dcSides(ir, kh)
	in.Method, in.Title, in.Proto, in.L3, in.IfaceKnown, in.FwdPort = "gre", "GRE", "GRE", true, true, 0
	dcCheck(t, in, "l3_drop_out", "route", "GRE packets from Iran", "sent 5")
	in = dcSides(dcActive+"IF missing\n", kh)
	in.Method, in.Title, in.Proto, in.L3, in.IfaceKnown = "gre", "GRE", "GRE", true, true
	dcCheck(t, in, "iface", "iran", "interface is missing")
}

func TestDownCauseMTU(t *testing.T) {
	ir := "P ActiveState=active\nP SubState=running\nFWD 1\nPING small 0\nPING big 100\nST LISTEN *:40212 *:*\nST ESTAB 192.0.2.10:40212 198.51.100.20:5555\n"
	kh := dcActive + "PROBE 1\nST ESTAB 198.51.100.20:5555 192.0.2.10:40212\nR 40212 0 90\n"
	dcCheck(t, dcSides(ir, kh), "mtu", "route", "big packets", "MTU")
}

// heartbeat timeouts minute after minute while both cores run and are connected
func TestDownCauseFlaps(t *testing.T) {
	ir := dcActive + "FWD 1\nST LISTEN *:3080 *:*\nST ESTAB 192.0.2.10:3080 198.51.100.20:5555\n" +
		"J @1794481100 11-Nov 21:55:40 [WARN] Heartbeat timeout — Status: Disconnected timeout=25000\n" +
		"J @1794481300 11-Nov 21:59:00 [WARN] Heartbeat timeout — Status: Disconnected timeout=25000\n" +
		"J @1794481500 11-Nov 22:02:20 [ERROR] transport failed, restarting error=\"Heartbeat timeout\"\n"
	kh := dcActive + "PROBE 1\nST ESTAB 198.51.100.20:5555 192.0.2.10:3080\nR 3080 0 80\n"
	in := dcSides(ir, kh)
	in.Method, in.Title = "backhaul", "Backhaul"
	dcCheck(t, in, "flaps", "route", "3 drops in the last 15 min")
}

func TestDownCauseLicenceAndTLS(t *testing.T) {
	ir := dcActive + "FWD 1\nJ @1794481600 23-Oct 14:36:58 [ERROR] License IP mismatch\n"
	in := dcSides(ir, dcActive+"PROBE 1\n")
	in.Method, in.Title = "premium", "Backhaul Premium"
	dcCheck(t, in, "license", "iran", "licence was refused", "License IP mismatch")

	kh := dcActive + "PROBE 1\nJ @1794481600 2026/11/12 11:06:40 remote error: tls: bad certificate psk=S3cr3t\n"
	dcCheck(t, dcSides(dcActive+"FWD 1\n", kh), "tls", "foreign", "TLS handshake")
	// "License is valid" is no cause
	if p := dcMatch("premium", "23-Oct 14:36:58 [INFO] License is valid"); p != nil {
		t.Fatalf("a valid licence matched %s", p.Code)
	}
}

func TestDownCauseOthers(t *testing.T) {
	dcCheck(t, dcSides(dcActive+"FWD 1\n", dcActive+"PROBE 0\n"), "probe_down", "foreign", "probe server isn't listening on port 49036")
	dcCheck(t, dcSides(dcActive+"FWD 0\n", dcActive+"PROBE 1\n"), "fwd_down", "iran", "check port 51079")
	in := dcSides(dcActive+"FWD 1\n", "")
	in.KH.Err = "dial tcp 192.0.2.10:22: i/o timeout"
	dcCheck(t, in, "ssh", "foreign", "can't reach it over SSH")
	dcCheck(t, dcSides("NOUNIT\n", dcActive), "no_unit", "iran", "isn't installed")
	dcCheck(t, dcSides(dcActive+"FWD 1\nMEM 20000 2000000\n", dcActive+"PROBE 1\n"), "memory", "iran", "memory is almost full")

	in = dcSides(dcActive+"FWD 1\n", dcActive+"PROBE 1\n")
	in.Job = &Job{Kind: "options", Started: in.DownAt - 120, Ended: in.DownAt - 30}
	dcCheck(t, in, "panel_job", "panel", "“options”")

	c := dcCheck(t, dcSides(dcActive+"FWD 1\n", dcActive+"PROBE 1\nR 40212 0 90\n"), "unknown", "", "nothing more could be proven")
	if len(c.Evidence) == 0 {
		t.Error("the fallback lists what was tested")
	}
}

func TestDCRuleHits(t *testing.T) {
	r := "-A IGPX -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 12346"
	if !dcRuleHits(r, "tcp", 443) || dcRuleHits(r, "tcp", 8443) || dcRuleHits(r, "udp", 443) {
		t.Fatal("multiport rule")
	}
	if !dcRuleHits("-A PREROUTING -p tcp -m tcp --dport 2000:2010 -j DNAT --to-destination 10.0.0.2", "tcp", 2005) {
		t.Fatal("port range")
	}
	if dcRuleHits("-A OUTPUT -p tcp -d 10.1.2.3/32 -j DNAT --to-destination 10.0.0.2", "tcp", 443) {
		t.Fatal("a rule without a port is not judged")
	}
	if h, p := dcHostPort("[::ffff:192.0.2.10]:40212"); h != "192.0.2.10" || p != 40212 {
		t.Fatalf("got %s %d", h, p)
	}
	if h, p := dcHostPort("192.0.2.10%eth0:80"); h != "192.0.2.10" || p != 80 {
		t.Fatalf("got %s %d", h, p)
	}
}

// dcHost answers the facts and the reach scripts with fixed outputs.
type dcHost struct{ facts, reach string }

func (h dcHost) Label() string { return "dc" }
func (h dcHost) Run(_ context.Context, s string, _ func(string)) (string, error) {
	if strings.Contains(s, "NOUNIT") {
		return h.facts, nil
	}
	return h.reach, nil
}
func (h dcHost) WriteFile(string, []byte, os.FileMode) error { return nil }

// end to end: the switcher reports a path down, the monitor's read starts one hunt (not
// two), the card's view carries the cause, and an up path forgets it
func TestDownCauseSchedule(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir1", Name: "iran2", IPv4: "192.0.2.10"}, {ID: "kh1", Name: "nl", IPv4: "198.51.100.20", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "nl", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 36,
			Active: "gre", HotStandby: true, Paths: []HSPath{{Method: "gre", Family: "v4", Index: 50}, {Method: "tpk", Family: "v4", Index: 53}}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}}
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir1" {
			return dcHost{facts: "TS 1\n" + dcActive + "FWD 1\nST LISTEN *:40212 *:*\n"}
		}
		return dcHost{facts: "TS 1\n" + dcActive + "PROBE 1\n", reach: "R 40212 0 77\n"}
	}
	tn := st.Tunnel("aaaaaaaaaaaa")
	v := &hsView{Active: 0, Paths: []string{"GRE (v4)", "TP Tunnel (v4)"}, OK: []bool{true, false}, Keys: []string{"gre|v4", "tpk|v4"}, Changed: []int64{0, 1794481086}}
	a.hsReport(tn, v, nil)
	a.hsReport(tn, v, nil) // the second read while the first hunt runs starts nothing
	deadline := time.Now().Add(5 * time.Second)
	var got *hsView
	for time.Now().Before(deadline) {
		if got = a.hsViewCause(tn.ID); got != nil && got.Cause != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got == nil || got.Cause == nil || got.Cause[1] == nil || got.Cause[0] != nil {
		t.Fatalf("no cause on the card: %+v", got)
	}
	if c := got.Cause[1]; c.Code != "stuck" || c.DownAt != 1794481086 || !strings.Contains(c.Text, "192.0.x.x:40212") {
		t.Fatalf("cause = %+v", c)
	}
	if a.hsViewOf(tn.ID).Cause != nil {
		t.Fatal("the cached view was changed")
	}
	a.healthMu.Lock()
	tried := len(a.dc.tried)
	a.healthMu.Unlock()
	if tried != 1 {
		t.Fatalf("%d hunts, want 1", tried)
	}
	// the same outage within dcEvery: no new hunt even after the gap
	a.healthMu.Lock()
	a.dc.tried["aaaaaaaaaaaa|tpk|v4"] = time.Now().Add(-time.Hour)
	a.healthMu.Unlock()
	a.hsReport(tn, v, nil)
	a.healthMu.Lock()
	busy := a.dc.busy["aaaaaaaaaaaa|tpk|v4"]
	a.healthMu.Unlock()
	if busy {
		t.Fatal("a known cause was looked for again")
	}
	up := *v
	up.OK = []bool{true, true}
	a.hsReport(tn, &up, nil)
	if c := a.hsViewCause(tn.ID).Cause; c != nil {
		t.Fatalf("an up path keeps its cause: %+v", c)
	}
}

// 2026-11-13, "تانل هلند 1": the card said "foreign server: the CPU is overloaded (load 4.2
// on 2 cores)" for Plain GRE and Backhaul Premium. nl's two cores were ~45% busy; the load
// came from many short threads (Premium under box64, a crash-looping qemu core). GRE lost
// 73% of its packets on the route; Premium's emulated core overflowed its tun queue.
func TestDownCauseLoadIsNotCPU(t *testing.T) {
	busy := strings.Replace(dcActive, "LOAD 0.20 2\n", "LOAD 4.20 2\nCPU 45\n", 1)
	in := dcSides(dcActive+"FWD 1\n", busy+"PROBE 1\n")
	if c := dcClassify(in); c.code == "cpu" {
		t.Fatalf("load 4.2 with the CPU 45%% busy named the CPU: %s", c.en)
	}
	hot := strings.Replace(dcActive, "LOAD 0.20 2\n", "LOAD 4.20 2\nCPU 97\n", 1)
	dcCheck(t, dcSides(dcActive+"FWD 1\n", hot+"PROBE 1\n"), "cpu", "foreign", "97% busy, load 4.2 on 2 cores", "97% مشغول")
	// an older answer without the busy sample still judges by the load
	old := strings.Replace(dcActive, "LOAD 0.20 2\n", "LOAD 4.20 2\n", 1)
	dcCheck(t, dcSides(dcActive+"FWD 1\n", old+"PROBE 1\n"), "cpu", "foreign", "load 4.2 on 2 cores")
}

func TestDownCauseL3Loss(t *testing.T) {
	ir := strings.Replace(dcActive, "PING small 0\n", "PING small 100\n", 1) + "IF up 100 200\nIF2 133 360\nINNER 70\n"
	kh := strings.Replace(dcActive, "LOAD 0.20 2\n", "LOAD 4.20 2\nCPU 45\n", 1) + "PROBE 1\nIF up 50 60\nIF2 59 166\n"
	in := dcSides(ir, kh)
	in.Method, in.Title, in.Proto, in.L3, in.IfaceKnown, in.FwdPort = "gre", "GRE", "GRE", true, true, 0
	dcCheck(t, in, "l3_loss", "route", "loses most of this tunnel's GRE packets", "70%", "sent 160, received 33")
}

func TestDownCauseCoreSlow(t *testing.T) {
	kh := strings.Replace(dcActive, "LOAD 0.20 2\n", "LOAD 4.20 2\nCPU 48\n", 1) + "PROBE 1\nEMU\nST ESTAB 192.0.2.10:443 198.51.100.20:443\nR 443 0 95\n"
	for i := 0; i < 30; i++ {
		kh += "J @1794481650 13-Nov 01:18:52 [WARN] NetToTun channel full, dropping packet\n"
	}
	ir := dcActive + "FWD 1\nST LISTEN 0.0.0.0:443 *:*\nST ESTAB 198.51.100.20:443 192.0.2.10:443\n"
	in := dcSides(ir, kh)
	in.Method, in.Title = "premium", "Backhaul Premium"
	dcCheck(t, in, "core_slow", "foreign", "can't keep up", "30 times", "under emulation", "NetToTun channel full")
}
