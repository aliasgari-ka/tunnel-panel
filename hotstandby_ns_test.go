package main

// Hot standby end to end through the real Apply (fake systemd, see failover_ns_test.go):
// GRE + standbys, GRE blocked → the switcher on "Iran" moves users within seconds, GRE
// back → users return after hsFailback, Stop leaves nothing. Root, TP_HS_E2E=1.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHotStandbyNS(t *testing.T) {
	if os.Getenv("TP_HS_E2E") == "" {
		t.Skip("set TP_HS_E2E=1 (root, network namespaces)")
	}
	fake, _ := filepath.Abs("testdata/fakesd")
	for _, ns := range []string{"tir", "tkh"} {
		sh(t, "rm -rf /etc/netns/"+ns+" && mkdir -p /etc/netns/"+ns+"/tunnel-panel /etc/netns/"+ns+"/systemd/system /etc/netns/"+ns+"/backpack /etc/tunnel-panel /etc/backpack")
	}
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/tir /etc/netns/tkh")
	e2eTopology(t, "v4")
	hsOnly = []string{"gre", "bp_l3", "golden", "backhaul", "frp"}
	defer func() { hsOnly = nil }()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}, {ID: "kh", Name: "foreign", IPv4: "10.99.0.2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "hs1", Name: "hot", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "28579", Index: 30, HotStandby: true,
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}}
		return nil
	})
	var msgs []string
	var mu sync.Mutex
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	allMsgs := func() string {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(msgs, "\n")
	}
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir" {
			return nsSD{"tir", fake}
		}
		return nsSD{"tkh", fake}
	}
	tn := st.Tunnel("hs1")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	user := func() bool {
		for k := 0; k < 5; k++ {
			if strings.HasPrefix(sh(t, "ip netns exec tus curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 6 http://10.98.0.1:28579/blob.bin"), "200 2097152") {
				return true
			}
			time.Sleep(2 * time.Second)
		}
		return false
	}
	active := func() string {
		return strings.Fields(sh(t, "cat /etc/netns/tir/tunnel-panel/t/hs1hs/active 2>/dev/null") + " -")[0]
	}
	step := func(name string, ok bool) {
		mark := "✓"
		if !ok {
			mark, _ = "✕", 0
			t.Errorf("FAILED: %s", name)
		}
		t.Logf("%s %s   [users on path %s]", mark, name, active())
	}
	if err := a.applyAndWait(ctx, tn, "gre"); err != nil {
		for _, l := range a.jobs.latestFor("hs1").snapshot().Lines {
			t.Log("  " + l)
		}
		t.Fatalf("apply: %v", err)
	}
	for _, l := range a.jobs.latestFor("hs1").snapshot().Lines {
		if strings.Contains(l, "path") || strings.Contains(l, "✓") || strings.Contains(l, "✕") || strings.Contains(l, "DONE") {
			t.Log("  apply: " + l)
		}
	}
	time.Sleep(8 * time.Second)
	step("users pass on the primary (GRE)", user() && active() == "0")

	sh(t, "ip netns exec tkh iptables -w -t raw -I PREROUTING -p 47 -j DROP")
	t0 := time.Now()
	for time.Since(t0) < 60*time.Second && active() == "0" {
		time.Sleep(2 * time.Second)
	}
	t.Logf("   switched after %s", time.Since(t0).Round(time.Second))
	step("GRE blocked → switcher moved the users off GRE within 15 s", active() != "0" && time.Since(t0) < 15*time.Second)
	step("users pass on the standby", user())

	sh(t, "ip netns exec tkh iptables -w -t raw -D PREROUTING -p 47 -j DROP")
	t1 := time.Now()
	for time.Since(t1) < 150*time.Second && active() != "0" {
		time.Sleep(3 * time.Second)
	}
	t.Logf("   back after %s", time.Since(t1).Round(time.Second))
	step("GRE back → users returned after the stability wait", active() == "0" && time.Since(t1) >= hsFailback*time.Second)
	step("users pass after failback", user())

	// seamless: a download running during a planned switch (path chosen in the panel, and
	// back) must finish intact; new connections take the new path
	seamless := func(name string, do func()) {
		sh(t, "rm -f /tmp/hs-dl.out; (ip netns exec tus curl -s -o /dev/null -w '%{http_code} %{size_download}' --limit-rate 150k --max-time 60 http://10.98.0.1:28579/blob.bin > /tmp/hs-dl.out 2>&1; echo \" exit=$?\" >> /tmp/hs-dl.out) >/dev/null 2>&1 &")
		time.Sleep(3 * time.Second)
		do()
		for i := 0; i < 40 && !strings.Contains(sh(t, "cat /tmp/hs-dl.out 2>/dev/null"), "exit="); i++ {
			time.Sleep(time.Second)
		}
		got := strings.TrimSpace(sh(t, "cat /tmp/hs-dl.out"))
		t.Logf("   download across the switch: %s", got)
		step(name+" — the open download finished intact ("+got+")", strings.HasPrefix(got, "200 2097152") && strings.HasSuffix(got, "exit=0"))
	}
	seamless("pin Golden-GRE from the panel", func() {
		msg, err := a.hsPinTo(ctx, tn, "golden|v4")
		t.Logf("   pin: %s %v", msg, err)
		for i := 0; i < 15 && active() != "1"; i++ {
			time.Sleep(time.Second)
		}
	})
	step("users on the chosen path (1)", active() == "1")
	step("new connections pass on it", user())
	seamless("back to the tunnel's own method", func() {
		_, _ = a.hsPinTo(ctx, tn, "")
		for i := 0; i < 15 && active() != "0"; i++ {
			time.Sleep(time.Second)
		}
	})
	step("users back on GRE (0)", active() == "0")
	j0, err := a.ApplyRoute(tn, "golden", "v4")
	for err == nil && j0.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
	time.Sleep(6 * time.Second)
	step("picking a running method in Manage is an instant switch, not a rebuild", err == nil && j0.snapshot().Kind == "switch" && active() == "1")
	_, _ = a.hsPinTo(ctx, tn, "")
	for i := 0; i < 15 && active() != "0"; i++ {
		time.Sleep(time.Second)
	}

	// an idle connection (a chat app waiting for a push) on a forwarder path that dies must be
	// closed at once, so the app reconnects, instead of waiting for its own keepalive
	bh := -1
	for k, p := range hsGood(tn) {
		if p.Method == "backhaul" {
			bh = k
		}
	}
	if bh >= 0 {
		_, _ = a.hsPinTo(ctx, tn, "backhaul|v4")
		for i := 0; i < 20 && active() != strconv.Itoa(bh); i++ {
			time.Sleep(time.Second)
		}
		sh(t, `rm -f /tmp/hs-idle.out; (ip netns exec tus timeout 90 python3 -c '
import socket, time
s = socket.create_connection(("10.98.0.1", 28579)); t = time.time()
try:
    d = s.recv(1); print("closed" if not d else "data", round(time.time() - t, 1))
except Exception as e:
    print("reset", type(e).__name__, round(time.time() - t, 1))
' > /tmp/hs-idle.out 2>&1) >/dev/null 2>&1 &`)
		time.Sleep(3 * time.Second)
		sh(t, "ip netns exec tkh iptables -w -I OUTPUT -p tcp -d 10.99.0.1 --dport 40000:60000 -j DROP")
		t4 := time.Now()
		for i := 0; i < 60 && strings.TrimSpace(sh(t, "cat /tmp/hs-idle.out 2>/dev/null")) == ""; i++ {
			time.Sleep(time.Second)
		}
		got := strings.TrimSpace(sh(t, "cat /tmp/hs-idle.out 2>/dev/null"))
		t.Logf("   idle connection on Backhaul after its path died: %q after %s (users now on path %s)", got, time.Since(t4).Round(time.Second), active())
		step("idle connection on the dead forwarder path is closed within 20 s", got != "" && !strings.HasPrefix(got, "data") && time.Since(t4) < 20*time.Second)
		step("new connections pass on the path it moved to", user())
		sh(t, "ip netns exec tkh iptables -w -D OUTPUT -p tcp -d 10.99.0.1 --dport 40000:60000 -j DROP")
		_, _ = a.hsPinTo(ctx, tn, "")
		for i := 0; i < 90 && active() != "0"; i++ {
			time.Sleep(time.Second)
		}
	} else {
		t.Log("   (no Backhaul path running: idle-connection check skipped)")
	}

	_, _, link := a.Health(ctx, tn)
	step("panel health reads the switcher (link "+link+")", link == "up")
	t.Log("   Telegram:\n      " + strings.ReplaceAll(allMsgs(), "\n", "\n      "))
	step("kernel change reported once", strings.Count(allMsgs(), "nf_conntrack_max") <= 1)
	step("switch and return were reported", strings.Contains(allMsgs(), "🔀 hot switched to") && strings.Contains(allMsgs(), "↩ hot back on Plain GRE (v4)"))

	// auto mode: GRE gets lossy (not down) → the switcher measures and moves the users
	msg, err := a.setHSMode(ctx, tn, true)
	step("auto mode switched on without a re-apply ("+msg+")", err == nil && strings.Contains(msg, "now auto"))
	time.Sleep(25 * time.Second) // a few ping rounds on the healthy GRE first
	sh(t, "ip netns exec tir tc qdisc add dev tp30 root netem loss 25%")
	t2 := time.Now()
	for time.Since(t2) < 150*time.Second && active() == "0" {
		time.Sleep(3 * time.Second)
	}
	t.Logf("   auto-switched after %s; status:\n%s", time.Since(t2).Round(time.Second), sh(t, "cat /etc/netns/tir/tunnel-panel/t/hs1hs/status; tail -4 /etc/netns/tir/tunnel-panel/t/hs1hs/events.log"))
	step("lossy GRE (25 %) → auto mode moved the users to a better path", active() != "0")
	step("users pass on it", user())
	moved := active()
	time.Sleep(30 * time.Second)
	step("no flapping: users stay put", active() == moved)
	sh(t, "ip netns exec tir tc qdisc del dev tp30 root")
	_, _ = a.setHSMode(ctx, tn, false)
	t3 := time.Now()
	for time.Since(t3) < 120*time.Second && active() != "0" {
		time.Sleep(3 * time.Second)
	}
	t.Logf("   manual again: back on the chosen path after %s", time.Since(t3).Round(time.Second))
	step("manual mode → users back on the chosen path (GRE)", active() == "0")
	v, _, _ := a.hsRead(ctx, nsSD{"tir", fake}, tn, 0)
	t.Logf("   view: %+v", v)
	step("view carries rtt/loss/speed", v != nil && len(v.RTT) == len(v.Paths) && v.RTT[0] >= 0)
	_, _, _ = a.Health(ctx, tn)
	all := allMsgs()
	step("auto move reported", strings.Contains(all, "auto mode moved the users"))

	// leaving a method out on the route takes it out of the running switcher (no rebuild),
	// putting it back starts it again
	waitJob := func(pj *Job) string {
		if pj == nil {
			return "none"
		}
		for pj.snapshot().Status == "running" {
			time.Sleep(time.Second)
		}
		return pj.snapshot().Status
	}
	npaths := func() int { n := 0; st.View(func(*State) { n = len(tn.Paths) }); return n }
	before := npaths()
	hasPath := func(mid string) (ok bool) { // in the list (FRP can't download its binary offline: it is there as failed)
		st.View(func(*State) {
			for _, p := range tn.Paths {
				ok = ok || p.Method == mid && p.Family == "v4"
			}
		})
		return
	}
	a.setRouteSkip("ir", "kh", "frp", "v4", true)
	s1 := waitJob(func() *Job { j, _ := a.hsUpdatePaths(tn); return j }())
	sw := sh(t, "grep -c . /etc/netns/tir/tunnel-panel/t/hs1hs/targets")
	step("left out FRP → path removed ("+s1+", paths "+strconv.Itoa(before)+"→"+strconv.Itoa(npaths())+", switcher targets "+sw+")",
		s1 == "ok" && !hasPath("frp") && npaths() == before-1 && sw == strconv.Itoa(npaths()))
	step("users still pass after the update", user())
	a.setRouteSkip("ir", "kh", "frp", "v4", false)
	s2 := waitJob(func() *Job { j, _ := a.hsUpdatePaths(tn); return j }())
	step("FRP put back → path added ("+s2+", paths "+strconv.Itoa(npaths())+")", s2 == "ok" && hasPath("frp") && npaths() == before)
	s3 := waitJob(func() *Job { j, _ := a.hsUpdatePaths(tn); return j }())
	step("nothing to change → no job ("+s3+")", s3 == "none")

	j, _ := a.Stop(tn)
	for j.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
	left := sh(t, "for n in tir tkh; do ip netns exec $n iptables-save; done 2>/dev/null | grep -cE 'TPI_|TPF_|TPM_|TP_|TPHA_|TPHB_|TPHP_'")
	step("stop leaves no firewall rules ("+left+")", left == "0")
	units := sh(t, "ls /etc/netns/tir/systemd/system /etc/netns/tkh/systemd/system 2>/dev/null | grep -c tp-")
	step("stop leaves no units ("+units+")", units == "0")
}
