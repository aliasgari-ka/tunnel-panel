package main

// Hot standby end to end through the real Apply (fake systemd, see failover_ns_test.go):
// GRE + standbys, GRE blocked → the switcher on "Iran" moves users within seconds, GRE
// back → users return after hsFailback, Stop leaves nothing. Root, TP_HS_E2E=1.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	a.notify = func(m string) { msgs = append(msgs, m) }
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
	step("GRE blocked → switcher moved the users off GRE within 30 s", active() != "0" && time.Since(t0) < 30*time.Second)
	step("users pass on the standby", user())

	sh(t, "ip netns exec tkh iptables -w -t raw -D PREROUTING -p 47 -j DROP")
	t1 := time.Now()
	for time.Since(t1) < 150*time.Second && active() != "0" {
		time.Sleep(3 * time.Second)
	}
	t.Logf("   back after %s", time.Since(t1).Round(time.Second))
	step("GRE back → users returned after the stability wait", active() == "0" && time.Since(t1) >= hsFailback*time.Second)
	step("users pass after failback", user())

	_, _, link := a.Health(ctx, tn)
	step("panel health reads the switcher (link "+link+")", link == "up")
	t.Log("   Telegram:\n      " + strings.Join(msgs, "\n      "))
	step("kernel change reported once", strings.Count(strings.Join(msgs, "\n"), "nf_conntrack_max") <= 1)
	step("switch and return were reported", strings.Contains(strings.Join(msgs, "\n"), "🔀 hot switched to") && strings.Contains(strings.Join(msgs, "\n"), "↩ hot back on Plain GRE (v4)"))

	j, _ := a.Stop(tn)
	for j.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
	left := sh(t, "for n in tir tkh; do ip netns exec $n iptables-save; done 2>/dev/null | grep -cE 'TPI_|TPF_|TPM_|TP_|TPHA_|TPHB_|TPHP_'")
	step("stop leaves no firewall rules ("+left+")", left == "0")
	units := sh(t, "ls /etc/netns/tir/systemd/system /etc/netns/tkh/systemd/system 2>/dev/null | grep -c tp-")
	step("stop leaves no units ("+units+")", units == "0")
}
