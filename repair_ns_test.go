package main

// Repair end to end (fake systemd, see failover_ns_test.go): a healthy tunnel is left alone, a
// broken one is applied again, a hot-standby tunnel with an older switcher gets the new one in
// place. Root, TP_REPAIR_E2E=1.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRepairNS(t *testing.T) {
	if os.Getenv("TP_REPAIR_E2E") == "" {
		t.Skip("set TP_REPAIR_E2E=1 (root, network namespaces)")
	}
	fake, _ := filepath.Abs("testdata/fakesd")
	for _, ns := range []string{"tir", "tkh"} {
		sh(t, "rm -rf /etc/netns/"+ns+" && mkdir -p /etc/netns/"+ns+"/tunnel-panel /etc/netns/"+ns+"/systemd/system /etc/netns/"+ns+"/backpack /etc/tunnel-panel /etc/backpack")
	}
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/tir /etc/netns/tkh")
	e2eTopology(t, "v4")
	hsOnly = []string{"gre", "bp_l3"}
	defer func() { hsOnly = nil }()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	mk := func(id string, idx int, port string, hot bool) *Tunnel {
		return &Tunnel{ID: id, Name: id, ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: port, Index: idx, HotStandby: hot,
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}
	}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}, {ID: "kh", Name: "foreign", IPv4: "10.99.0.2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{mk("okok", 40, "28501", false), mk("brkn", 41, "28502", false), mk("hots", 42, "28579", true)}
		return nil
	})
	var mu sync.Mutex
	var msgs []string
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir" {
			return nsSD{"tir", fake}
		}
		return nsSD{"tkh", fake}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	for _, id := range []string{"okok", "brkn", "hots"} {
		if err := a.applyAndWait(ctx, st.Tunnel(id), "gre"); err != nil {
			t.Fatalf("apply %s: %v", id, err)
		}
	}
	time.Sleep(10 * time.Second)
	step := func(name string, ok bool) {
		if !ok {
			t.Errorf("FAILED: %s", name)
		}
		t.Logf("%s %s", map[bool]string{true: "✓", false: "✕"}[ok], name)
	}
	health := func(id string) string { return healthReason(a.Health(ctx, st.Tunnel(id))) }
	step("all three work after apply", health("okok") == "" && health("brkn") == "" && health("hots") == "")
	// break one (its unit dies on Iran), and make the hot-standby switcher an older one
	_, _ = nsSD{"tir", fake}.Run(ctx, "systemctl stop tp-brkn.service; ip link del tp41 2>/dev/null; true", nil)
	sh(t, "sed -i '/tp-switcher 3/d' /etc/netns/tir/tunnel-panel/t/hotshs/switch.sh")
	time.Sleep(3 * time.Second)
	t.Logf("   before repair: okok=%q brkn=%q", health("okok"), health("brkn"))
	step("the broken tunnel is seen as broken", health("brkn") != "")
	j, err := a.Repair("test")
	if err != nil {
		t.Fatal(err)
	}
	for j.snapshot().Status == "running" {
		time.Sleep(2 * time.Second)
	}
	for _, l := range j.snapshot().Lines {
		t.Log("  repair: " + l)
	}
	time.Sleep(8 * time.Second)
	step("the broken tunnel works again", health("brkn") == "")
	step("the healthy one still works", health("okok") == "")
	step("hot standby has the new switcher", strings.Contains(sh(t, "cat /etc/netns/tir/tunnel-panel/t/hotshs/switch.sh"), "tp-switcher 3"))
	step("hot standby still passes", health("hots") == "")
	lines := strings.Join(j.snapshot().Lines, "\n")
	step("healthy one left alone", strings.Contains(lines, "okok: fine"))
	step("hot standby got only the switcher (no rebuild)", strings.Contains(lines, "hots: older switcher — updating the switcher in place"))
	mu.Lock()
	all := strings.Join(msgs, "\n")
	mu.Unlock()
	step("summary sent", strings.Contains(all, "🛠 Repair (test)") && strings.Contains(all, "✅ brkn"))
	for _, id := range []string{"okok", "brkn", "hots"} {
		jj, _ := a.Stop(st.Tunnel(id))
		for jj.snapshot().Status == "running" {
			time.Sleep(time.Second)
		}
	}
}
