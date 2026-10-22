package main

// Diagnose on a broken BackPack L3 link, through the real Apply (fake systemd, see
// failover_ns_test.go): the carrier dropped before the foreign server (a provider
// firewall), then only on the way back. Run as root with TP_DIAG_E2E=1.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBPL3DiagnoseNS(t *testing.T) {
	if os.Getenv("TP_DIAG_E2E") == "" {
		t.Skip("set TP_DIAG_E2E=1 (root, network namespaces)")
	}
	fake, _ := filepath.Abs("testdata/fakesd")
	for _, ns := range []string{"tir", "tkh"} {
		sh(t, "rm -rf /etc/netns/"+ns+" && mkdir -p /etc/netns/"+ns+"/tunnel-panel /etc/netns/"+ns+"/systemd/system /etc/netns/"+ns+"/backpack /etc/tunnel-panel /etc/backpack")
	}
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/tir /etc/netns/tkh")
	e2eTopology(t, "v4")
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}, {ID: "kh", Name: "nl", IPv4: "10.99.0.2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "dg1", Name: "diag", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "28579", Index: 6,
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir" {
			return nsSD{"tir", fake}
		}
		return nsSD{"tkh", fake}
	}
	tn := st.Tunnel("dg1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := a.applyAndWait(ctx, tn, "bp_l3"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	diag := func() string {
		j, err := a.Diagnose(tn)
		if err != nil {
			t.Fatal(err)
		}
		for j.snapshot().Status == "running" {
			time.Sleep(time.Second)
		}
		var keep []string
		for _, l := range j.snapshot().Lines {
			if strings.Contains(l, "carrier") || strings.Contains(l, "DONE") {
				keep = append(keep, strings.TrimSpace(l[strings.Index(l, " ")+1:]))
			}
		}
		return strings.Join(keep, "\n")
	}
	port := "40024"
	sh(t, "ip netns exec tkh iptables -w -t raw -I PREROUTING -p udp --dport "+port+" -j DROP")
	sh(t, "ip netns exec tir ip link set tp6 down; ip netns exec tir ip link set tp6 up") // make sure no stale state carries it
	time.Sleep(3 * time.Second)
	out := diag()
	t.Logf("── carrier dropped before the foreign server ──\n%s", out)
	if !strings.Contains(out, "never arrive at the foreign server") {
		t.Error("the drop towards the foreign server was not identified")
	}
	sh(t, "ip netns exec tkh iptables -w -t raw -D PREROUTING -p udp --dport "+port+" -j DROP")
	sh(t, "ip netns exec tir iptables -w -t raw -I PREROUTING -p udp --sport "+port+" -j DROP")
	time.Sleep(3 * time.Second)
	out = diag()
	t.Logf("── replies dropped on the way back ──\n%s", out)
	if !strings.Contains(out, "nothing comes back") {
		t.Error("the drop on the way back was not identified")
	}
	sh(t, "ip netns exec tir iptables -w -t raw -D PREROUTING -p udp --sport "+port+" -j DROP")
	j, _ := a.Stop(tn)
	for j.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
}
