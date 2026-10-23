package main

// The benchmark's carrier fallback on a filtered route: UDP and TCP between the two servers
// are dropped on the wire (like Iran's IPv4 filtering of UDP and hand-made TCP), GRE and
// ICMP pass. BackPack L3 (udp), Premium ipx (tcp) and Golden-GRE (dns) must each find a
// carrier that works, and hot standby must use it. Root, TP_BENCHALT_E2E=1.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBenchAltNS(t *testing.T) {
	if os.Getenv("TP_BENCHALT_E2E") == "" {
		t.Skip("set TP_BENCHALT_E2E=1 (root, network namespaces)")
	}
	fake, _ := filepath.Abs("testdata/fakesd")
	for _, ns := range []string{"tir", "tkh"} {
		sh(t, "rm -rf /etc/netns/"+ns+" && mkdir -p /etc/netns/"+ns+"/tunnel-panel /etc/netns/"+ns+"/systemd/system /etc/netns/"+ns+"/backpack /etc/tunnel-panel /etc/backpack")
	}
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/tir /etc/netns/tkh")
	e2eTopology(t, "v4")
	// public-looking addresses (the Premium core refuses to run without a public IP)
	sh(t, "ip -n tir addr add 198.51.100.1/24 dev vir; ip -n tkh addr add 198.51.100.2/24 dev vkh")
	// the filter: on the wire (egress of both ends) UDP and TCP between the servers die
	sh(t, `for x in "tir vir" "tkh vkh"; do set -- $x
ip netns exec $1 tc qdisc add dev $2 root handle 1: prio
ip netns exec $1 tc filter add dev $2 parent 1: protocol ip u32 match ip protocol 17 0xff action drop
ip netns exec $1 tc filter add dev $2 parent 1: protocol ip u32 match ip protocol 6 0xff action drop
done`)
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "198.51.100.1"}, {ID: "kh", Name: "foreign", IPv4: "198.51.100.2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "hs2", Name: "hot", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "28579", Index: 31, HotStandby: true,
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, benchRes: map[string][]BenchResult{}}
	a.notify = func(string) {}
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir" {
			return nsSD{"tir", fake}
		}
		return nsSD{"tkh", fake}
	}
	step := func(name string, ok bool) {
		if !ok {
			t.Errorf("FAILED: %s", name)
		}
		t.Logf("%s %s", map[bool]string{true: "✓", false: "✕"}[ok], name)
	}
	j, err := a.Bench(BenchRequest{IranID: "ir", ForeignID: "kh", Family: "v4", Methods: []string{"premium", "gre"}, Seconds: 2, MaxMB: 2})
	if err != nil {
		t.Fatal(err)
	}
	for j.snapshot().Status == "running" {
		time.Sleep(2 * time.Second)
	}
	for _, l := range j.snapshot().Lines {
		if strings.Contains(l, "──") || strings.Contains(l, "→ trying") || strings.Contains(l, "✓ works") || strings.Contains(l, "FAILED") || strings.Contains(l, "ok:") {
			t.Log("  bench: " + l)
		}
	}
	res := map[string]BenchResult{}
	for _, r := range a.benchResults("ir", "kh", "v4") {
		res[r.Method] = r
	}
	for _, mid := range []string{"premium"} {
		r := res[mid]
		step(mid+" works with another carrier ("+r.Title+")", r.OK && len(r.Opts) > 0)
	}
	step("Plain GRE passes as is", res["gre"].OK && len(res["gre"].Opts) == 0)

	// hot standby takes the carriers the benchmark found
	hsOnly = []string{"gre", "premium"}
	defer func() { hsOnly = nil }()
	tn := st.Tunnel("hs2")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := a.applyAndWait(ctx, tn, "gre"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, p := range tn.Paths {
		t.Logf("   path %s opts %v failed=%q", p.label(), p.Opts, p.Failed)
	}
	time.Sleep(25 * time.Second)
	v, _, _ := a.hsRead(ctx, nsSD{"tir", fake}, tn, 0)
	t.Logf("   switcher: %+v", v)
	n := 0
	for _, ok := range v.OK {
		if ok {
			n++
		}
	}
	step("every hot-standby path passes traffic on the filtered route", v != nil && n == len(v.Paths) && n == 2)
	j2, _ := a.Stop(tn)
	for j2.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
}
