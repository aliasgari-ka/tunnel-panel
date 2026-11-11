package main

import (
	"strings"
	"testing"
)

// The ICMP facade's two firewall rules ("INPUT -p icmp -s <peer> -j ACCEPT" and "OUTPUT -d
// <peer> -p icmp --icmp-type 0 -j DROP") were the same for every tunnel between the same
// two servers, so stopping one (a second tunnel, a hot-standby path, the benchmark's copy)
// deleted the live tunnel's: its DROP went and the kernel answered every relay frame with
// a full-size echo reply. Each tunnel now tags its rules and removes only its own.
func TestHunt3A_ICMPTeardownRemovesSharedRules(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.10"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.20", Role: "foreign"}
	live := &Tunnel{ID: "aaaaaaaaaaaa", Name: "live", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 3}
	bench := &Tunnel{ID: "bench", Name: "route-benchmark", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "41002", Index: 250,
		Options: map[string]map[string]string{}, Secrets: map[string]string{}}
	m := methodByID["icmp"]
	liveIR, _, err := buildPlans(m, live, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	benchIR, _, err := buildPlans(m, bench, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	liveUp := string(liveIR.Files[tunnelDir(live)+"/up.sh"].Content)
	benchDown := string(benchIR.Files[tunnelDir(bench)+"/down.sh"].Content)
	for _, r := range []string{"OUTPUT -d 198.51.100.20 -p icmp --icmp-type 0", "INPUT -p icmp -s 198.51.100.20"} {
		v := " -j ACCEPT"
		if strings.HasPrefix(r, "OUTPUT") {
			v = " -j DROP"
		}
		if !strings.Contains(liveUp, "iptables -I "+r+" -m comment --comment tpg-aaaaaaaaaaaa"+v) {
			t.Errorf("live up.sh doesn't add its own tagged %q:\n%s", r, liveUp)
		}
		// the copy deletes its own tagged rule, and the untagged (legacy) one only when no
		// tunnel's tagged rule for the peer is left
		if !strings.Contains(benchDown, "iptables -w -D "+r+" -m comment --comment tpg-bench"+v) {
			t.Errorf("bench down.sh doesn't remove its own %q:\n%s", r, benchDown)
		}
		for _, l := range strings.Split(benchDown, "\n") {
			if strings.Contains(l, "-D "+r+v) && !strings.Contains(l, "grep -q -- '--comment tpg-' ||") {
				t.Errorf("bench down.sh removes the shared untagged %q unguarded: %s", r, l)
			}
		}
	}
}
