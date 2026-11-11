package main

import (
	"strings"
	"testing"
)

// The configs carry the TCP flags, the same on both sides: paqet's own PSH+ACK by default
// (other flags were no better on xe108, where the route cut some flows whatever the flags),
// another one when chosen, and nothing else reaches the YAML.
func TestPaqetTCPFlags(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	tun := func(opts map[string]map[string]string) *Tunnel {
		return &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "443", Index: 3, Options: opts, Secrets: map[string]string{}}
	}
	tmpl := func(p SidePlan) string {
		for name, f := range p.Files {
			if strings.HasSuffix(name, "/paqet.tmpl") {
				return string(f.Content)
			}
		}
		return ""
	}
	ir, kh, err := buildPlans(methodPaqet, tun(nil), srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	for side, p := range map[string]SidePlan{"Iran": ir, "foreign": kh} {
		c := tmpl(p)
		if !strings.Contains(c, "  tcp:\n    local_flag: [\"PA\"]\n    remote_flag: [\"PA\"]\n") {
			t.Errorf("%s config: want PSH+ACK TCP flags by default, got:\n%s", side, c)
		}
	}
	ir, _, err = buildPlans(methodPaqet, tun(map[string]map[string]string{"paqet": {"flags": "A"}}), srv, fsrv, Settings{})
	if err != nil || !strings.Contains(tmpl(ir), `local_flag: ["A"]`) {
		t.Errorf("flags A not in the config (err %v)", err)
	}
	if _, _, err = buildPlans(methodPaqet, tun(map[string]map[string]string{"paqet": {"flags": `A"] ; x`}}), srv, fsrv, Settings{}); err == nil {
		t.Error("an unknown flags value reached the config")
	}
}

// The core runs but its frames are lost on the route: the path says so, not "last error: …".
func TestHSWhyPaqetLoss(t *testing.T) {
	// as the why script hands it over: tr -cd '[:print:]' has cut the "—"
	line := "2026-11-11 22:29:37.434 [WARN] [ALERT] BOTTLENECK: packet_loss  82.4% retransmission (>5%). Causes: pcap buffer overflow"
	if got, want := hsWhyText("active", line), "the route drops most of its raw TCP frames (82.4% retransmission) — try other TCP flags in Paqet's settings"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := hsWhyText("active", "[WARN] [ALERT] BOTTLENECK: kcp_lost — 894 lost segments (>100)."); !strings.Contains(got, "(894 lost segments)") {
		t.Errorf("kcp_lost: got %q", got)
	}
	if got := hsWhyText("failed", line); !strings.HasPrefix(got, "its core on the Iran server is failed") {
		t.Errorf("a stopped core still says so first: %q", got)
	}
}
