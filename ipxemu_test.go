package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The emulation check is valid shell and stops on an emulated v2 core.
func TestPremiumEmuCheckScript(t *testing.T) {
	if !strings.Contains(premiumEmuCheck, "doesn't run on this") || !strings.Contains(premiumEmuCheck, "exit 1") {
		t.Errorf("the check should stop on an emulated core:\n%s", premiumEmuCheck)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader("set -e\n" + premiumEmuCheck)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v %s", err, out)
	}
}

// Premium v2 is refused up front in every mode when either side is ARM (the core would run
// emulated and carries no data there), worded so the bench doesn't try the other carriers.
func TestPremiumRefusedOnEmulatedSide(t *testing.T) {
	ir := &Server{ID: "i", Arch: "x86_64", IPv4: "81.12.35.113"}
	kh := &Server{ID: "k", Arch: "aarch64", IPv4: "159.195.238.75", Role: "foreign"}
	if _, emu := premiumCoreEmulated(kh); !emu {
		t.Fatal("no arm64 v2 core uploaded: the core runs emulated")
	}
	if _, emu := premiumCoreEmulated(ir); emu {
		t.Fatal("x86_64 runs the core natively")
	}
	for _, mode := range []string{"ipx", "tcpmux", "anytls"} {
		tn := &Tunnel{ID: "tp", Name: "us", ServerID: "i", ForeignID: "k", Family: "v4", Ports: "443", Index: 5,
			Options: map[string]map[string]string{"premium": {"mode": mode}}}
		_, _, err := buildPlans(methodPremium, tn, ir, kh, Settings{})
		if err == nil || !strings.Contains(err.Error(), "doesn't run on arm64 servers") || strings.Contains(err.Error(), "can't run on this") {
			t.Errorf("%s on an ARM foreign side: want the doesn't-run error, got %v", mode, err)
		}
	}
	tn := &Tunnel{ID: "tp", Name: "us", ServerID: "i", ForeignID: "k2", Family: "v4", Ports: "443", Index: 5}
	if _, _, err := buildPlans(methodPremium, tn, ir, &Server{ID: "k2", Arch: "x86_64", IPv4: "159.195.238.76", Role: "foreign"}, Settings{}); err != nil && strings.Contains(err.Error(), "doesn't run on") {
		t.Fatalf("x86_64 on both sides should build: %v", err)
	}
}

// The probe-server start waits for the previous server to exit before binding its port.
func TestProbeServerUpScript(t *testing.T) {
	s := probeServerUpLife(41002, 60)
	if !strings.Contains(s, "pgrep -f -- '-listen :41002 -life'") || strings.Index(s, "pgrep") > strings.Index(s, "setsid") {
		t.Errorf("no wait for the old probe server before starting:\n%s", s)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(s)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v %s", err, out)
	}
}
