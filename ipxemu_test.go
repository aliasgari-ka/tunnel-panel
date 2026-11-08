package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The ipx emulation check is valid shell and stops with the message the bench switches
// carriers on (ipx can't run under emulation).
func TestIPXEmuCheckScript(t *testing.T) {
	if ipxEmuCheck("tcpmux") != "" {
		t.Error("non-ipx modes need no emulator check")
	}
	s := ipxEmuCheck("ipx")
	if !strings.Contains(s, "can't run on this") || strings.Contains(s, "box64 installed") {
		t.Errorf("the check should stop on an emulated core, not install box64:\n%s", s)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader("set -e\n" + s)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v %s", err, out)
	}
}

// Premium ipx is refused up front when either side is ARM (the core would run emulated),
// with the text the bench falls back to tcpmux/anytls on; the TCP modes still build.
func TestPremiumIPXRefusedOnEmulatedSide(t *testing.T) {
	ir, kh := &Server{ID: "i", Arch: "x86_64"}, &Server{ID: "k", Arch: "aarch64"}
	if !emulatedAmd64(kh) || emulatedAmd64(ir) {
		t.Fatal("aarch64 should count as emulated, x86_64 as native")
	}
	if _, emu := premiumCoreEmulated(kh); !emu {
		t.Fatal("no arm64 v2 core uploaded: the core runs emulated")
	}
	if _, emu := premiumCoreEmulated(ir); emu {
		t.Fatal("x86_64 runs the core natively")
	}
	kh.IPv4, kh.Role, ir.IPv4 = "159.195.238.75", "foreign", "81.12.35.113"
	tn := &Tunnel{ID: "tp", Name: "us", ServerID: "i", ForeignID: "k", Family: "v4", Ports: "443", Index: 5}
	if _, _, err := buildPlans(methodPremium, tn, ir, kh, Settings{}); err == nil || !strings.Contains(err.Error(), "can't run on this arm64 server") {
		t.Fatalf("ipx on an ARM foreign side: want the can't-run error, got %v", err)
	}
	tn.Options = map[string]map[string]string{"premium": {"mode": "tcpmux"}}
	if _, _, err := buildPlans(methodPremium, tn, ir, kh, Settings{}); err != nil && strings.Contains(err.Error(), "can't run on this") {
		t.Fatalf("tcpmux should build on ARM: %v", err)
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
