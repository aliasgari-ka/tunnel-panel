package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func spoofTunnel(ports string) *Tunnel {
	return &Tunnel{ID: "sp1", Name: "sp", Family: "v4", Ports: ports, Index: 7, Selected: "spoof",
		Options: map[string]map[string]string{"spoof": {"spoof_ip": "203.0.113.5", "peer_spoof_ip": "203.0.113.6"}}}
}

// a mapping 8080=80 must reach :80 on the foreign side; lists and ranges are refused
func TestSpoofMappedPortAndSinglePort(t *testing.T) {
	ir, kh, err := buildPlans(methodByID["spoof"], spoofTunnel("8080=80"), &Server{IPv4: "192.0.2.1"}, &Server{IPv4: "192.0.2.2"}, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := tunnelDir(spoofTunnel("")) + "/spoof.json"
	irc, khc := string(ir.Files[cfg].Content), string(kh.Files[cfg].Content)
	if !strings.Contains(irc, `"listen": "0.0.0.0:8080"`) {
		t.Fatalf("Iran side should listen on 8080:\n%s", irc)
	}
	if !strings.Contains(khc, `"forward": "127.0.0.1:80"`) {
		t.Fatalf("foreign side should forward to :80:\n%s", khc)
	}
	for _, ports := range []string{"443,8443", "2000-2010", "2000-2010=3000-3010", "x"} {
		if _, _, err := buildPlans(methodByID["spoof"], spoofTunnel(ports), &Server{IPv4: "192.0.2.1"}, &Server{IPv4: "192.0.2.2"}, Settings{}); err == nil {
			t.Errorf("ports %q: want an error, Spoof-Tunnel forwards one port", ports)
		}
	}
	if l, d, err := spoofPorts(""); err != nil || l != "443" || d != "443" {
		t.Fatalf("empty ports: %s %s %v", l, d, err)
	}
}

// a range wider than 4096 ports still clashes with a port near its end
func TestPortClashWideRange(t *testing.T) {
	st := &State{Tunnels: []*Tunnel{{ID: "a", Name: "wide", ServerID: "ir", Ports: "1000-9000", Index: 4, Active: "gre"}}}
	if err := portClash(st, &Tunnel{ID: "x", ServerID: "ir", Ports: "8000", Index: 9, Selected: "gre"}, ""); err == nil || !strings.Contains(err.Error(), `"wide"`) || !strings.Contains(err.Error(), "port 8000") {
		t.Fatalf("want a clash on 8000, got %v", err)
	}
	if err := portClash(st, &Tunnel{ID: "x", ServerID: "ir", Ports: "8500-9500", Index: 9, Selected: "gre"}, ""); err == nil || !strings.Contains(err.Error(), "port 8500") {
		t.Fatalf("want a clash on overlapping ranges, got %v", err)
	}
	if err := portClash(st, &Tunnel{ID: "x", ServerID: "ir", Ports: "9001-9100,999", Index: 9, Selected: "gre"}, ""); err != nil {
		t.Fatalf("adjacent ranges don't clash: %v", err)
	}
}

// stopping one tunnel keeps the shared firewalld peer rule while another tunnel to the
// same peer still runs, and removes it once none does
func TestInboundPeerRichRuleShared(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	root := t.TempDir()
	tdir, bin := filepath.Join(root, "t"), filepath.Join(root, "bin")
	log := filepath.Join(root, "fw.log")
	_ = os.MkdirAll(bin, 0o755)
	slash := filepath.ToSlash
	_ = os.WriteFile(filepath.Join(bin, "firewall-cmd"), []byte("#!/bin/bash\necho \"$*\" >>'"+slash(log)+"'\n"), 0o755)
	// tp-b is running unless $B_DOWN is set
	_ = os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/bash\nif [ \"$2\" = tp-b.service ] && [ -z \"$B_DOWN\" ]; then echo active; else echo inactive; exit 3; fi\n"), 0o755)

	down := map[string]string{}
	for _, id := range []string{"a", "b"} {
		up, d := inboundRules(&Tunnel{ID: id}, "198.51.100.7", "443", "")
		_ = os.MkdirAll(filepath.Join(tdir, id), 0o755)
		_ = os.WriteFile(filepath.Join(tdir, id, "fw-in-up.sh"), []byte("#!/bin/bash\n"+up), 0o755)
		down[id] = strings.ReplaceAll(d, "/etc/tunnel-panel/t", slash(tdir))
		f := filepath.Join(root, id+"-down.sh")
		_ = os.WriteFile(f, []byte("#!/bin/bash\n"+down[id]), 0o755)
		if out, err := exec.Command(bash, "-n", slash(f)).CombinedOutput(); err != nil {
			t.Fatalf("bash -n: %v %s", err, out)
		}
	}
	run := func(id string, env ...string) string {
		_ = os.Remove(log)
		c := exec.Command(bash, slash(filepath.Join(root, id+"-down.sh")))
		c.Env = append(os.Environ(), env...)
		c.Env = append(c.Env, "PATH="+slash(bin)+":"+os.Getenv("PATH"))
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s down: %v %s", id, err, out)
		}
		b, _ := os.ReadFile(log)
		return string(b)
	}
	// (an MSYS bash may not see a Windows PATH entry for the stubs: then nothing is logged)
	if got := run("a"); !strings.Contains(got, "--state") {
		t.Skipf("stub firewall-cmd not on bash's PATH: %q", got)
	} else if strings.Contains(got, "--remove-rich-rule") || !strings.Contains(got, "--remove-port=443/tcp") {
		t.Fatalf("a stopped while b runs: the shared peer rule must stay:\n%s", got)
	}
	if got := run("a", "B_DOWN=1"); !strings.Contains(got, "--remove-rich-rule=rule family=ipv4 source address=198.51.100.7 accept") {
		t.Fatalf("no other tunnel runs: the peer rule must go:\n%s", got)
	}
}

func TestRestoreRefusesBenchIndex(t *testing.T) {
	for idx, ok := range map[int]bool{1: true, 249: true, 250: false, 251: false, 0: false} {
		err := checkBackup(&State{Tunnels: []*Tunnel{{ID: "t1", Family: "v4", Index: idx}}})
		if ok != (err == nil) {
			t.Errorf("index %d: err %v", idx, err)
		}
	}
}

func TestBenchIPsecHint(t *testing.T) {
	if methodByID["ipsec6"] == nil {
		t.Fatal("ipsec6 method missing")
	}
	if e := benchFailHint("ipsec6", "unit is running but no traffic passes through the tunnel"); !strings.Contains(e, "UDP 500/4500") {
		t.Fatalf("no IPsec hint: %s", e)
	}
	if e := benchFailHint("gre", "no traffic passes"); strings.Contains(e, "UDP 500") {
		t.Fatalf("hint on another method: %s", e)
	}
}

func TestUnitDescriptionEscapesPercent(t *testing.T) {
	u := renderUnit(Unit{Desc: "tunnel 100%h", ExecStart: "/bin/true"})
	if !strings.Contains(u, "Description=tunnel 100%%h\n") {
		t.Fatalf("%% not escaped:\n%s", u)
	}
}
