package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// nsHost runs on one network namespace (the filesystem is shared).
type nsHost struct{ ns string }

func (h nsHost) Label() string { return h.ns }
func (h nsHost) Run(ctx context.Context, script string, log func(string)) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", h.ns, "bash", "-s")
	cmd.Stdin = strings.NewReader(scriptPrelude + script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func (h nsHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	return LocalHost{}.WriteFile(path, data, mode)
}

func TestReversePreflightNS(t *testing.T) {
	if os.Getenv("TP_NS_TEST") == "" {
		t.Skip()
	}
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}, {ID: "kh", Name: "ovh", IPv4: "10.99.0.2", Role: "foreign"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	m := methodByID["backhaul"]
	tn := &Tunnel{ID: "rv", Name: "rev", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "28579", Index: 7, Options: map[string]map[string]string{}}
	j, _ := a.jobs.start("", "t")
	ctx := context.Background()
	changed, err := a.reversePreflight(ctx, j, tn, m, nsHost{"tir"}, nsHost{"tkh"})
	for _, l := range j.snapshot().Lines {
		t.Log(l)
	}
	t.Logf("changed=%v err=%v options=%v", changed, err, tn.Options)
	if want := os.Getenv("TP_NS_WANT"); want == "error" {
		if err == nil {
			t.Fatal("expected an error")
		}
	} else if err != nil || tn.Options["backhaul"]["tunnel_port"] != want {
		t.Fatalf("want tunnel_port=%s", want)
	}
}

// Where reverse connections get lost, and a foreign server dialling from another address
// than its saved one. Run as root with TP_E2E=v4.
func TestPreflightWhereNS(t *testing.T) {
	if os.Getenv("TP_E2E") != "v4" {
		t.Skip("set TP_E2E=v4 (root, network namespaces)")
	}
	e2eTopology(t, "v4")
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}, {ID: "kh", Name: "xe105", IPv4: "10.99.0.2", Role: "foreign"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	run := func(name string) error {
		tn := &Tunnel{ID: "rv", Name: "rev", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "28579", Index: 2, Options: map[string]map[string]string{}}
		j := &Job{}
		_, err := a.reversePreflight(context.Background(), j, tn, methodByID["bp_reverse"], nsHost{"tir"}, nsHost{"tkh"})
		t.Logf("── %s → %v", name, err)
		return err
	}
	// 1. dropped before Iran (raw comes before the counting rule, like a filter upstream)
	sh(t, "ip netns exec tir iptables -w -t raw -I PREROUTING -p tcp -s 10.99.0.2 --syn -j DROP")
	if err := run("SYNs dropped before Iran"); err == nil || !strings.Contains(err.Error(), "none of its connection attempts reached") {
		t.Error("not identified as dropped on the way")
	}
	sh(t, "ip netns exec tir iptables -w -t raw -D PREROUTING -p tcp -s 10.99.0.2 --syn -j DROP")
	// 2. they reach Iran, the answers are lost
	sh(t, "ip netns exec tir iptables -w -I OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP")
	if err := run("SYN-ACKs dropped"); err == nil || !strings.Contains(err.Error(), "DID reach the Iran server") {
		t.Error("not identified as reaching Iran without an answer")
	}
	sh(t, "ip netns exec tir iptables -w -D OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP")
	// 2b. Iran's datacenter lets only its SSH port in from abroad (the user's case)
	_ = st.Update(func(s *State) error { s.Servers[0].SSHPort = 2005; return nil })
	sh(t, "ip netns exec tir iptables -w -I INPUT -p tcp --dport 2005 -j ACCEPT; ip netns exec tir setsid python3 -m http.server 2005 >/dev/null 2>&1 & sleep 1")
	sh(t, "ip netns exec tir iptables -w -t raw -I PREROUTING -p tcp -s 10.99.0.2 --syn ! --dport 2005 -j DROP")
	if err := run("only the SSH port 2005 open from abroad"); err == nil || !strings.Contains(err.Error(), "SSH port 2005 IS reachable") {
		t.Error("the only-some-ports-open case was not identified")
	}
	sh(t, "ip netns exec tir iptables -w -t raw -D PREROUTING -p tcp -s 10.99.0.2 --syn ! --dport 2005 -j DROP; pkill -f 'http.server 2005'")
	// 3. the foreign server dials from a second address; Iran's INPUT policy is DROP
	sh(t, "ip -n tkh addr add 10.99.0.9/24 dev vkh; ip -n tkh route add 10.99.0.1/32 dev vkh src 10.99.0.9")
	if err := run("foreign leaves from 10.99.0.9 (saved 10.99.0.2)"); err != nil {
		t.Error("a foreign server with another source address must pass")
	}
	if n := sh(t, "ip netns exec tir iptables-save | grep -c tp-preflight"); n != "0" {
		t.Errorf("%s preflight rules left", n)
	}
}
