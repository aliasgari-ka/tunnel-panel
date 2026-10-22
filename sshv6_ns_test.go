package main

// SSH over IPv6 when IPv4 is disrupted, against a real SSH server in network namespaces:
// the Iran namespace runs a tiny SSH server (this test binary, TestHelperSSHServer), the
// test itself runs in the foreign namespace as the panel. Run as root with TP_SSH6_E2E=1
// (the test re-executes itself under ip netns exec).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestHelperSSHServer is the SSH server side (any password, exec runs bash -c).
func TestHelperSSHServer(t *testing.T) {
	if os.Getenv("TP_SSH_HELPER") == "" {
		t.Skip("helper process")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "[::]:2005")
	if err != nil {
		t.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			_, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				ch, rq, err := nc.Accept()
				if err != nil {
					continue
				}
				go func() {
					for r := range rq {
						if r.Type == "exec" {
							cmd := string(r.Payload[4:])
							_ = r.Reply(true, nil)
							x := exec.Command("bash", "-c", cmd)
							x.Stdin, x.Stdout, x.Stderr = ch, ch, ch.Stderr() // the panel sends its script on stdin
							_ = x.Run()
							_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
							return
						}
						_ = r.Reply(r.Type == "env", nil)
					}
				}()
			}
		}(c)
	}
}

func TestSSHv6FallbackNS(t *testing.T) {
	if os.Getenv("TP_SSH6_E2E") == "" {
		t.Skip("set TP_SSH6_E2E=1 (root, network namespaces)")
	}
	if os.Getenv("TP_SSH6_INNER") == "" {
		// set up, then run the panel side inside the foreign namespace
		e2eTopology(t, "v6")
		defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")
		sh(t, "ip -n tir addr add 10.99.0.1/24 dev vir; ip -n tkh addr add 10.99.0.2/24 dev vkh")
		sh(t, "ip netns exec tir iptables -w -I INPUT -p tcp --dport 2005 -j ACCEPT; ip netns exec tir ip6tables -w -I INPUT -p tcp --dport 2005 -j ACCEPT")
		self, _ := os.Executable()
		srv := exec.Command("ip", "netns", "exec", "tir", "env", "TP_SSH_HELPER=1", self, "-test.run", "TestHelperSSHServer")
		_ = srv.Start()
		defer srv.Process.Kill()
		time.Sleep(time.Second)
		out, err := exec.Command("ip", "netns", "exec", "tkh", "env", "TP_SSH6_E2E=1", "TP_SSH6_INNER=1", self, "-test.run", "TestSSHv6FallbackNS", "-test.v").CombinedOutput()
		t.Log("\n" + string(out))
		if err != nil {
			t.Fail()
		}
		return
	}
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	srv := &Server{ID: "ir", Name: "iran-1", IPv4: "10.99.0.1", IPv6: "2001:db8:99::1", SSHPort: 2005, Password: "x"}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{srv}; return nil })
	var mu sync.Mutex
	var msgs []string
	a := &App{store: st, jobs: newJobs()}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	mon := &serverMon{state: map[string]*srvState{}}
	a.srvMon = mon
	ctx := context.Background()
	runOn := func(step string) {
		dropHost("ir")
		h, path, err := a.reach(ctx, st.Server("ir"), nil)
		if err != nil {
			t.Errorf("%s: no path: %v", step, err)
			return
		}
		out, err := h.Run(ctx, "echo hi-from-$(hostname -s 2>/dev/null || echo iran)", nil)
		t.Logf("%s: reached via %q → %q %v", step, path, strings.TrimSpace(out), err)
		if !strings.Contains(out, "hi-from") {
			t.Errorf("%s: command didn't run", step)
		}
	}
	check := func() { a.checkServer(mon, st.Server("ir"), sshAddr(st.Server("ir")), 200*time.Millisecond) }
	nsRun := func(c string) { _ = exec.Command("ip", "netns", "exec", "tir", "bash", "-c", c).Run() }

	runOn("both families up")
	check()
	// IPv4 SSH disrupted (like the Iran outage): the panel must manage it over IPv6
	nsRun("iptables -w -t raw -I PREROUTING -p tcp --dport 2005 -j DROP")
	check()
	runOn("IPv4 dropped")
	if !a.serverReachable("ir") {
		t.Error("server reported down although IPv6 SSH works")
	}
	// IPv6 too: now the server is down
	nsRun("ip6tables -w -t raw -I PREROUTING -p tcp --dport 2005 -j DROP")
	check()
	if a.serverReachable("ir") {
		t.Error("server reported up although neither family answers")
	}
	nsRun("iptables -w -t raw -D PREROUTING -p tcp --dport 2005 -j DROP; ip6tables -w -t raw -D PREROUTING -p tcp --dport 2005 -j DROP")
	time.Sleep(1100 * time.Millisecond)
	check()
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	all := strings.Join(msgs, "\n---\n")
	mu.Unlock()
	t.Log("\nTelegram messages:\n" + all)
	for _, want := range []string{"🟠 SSH over IPv4 down: iran-1 (IPv4)", "IPv6 ([2001:db8:99::1]:2005) works", "🔴 Server unreachable: iran-1", "🟢 Server reachable again: iran-1"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
	_ = fmt.Sprint
}
