package main

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServerMonitor(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	srv := &Server{ID: "ir", Name: "iran-1", SSHHost: "127.0.0.1", SSHPort: port}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{srv}; return nil })
	var mu sync.Mutex
	var msgs []string
	a := &App{store: st}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	m := &serverMon{state: map[string]*srvState{}}
	a.srvMon = m
	addr := sshAddr(srv)

	a.checkServer(m, srv, addr, 10*time.Millisecond) // up: nothing to say
	ln.Close()
	a.checkServer(m, srv, addr, 10*time.Millisecond) // down
	if a.serverReachable("ir") {
		t.Fatal("still reachable after the port closed")
	}
	tn := &Tunnel{ID: "t", Name: "x", ServerID: "ir", ForeignID: ""}
	if c := a.tunnelCause(tn); !strings.Contains(c, "Iran server iran-1 doesn't answer") {
		t.Errorf("cause: %s", c)
	}
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skip("port taken again:", err)
	}
	defer ln2.Close()
	time.Sleep(1100 * time.Millisecond)
	a.checkServer(m, srv, addr, 10*time.Millisecond) // back
	if c := a.tunnelCause(tn); !strings.Contains(c, "the tunnel itself") {
		t.Errorf("cause when servers answer: %s", c)
	}
	time.Sleep(100 * time.Millisecond) // push is async
	mu.Lock()
	all := strings.Join(msgs, "\n---\n")
	mu.Unlock()
	for _, want := range []string{"🔴 Server unreachable: iran-1", "since 20", "(Tehran)", "🟢 Server reachable again: iran-1", "down 1s"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	var os []Outage
	st.View(func(s *State) { os = append(os, s.Outages...) })
	if len(os) != 1 || os[0].End == 0 || os[0].Kind != "server" {
		t.Errorf("outage log: %+v", os)
	}
	t.Log("\n" + all)
}

func TestProbePlan(t *testing.T) {
	cases := []struct {
		pool4, pool6, alive, full bool
		want4, want6              bool
	}{
		{false, false, false, false, true, true},  // nothing known: connect to both ports, as before
		{true, false, true, false, false, false},  // direct IPv4 open: nothing to connect to...
		{true, false, true, true, false, true},    // ...except IPv6 on a full round
		{false, false, true, false, false, false}, // alive over a jump host or the agent: full rounds only
		{false, false, true, true, true, true},
		{true, true, true, true, false, false}, // both families open: never
	}
	for _, c := range cases {
		p4, p6 := probePlan(c.pool4, c.pool6, c.alive, c.full)
		if p4 != c.want4 || p6 != c.want6 {
			t.Errorf("probePlan(%v %v %v %v) = %v %v, want %v %v", c.pool4, c.pool6, c.alive, c.full, p4, p6, c.want4, c.want6)
		}
	}
}
