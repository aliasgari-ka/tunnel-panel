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
