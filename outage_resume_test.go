package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A restart of the panel takes up the outages it left open: the same entry ends when the
// server is back, and a server still down goes on in it — no new entry, no second alert.
// Before, every restart closed them at the restart's time and opened new ones.
func TestServerOutageSurvivesRestart(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // down
	srv := &Server{ID: "ir", Name: "iran-1", SSHHost: "127.0.0.1", SSHPort: port}
	start := time.Now().Add(-2 * time.Hour).Unix()
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{srv}
		s.Outages = []Outage{
			{ID: "a", Kind: "server", Target: "ir", Name: "iran-1", Start: start, Reason: "x"},
			{ID: "b", Kind: "ssh-v4", Target: "gone/v4", Name: "old (IPv4)", Start: start, Reason: "y"}, // its server was deleted
			{ID: "c", Kind: "server", Target: "ir", Name: "iran-1", Start: start + 60, Reason: "x"},     // a duplicate the old way left
			{ID: "d", Kind: "tunnel", Target: "t1", Name: "tun", Start: start, Reason: "z"},             // not the server monitor's
		}
		return nil
	})
	var msgs []string
	a := &App{store: st}
	a.notify = func(m string) { msgs = append(msgs, m) }
	m := &serverMon{state: map[string]*srvState{}}
	m.resume(a)
	a.srvMon = m
	if a.serverReachable("ir") {
		t.Fatal("a server with an open outage is taken for up before its first check")
	}
	a.checkServer(m, srv, sshAddr(srv), 10*time.Millisecond) // still down
	get := func() map[string]Outage {
		r := map[string]Outage{}
		st.View(func(s *State) {
			for _, o := range s.Outages {
				r[o.ID] = o
			}
		})
		return r
	}
	os := get()
	if len(os) != 4 {
		t.Fatalf("a new entry was opened for a server still down: %+v", os)
	}
	if os["a"].End != 0 || os["d"].End != 0 {
		t.Errorf("the open outage was closed: %+v / %+v", os["a"], os["d"])
	}
	if os["b"].End == 0 || os["c"].End == 0 {
		t.Errorf("outages of a deleted server / a duplicate stay open: %+v / %+v", os["b"], os["c"])
	}
	ln2, err := net.Listen("tcp", sshAddr(srv))
	if err != nil {
		t.Skip("port taken:", err)
	}
	defer ln2.Close()
	a.checkServer(m, srv, sshAddr(srv), 10*time.Millisecond) // back
	os = get()
	if len(os) != 4 || os["a"].End == 0 || os["a"].Start != start || strings.Contains(os["a"].Reason, "restarted") {
		t.Errorf("the same entry should end with its real end: %+v", os["a"])
	}
}

func TestTunnelOutageSurvivesRestart(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	start := time.Now().Add(-time.Hour).Unix()
	_ = st.Update(func(s *State) error {
		s.Tunnels = []*Tunnel{{ID: "t1", Name: "a", Active: "gre"}, {ID: "t2", Name: "b"}}
		s.Outages = []Outage{
			{ID: "a", Kind: "tunnel", Target: "t1", Start: start},
			{ID: "b", Kind: "tunnel", Target: "t2", Start: start}, // stopped meanwhile
			{ID: "c", Kind: "tunnel", Target: "t3", Start: start}, // deleted
			{ID: "d", Kind: "server", Target: "ir", Start: start}, // not the tunnel monitor's
		}
		return nil
	})
	a := &App{store: st}
	now := time.Now()
	state := resumeTunnelOutages(a, now)
	h := state["t1"]
	if len(state) != 1 || h == nil || h.outageID != "a" || !h.alerted || h.downSince.Unix() != start {
		t.Fatalf("state: %+v", state)
	}
	// the next failover is due failoverAfter from now, not at once
	if d := failoverRetry - now.Sub(h.failoverAt); d != failoverAfter {
		t.Errorf("next failover in %s, want %s", d, failoverAfter)
	}
	if h.step("", now) != "up" {
		t.Error("a resumed outage should end with \"up\" at the first good check")
	}
	st.View(func(s *State) {
		for _, o := range s.Outages {
			if (o.ID == "a" || o.ID == "d") != (o.End == 0) {
				t.Errorf("outage %s: end %d", o.ID, o.End)
			}
		}
	})
}

// IPv4-only / IPv6-only outages have their own room: a flapping family can't push the real
// outages out of the log; open ones are never dropped.
func TestTrimOutagesKeepsRealOnes(t *testing.T) {
	var all []Outage
	all = append(all, Outage{ID: "open-fam", Kind: "ssh-v4", Start: 1})
	for i := 0; i < maxOutageLogs; i++ {
		all = append(all, Outage{Kind: "server", Start: int64(10 + i), End: int64(11 + i)})
	}
	for i := 0; i < 500; i++ {
		all = trimOutages(append(all, Outage{Kind: "ssh-v6", Start: int64(1000 + i), End: int64(1001 + i)}))
	}
	var real, fam int
	open := false
	for _, o := range all {
		if familyOutage(o.Kind) {
			fam++
		} else {
			real++
		}
		open = open || o.ID == "open-fam"
	}
	if real != maxOutageLogs || fam != maxFamilyLogs || !open {
		t.Errorf("real %d fam %d open kept %v", real, fam, open)
	}
	if all[len(all)-1].Start != 1499 {
		t.Error("the newest was dropped")
	}
}
