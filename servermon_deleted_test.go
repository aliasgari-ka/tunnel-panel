package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// A server deleted while a monitor round was checking it: the round's late "down" must not
// open a new outage (nothing would ever end it) nor alert about the deleted server. Live, the
// delete ended the old outage at 17:51:29 and the check under way opened one at 17:51:17
// that stayed open 3 days, until the panel restarted.
func TestServerDeletedDuringCheck(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	// port 1 (tcpmux): nothing listens there, the server is down — a freed ephemeral port
	// was taken again by another test of the full run
	srv := &Server{ID: "goneDelTest", Name: "old box", SSHHost: "127.0.0.1", SSHPort: 1}
	keep := &Server{ID: "keptDelTest", Name: "kept", SSHHost: "127.0.0.1", SSHPort: 1}
	addr := sshAddr(srv)
	_ = st.Update(func(s *State) error { s.Servers = []*Server{keep}; return nil }) // "gone" already deleted
	var mu sync.Mutex
	var msgs []string
	a := &App{store: st}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	m := &serverMon{state: map[string]*srvState{}}
	a.srvMon = m
	a.forgetServerMon("goneDelTest")

	a.checkServer(m, srv, addr, time.Millisecond) // the round's copy of the deleted server
	a.checkServer(m, keep, addr, time.Millisecond)
	time.Sleep(100 * time.Millisecond) // push is async

	var open []string
	st.View(func(s *State) {
		for _, o := range s.Outages {
			if o.End == 0 {
				open = append(open, o.Target)
			}
		}
	})
	if strings.Join(open, ",") != "keptDelTest" {
		t.Errorf("open outages %v, want only keptDelTest", open)
	}
	if !a.serverReachable("goneDelTest") {
		t.Error("monitor keeps the deleted server as down")
	}
	mu.Lock()
	all := strings.Join(msgs, "\n")
	mu.Unlock()
	if strings.Contains(all, "old box") || !strings.Contains(all, "kept") {
		t.Errorf("alerts: %s", all)
	}
}
