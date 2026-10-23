package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recHost records what it is asked to run.
type recHost struct {
	mu   sync.Mutex
	runs []string
}

func (h *recHost) Label() string { return "rec" }
func (h *recHost) Run(_ context.Context, s string, _ func(string)) (string, error) {
	h.mu.Lock()
	h.runs = append(h.runs, s)
	h.mu.Unlock()
	out := ""
	if strings.Contains(s, "echo TP-TEARDOWN-DONE") {
		out = "TP-TEARDOWN-DONE\n" // a real shell prints it at the end
	}
	return out, nil
}
func (h *recHost) WriteFile(string, []byte, os.FileMode) error { return nil }

// Stop while Iran is unreachable: the foreign side stops now, the Iran side as soon as it
// answers again; until then the tunnel's number isn't given to a new tunnel.
func TestCleanupWhenBack(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "192.0.2.1"}, {ID: "kh", Name: "foreign", IPv4: "198.51.100.1", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon()}
	a.notify = func(string) {}
	iranUp := false
	ir, kh := &recHost{}, &recHost{}
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir" {
			if !iranUp {
				return downHost{}
			}
			return ir
		}
		return kh
	}
	tn := st.Tunnel("t1")
	j, _ := a.Stop(tn)
	for j.snapshot().Status == "running" {
		time.Sleep(50 * time.Millisecond)
	}
	if len(kh.runs) == 0 || len(ir.runs) != 0 {
		t.Fatalf("foreign %d runs, Iran %d", len(kh.runs), len(ir.runs))
	}
	var pending []Cleanup
	st.View(func(s *State) { pending = append(pending, s.Cleanups...) })
	if len(pending) != 1 || pending[0].ServerID != "ir" || !strings.Contains(pending[0].Script, "tp-t1") {
		t.Fatalf("pending cleanup: %+v", pending)
	}
	// the tunnel is deleted; a new tunnel must not get index 1 while the leftovers sit on Iran
	_ = st.Update(func(s *State) error { s.Tunnels = nil; return nil })
	var idx int
	_ = st.Update(func(s *State) error { idx = st.nextIndexLocked(s); return nil })
	if idx == 1 {
		t.Error("index 1 reused while its leftovers are still on the Iran server")
	}
	// Iran answers again: the cleanup runs once and is forgotten
	iranUp = true
	a.runCleanups("ir")
	a.runCleanups("ir")
	if len(ir.runs) != 1 || !strings.Contains(ir.runs[0], "tp-t1") {
		t.Fatalf("Iran runs after it came back: %d", len(ir.runs))
	}
	st.View(func(s *State) { pending = s.Cleanups })
	if len(pending) != 0 {
		t.Error("cleanup not forgotten after it ran")
	}
	_ = st.Update(func(s *State) error { idx = st.nextIndexLocked(s); return nil })
	if idx != 1 {
		t.Errorf("index 1 not free again (got %d)", idx)
	}
}

// flakyHost runs everything, but refuses to write files while fail is set (a deploy that
// breaks after the old method was already taken down).
type flakyHost struct {
	recHost
	fail *atomic.Bool
}

func (h *flakyHost) WriteFile(string, []byte, os.FileMode) error {
	if h.fail.Load() {
		return errors.New("disk full (test)")
	}
	return nil
}

// Switching a running tunnel to a method that fails brings the previous one back.
func TestApplyRestoresPrevious(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "192.0.2.1"}, {ID: "kh", Name: "foreign", IPv4: "198.51.100.1", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre",
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}}
		return nil
	})
	var msgs []string
	var mu sync.Mutex
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	fail := &atomic.Bool{}
	fail.Store(true)
	h := &flakyHost{fail: fail}
	a.hostFor = func(*Server) Host { return h }
	tn := st.Tunnel("t1")
	j, err := a.ApplyRoute(tn, "golden", "v4")
	if err != nil {
		t.Fatal(err)
	}
	for j.snapshot().Status == "running" {
		time.Sleep(50 * time.Millisecond)
	}
	fail.Store(false) // the old method's deploy works
	active := func() (v string) { st.View(func(*State) { v = tn.Active }); return }
	for i := 0; i < 100 && active() != "gre"; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	all := strings.Join(msgs, "\n")
	mu.Unlock()
	t.Log(all)
	if j.snapshot().Status != "error" || active() != "gre" || !strings.Contains(all, "bringing back Plain GRE") {
		t.Fatalf("status %s, active %q", j.snapshot().Status, active())
	}
}

// reach gives up when its caller does, instead of trying every path for minutes.
func TestReachHonoursContext(t *testing.T) {
	// a port that accepts the connection and then says nothing: the SSH handshake would wait 20 s
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "127.0.0.1", SSHPort: port, Password: "x"},
			{ID: "j1", Name: "jump1", IPv4: "127.0.0.1", SSHPort: port, Prepared: true}, {ID: "j2", Name: "jump2", IPv4: "127.0.0.1", SSHPort: port, Prepared: true}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, _, err = a.reach(ctx, st.Server("ir"), nil)
	if took := time.Since(t0); err == nil || took > 4*time.Second {
		t.Fatalf("reach took %s (err %v)", took.Round(time.Millisecond), err)
	}
}
