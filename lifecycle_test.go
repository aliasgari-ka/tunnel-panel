package main

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// lcHost records what it runs and writes; every file write fails (a deploy that breaks after
// the old method was taken down). delay slows each command; gate, when set, holds every
// write until it is closed.
type lcHost struct {
	mu     sync.Mutex
	runs   []string
	writes []string
	delay  time.Duration
	gate   chan struct{}
}

func (h *lcHost) Label() string { return "lc" }
func (h *lcHost) Run(_ context.Context, s string, _ func(string)) (string, error) {
	if h.delay > 0 {
		time.Sleep(h.delay)
	}
	h.mu.Lock()
	h.runs = append(h.runs, s)
	h.mu.Unlock()
	if strings.Contains(s, "echo TP-TEARDOWN-DONE") {
		return "TP-TEARDOWN-DONE\n", nil
	}
	return "", nil
}
func (h *lcHost) WriteFile(path string, _ []byte, _ os.FileMode) error {
	if h.gate != nil {
		<-h.gate
	}
	h.mu.Lock()
	h.writes = append(h.writes, path)
	h.mu.Unlock()
	return errors.New("disk full (test)")
}
func (h *lcHost) touched(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, x := range append(append([]string(nil), h.runs...), h.writes...) {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func lcApp(t *testing.T, tn *Tunnel, h Host) (*App, *Store) {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "192.0.2.1"}, {ID: "kh", Name: "foreign", IPv4: "198.51.100.1", Role: "foreign"}}
		if tn.Options == nil {
			tn.Options = map[string]map[string]string{}
		}
		if tn.Secrets == nil {
			tn.Secrets = map[string]string{}
		}
		s.Tunnels = []*Tunnel{tn}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, hsViews: map[string]*hsView{}}
	a.notify = func(string) {}
	a.hostFor = func(*Server) Host { return h }
	return a, st
}

func waitJob(t *testing.T, j *Job) {
	t.Helper()
	for i := 0; j.snapshot().Status == "running"; i++ {
		if i > 600 {
			t.Fatal("job still running")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Bug 1: the hourly retry of a failed hot-standby path that fails again must not touch the
// running switcher (it was redeployed and restarted every hour, losing its state).
func TestHSRetryFailedKeepsSwitcher(t *testing.T) {
	now := time.Now()
	h := &lcHost{}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1,
		Active: "gre", Selected: "gre", HotStandby: true, Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1},
			{Method: "bp_reverse", Family: "v4", Index: 2, Failed: "refused", FailedAt: now.Add(-2 * time.Hour).Unix()},
		}}
	a, st := lcApp(t, tn, h)
	j, err := a.hsRetryFailed(tn)
	if err != nil || j == nil {
		t.Fatalf("retry job: %v %v", j, err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "ok" {
		t.Fatalf("retry job %s:\n%s", s.Status, strings.Join(s.Lines, "\n"))
	}
	if h.touched(tn.ID + "hs") {
		t.Fatal("a failed retry redeployed the running switcher")
	}
	st.View(func(*State) {
		if tn.Active != "gre" || len(tn.Paths) != 2 || tn.Paths[0].Method != "gre" || tn.Paths[0].Failed != "" ||
			tn.Paths[1].Method != "bp_reverse" || tn.Paths[1].Failed == "" || tn.Paths[1].FailedAt < now.Unix() {
			t.Fatalf("paths after the failed retry: active %s, %+v", tn.Active, tn.Paths)
		}
	})
}

// Bug 2: an automatic re-apply (Repair / rebuild) that fails after the teardown leaves the
// tunnel marked as running, so the monitor and Repair keep at it; a user's Apply doesn't,
// nor an automatic one the user cancelled.
func TestAutoReapplyKeepsTunnelWanted(t *testing.T) {
	h := &lcHost{}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre"}
	a, st := lcApp(t, tn, h)
	active := func() (v, applying string) { st.View(func(*State) { v, applying = tn.Active, tn.Applying }); return }

	j, err := a.rebuildMode(tn)
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if v, ap := active(); j.snapshot().Status != "error" || v != "gre" || ap != "" {
		t.Fatalf("failed rebuild: status %s, active %q applying %q — want it still marked gre", j.snapshot().Status, v, ap)
	}

	j, _ = a.Apply(tn, "gre") // the user's own apply: a failure leaves it down as before
	waitJob(t, j)
	if v, _ := active(); v != "" {
		t.Fatalf("a user's failed apply kept active %q", v)
	}

	// cancelled by the user: their choice, not "wanted"
	_ = st.Update(func(*State) error { tn.Active = "gre"; return nil })
	h.gate = make(chan struct{})
	j, _ = a.rebuildMode(tn)
	for i := 0; i < 200; i++ {
		if v, _ := active(); v == "" {
			break // torn down, waiting in the deploy
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _ = a.jobs.cancel(j.ID)
	close(h.gate)
	time.Sleep(300 * time.Millisecond)
	if v, _ := active(); v != "" {
		t.Fatalf("a cancelled rebuild still marked the tunnel %q", v)
	}
}

// Bug 2 (resume): a resume after a restart that fails again keeps the tunnel wanted.
func TestResumeFailureKeepsTunnelWanted(t *testing.T) {
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Applying: "gre"}
	a, st := lcApp(t, tn, &lcHost{})
	j, err := a.applyRoute(tn, "gre", "v4", true)
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	st.View(func(*State) {
		if tn.Active != "gre" {
			t.Fatalf("failed resume left active %q applying %q", tn.Active, tn.Applying)
		}
	})
}

// Bug 3: a new tunnel never gets the index a hot-standby job holds for a path it deploys.
func TestNextIndexSkipsHeldPathIndex(t *testing.T) {
	hsIdxMu.Lock()
	hsIdxHeld = map[int]time.Time{}
	hsIdxMu.Unlock()
	defer func() {
		hsIdxMu.Lock()
		hsIdxHeld = map[int]time.Time{}
		hsIdxMu.Unlock()
	}()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	var held, idx int
	_ = st.Update(func(s *State) error { held = hsFreeIndex(pendingIndices(s)); return nil }) // a job picks a path index
	_ = st.Update(func(s *State) error { idx = st.nextIndexLocked(s); return nil })
	if held != 1 || idx == held || idx == 0 {
		t.Fatalf("held %d, new tunnel got %d", held, idx)
	}
}

// Bug 4: a path chosen in the panel doesn't outlive a Stop or a Start of another method,
// but a rebuild of the same method keeps it.
func TestHSPinClearedOnStopAndOtherMethod(t *testing.T) {
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre", HSPin: "golden|v4"}
	a, st := lcApp(t, tn, &lcHost{})
	pin := func() (v string) { st.View(func(*State) { v = tn.HSPin }); return }

	j, _ := a.rebuildMode(tn)
	waitJob(t, j)
	if pin() != "golden|v4" {
		t.Fatalf("a same-method rebuild dropped the pin (%q)", pin())
	}
	_ = st.Update(func(*State) error { tn.Active = "gre"; return nil })
	j, err := a.ApplyRoute(tn, "golden", "v4")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if pin() != "" {
		t.Fatalf("Start of another method kept the pin %q", pin())
	}
	_ = st.Update(func(*State) error { tn.Active, tn.HSPin = "gre", "golden|v4"; return nil })
	j, _ = a.Stop(tn)
	waitJob(t, j)
	if pin() != "" {
		t.Fatalf("Stop kept the pin %q", pin())
	}
}

// Bug 5: a stale cleanup doesn't tear a tunnel down while it is being applied, and the
// apply's own teardown drops it.
func TestCleanupSkipsTunnelBeingApplied(t *testing.T) {
	h := &lcHost{}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Applying: "gre"}
	a, st := lcApp(t, tn, h)
	_ = st.Update(func(s *State) error {
		s.Cleanups = []Cleanup{{ServerID: "ir", TunnelID: "t1", Name: "one", Indices: []int{1}, Script: cleanupScript(tn), Since: 1}}
		return nil
	})
	pending := func() (n int) { st.View(func(s *State) { n = len(s.Cleanups) }); return }
	a.runCleanups("ir")
	if len(h.runs) != 0 || pending() != 1 {
		t.Fatalf("mid-apply: %d runs, %d pending — the cleanup must wait", len(h.runs), pending())
	}
	_ = st.Update(func(*State) error { tn.Applying = ""; return nil })
	busy, _ := a.jobs.start("t1", "apply:gre") // a job on it (before Applying is set)
	a.runCleanups("ir")
	if len(h.runs) != 0 || pending() != 1 {
		t.Fatalf("job running: %d runs, %d pending", len(h.runs), pending())
	}
	a.jobs.done(busy)

	j, _ := a.Apply(tn, "gre")
	waitJob(t, j)
	if pending() != 0 {
		t.Fatal("the apply's own teardown didn't drop the stale cleanup")
	}
}

// Bug 6: when a failover's time runs out mid-apply it waits for that apply, puts the
// original back and finishes its job (it went the "cancelled by the user" way: the job
// stayed running for good and the family stayed the candidate's).
func TestFailoverDeadlineFinishes(t *testing.T) {
	oldT, oldP := failoverTimeout, applyPoll
	failoverTimeout, applyPoll = 300*time.Millisecond, 20*time.Millisecond
	defer func() { failoverTimeout, applyPoll = oldT, oldP }()
	h := &lcHost{delay: 60 * time.Millisecond}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre"}
	a, st := lcApp(t, tn, h)
	done := make(chan struct{})
	go func() { a.Failover(tn, "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("Failover never returned")
	}
	j := a.jobs.latestFor(failoverJobKey + tn.ID)
	if j == nil || j.snapshot().Status != "error" {
		t.Fatalf("failover job: %+v", j.snapshot())
	}
	if a.jobs.running(tn.ID) != "" {
		t.Fatal("an apply still runs after Failover returned")
	}
	st.View(func(*State) {
		if tn.Family != "v4" || tn.Active != "gre" || tn.Failover != nil {
			t.Fatalf("after the deadline: family %s active %q failover %+v", tn.Family, tn.Active, tn.Failover)
		}
	})
}

// Bug 7: with both families gone, no per-family "back" (or "down") alert goes out next to
// "Server unreachable".
func TestServerMonNoFamilyFlapWhenBothDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing answers on either family
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	srv := &Server{ID: "ir", Name: "iran-1", SSHHost: "127.0.0.1", IPv6: "::1", SSHPort: port}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{srv}; return nil })
	var mu sync.Mutex
	var msgs []string
	a := &App{store: st}
	a.notify = func(m string) { mu.Lock(); msgs = append(msgs, m); mu.Unlock() }
	m := &serverMon{state: map[string]*srvState{srv.ID + "/v6": {down: true, since: time.Now(), outageID: "x"}}} // IPv6 died first
	a.srvMon = m
	a.checkServer(m, srv, sshAddr(srv), 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	all := strings.Join(msgs, "\n---\n")
	mu.Unlock()
	if !strings.Contains(all, "Server unreachable") || strings.Contains(all, "IPv6 back") || strings.Contains(all, "IPv4 down") {
		t.Fatalf("alerts:\n%s", all)
	}
	if !m.state[srv.ID+"/v6"].down {
		t.Fatal("the IPv6 state flipped while neither family answered")
	}
}
