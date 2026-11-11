package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// h2Host: a scriptable fake host; fn, when set, answers a command first.
type h2Host struct {
	name   string
	mu     sync.Mutex
	runs   []string
	writes []string
	fn     func(ctx context.Context, s string) (string, error, bool)
}

func (h *h2Host) Label() string { return h.name }
func (h *h2Host) Run(ctx context.Context, s string, _ func(string)) (string, error) {
	h.mu.Lock()
	h.runs = append(h.runs, s)
	fn := h.fn
	h.mu.Unlock()
	if fn != nil {
		if out, err, ok := fn(ctx, s); ok {
			return out, err
		}
	}
	switch {
	case strings.Contains(s, "echo TP-TEARDOWN-DONE"):
		return "TP-TEARDOWN-DONE\n", nil
	case strings.HasPrefix(s, "uname -m"):
		return "x86_64\n", nil
	case strings.Contains(s, "echo OK ") && strings.Contains(s, "probe rtt"):
		return "", nil
	case strings.Contains(s, "probe rtt"):
		return `{"rttMs":5,"jitterMs":1}`, nil
	case strings.Contains(s, "probe bw"):
		return `{"mbps":50}`, nil
	case strings.Contains(s, "echo probe-up"):
		return "probe-up\n", nil
	}
	return "", nil
}
func (h *h2Host) WriteFile(path string, _ []byte, _ os.FileMode) error {
	h.mu.Lock()
	h.writes = append(h.writes, path)
	h.mu.Unlock()
	return nil
}
func (h *h2Host) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.runs...)
}

// h2SwFail fails the upload of the hot-standby switcher (and marks where in runs).
type h2SwFail struct{ h2Host }

func (h *h2SwFail) WriteFile(path string, b []byte, m os.FileMode) error {
	if strings.Contains(path, "hs/switch.sh") {
		h.mu.Lock()
		h.runs = append(h.runs, "WRITE-FAIL "+path)
		h.mu.Unlock()
		return errors.New("connection lost (test)")
	}
	return h.h2Host.WriteFile(path, b, m)
}

func h2App(t *testing.T, tn *Tunnel, ir, kh Host) (*App, *Store) {
	t.Helper()
	a, st := lcApp(t, tn, ir)
	a.hostFor = func(s *Server) Host {
		if s.ID == "kh" {
			return kh
		}
		return ir
	}
	_ = os.MkdirAll(filepath.Join(dataDir, "helpers"), 0o755)
	_ = os.WriteFile(filepath.Join(dataDir, "helpers", "tp-agent-amd64"), []byte("probe"), 0o755)
	return a, st
}

// the foreign deploy fails: what it installed (unit enabled, Restart=always) is taken down again.
func TestHunt2CoreKHDeployFailTearsDown(t *testing.T) {
	ir, kh := &h2Host{name: "ir"}, &h2Host{name: "kh"}
	kh.fn = func(_ context.Context, s string) (string, error, bool) {
		if strings.Contains(s, "systemctl restart tp-") {
			return "unit tp-t1.service: activating\n", errors.New("Process exited with status 1"), true
		}
		return "", nil, false
	}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1}
	a, _ := h2App(t, tn, ir, kh)
	j, err := a.Apply(tn, "gre")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "error" {
		t.Fatalf("apply ended %s", s.Status)
	}
	runs := kh.snapshot()
	failAt := -1
	for i, r := range runs {
		if strings.Contains(r, "systemctl restart tp-t1.service") {
			failAt = i
		}
	}
	if failAt < 0 {
		t.Fatal("the deploy script never ran on the foreign host")
	}
	tornDown := false
	for _, r := range runs[failAt+1:] {
		tornDown = tornDown || strings.Contains(r, "systemctl disable --now")
	}
	if !tornDown {
		t.Error("the foreign unit stays installed and enabled after its failed start")
	}
}

// a failed ApplyRoute to another family before anything was torn down keeps the old family.
func TestHunt2CoreFamilyRestored(t *testing.T) {
	ir := &h2Host{name: "ir"}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre"}
	a, st := lcApp(t, tn, ir)
	_ = st.Update(func(s *State) error {
		s.Servers[0].IPv6, s.Servers[1].IPv6 = "2001:db8::1", "2001:db8::2"
		return nil
	})
	a.hostFor = func(s *Server) Host { // the foreign server can't be reached
		if s.ID == "kh" {
			return nil
		}
		return ir
	}
	j, err := a.ApplyRoute(tn, "gre", "v6")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "error" {
		t.Fatalf("apply ended %s", s.Status)
	}
	for _, r := range ir.snapshot() {
		if strings.Contains(r, "systemctl disable --now") {
			t.Fatal("the running tunnel was torn down — the test expects a failure before that")
		}
	}
	var fam, active string
	for i := 0; i < 100; i++ {
		st.View(func(*State) { fam, active = tn.Family, tn.Active })
		if fam == "v4" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if active != "gre" || fam != "v4" {
		t.Errorf("gre still runs over v4 on the servers, the panel records active=%q family=%q", active, fam)
	}
}

// Failback: the user stops the tunnel while the check of the original path runs.
func TestHunt2CoreFailbackAfterStop(t *testing.T) {
	old := applyPoll
	applyPoll = 20 * time.Millisecond
	defer func() { applyPoll = old }()
	ir, kh := &h2Host{name: "ir"}, &h2Host{name: "kh"}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "wg", Selected: "wg",
		Failover: &FailoverState{Method: "gre", Family: "v4", Since: time.Now().Add(-2 * time.Hour).Unix()}}
	a, st := h2App(t, tn, ir, kh)
	var once sync.Once
	ir.fn = func(_ context.Context, s string) (string, error, bool) {
		if strings.Contains(s, "probe bw -down") {
			once.Do(func() { // what tunnelStop does
				a.clearFailover(tn)
				sj, err := a.Stop(tn)
				if err != nil {
					t.Errorf("stop: %v", err)
					return
				}
				for sj.snapshot().Status == "running" {
					time.Sleep(5 * time.Millisecond)
				}
			})
		}
		return "", nil, false
	}
	a.Failback(tn)
	var act string
	st.View(func(*State) { act = tn.Active })
	if act != "" {
		t.Errorf("the tunnel the user stopped was started again by Failback (now running %q)", act)
	}
	if j := a.jobs.latestFor("bench"); j == nil || j.snapshot().Status != "cancelled" {
		t.Errorf("Stop did not cancel the running fail-back check")
	}
}

// a cancelled benchmark keeps the method's earlier result and writes no history.
func TestHunt2CoreBenchCancelKeepsResult(t *testing.T) {
	ir, kh := &h2Host{name: "ir"}, &h2Host{name: "kh"}
	reached := make(chan struct{})
	var once sync.Once
	kh.fn = func(ctx context.Context, s string) (string, error, bool) {
		if strings.Contains(s, "systemctl restart tp-bench") {
			once.Do(func() { close(reached) })
			<-ctx.Done()
			return "", ctx.Err(), true
		}
		return "", nil, false
	}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1}
	a, _ := h2App(t, tn, ir, kh)
	a.setBench("ir", "kh", "v4", []BenchResult{{Method: "gre", Title: "Plain GRE", OK: true, Kind: "l3", Mbps: 80, DownMbps: 80, UpMbps: 80, Score: 180}})
	j, err := a.Bench(BenchRequest{IranID: "ir", ForeignID: "kh", Family: "v4", Methods: []string{"gre"}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("bench never deployed")
	}
	_, _ = a.jobs.cancel(j.ID)
	for i := 0; a.jobs.running("bench") != "" && i < 500; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	rs := a.benchResults("ir", "kh", "v4")
	if len(rs) != 1 || !rs[0].OK || rs[0].Error != "" {
		t.Errorf("cancelling the benchmark changed gre's good result: %+v", rs)
	}
	var hist int
	a.store.View(func(st *State) { hist = len(st.BenchHistory) })
	if hist != 0 {
		t.Errorf("a cancelled benchmark wrote %d history records", hist)
	}
}

// goldenConflict: (a) the tunnel's own Golden-GRE path is no conflict with the tunnel;
// (b) another tunnel's Golden-GRE standby path is one.
func TestHunt2CoreGoldenConflict(t *testing.T) {
	ir := &h2Host{name: "ir"}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1,
		Active: "golden", Selected: "golden", HotStandby: true, Paths: []HSPath{
			{Method: "golden", Family: "v4", Index: 1},
			{Method: "gre", Family: "v4", Index: 2},
		}}
	a, st := h2App(t, tn, ir, ir)
	var c string
	st.View(func(s *State) { c = goldenConflict(s, pathTunnel(tn, tn.Paths[0])) })
	if c != "" {
		t.Errorf("(a) the tunnel's own Golden-GRE path conflicts with the tunnel itself (%q)", c)
	}
	if _, _, err := a.build(methodByID["golden"], pathTunnel(tn, tn.Paths[0]), a.store.Server("ir")); err != nil && strings.Contains(err.Error(), "already runs Golden-GRE") {
		t.Errorf("(a) build refused the tunnel's own path: %v", err)
	}

	_ = st.Update(func(s *State) error {
		tn.Active, tn.Selected = "gre", "gre"
		tn.Paths = []HSPath{{Method: "gre", Family: "v4", Index: 1}, {Method: "golden", Family: "v4", Index: 2}}
		return nil
	})
	b := &Tunnel{ID: "bbbbbbbbbbbb", Name: "b", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "8443", Index: 3}
	st.View(func(s *State) { c = goldenConflict(s, b) })
	if c != "uk" {
		t.Errorf("(b) another tunnel's running Golden-GRE standby path is not seen (conflict %q)", c)
	}
	// a failed one doesn't run
	_ = st.Update(func(s *State) error { tn.Paths[1].Failed = "refused"; return nil })
	st.View(func(s *State) { c = goldenConflict(s, b) })
	if c != "" {
		t.Errorf("a failed Golden-GRE path counted as running (%q)", c)
	}
}

// concurrent reach() of one server: one SSH connection, none left open after dropHost.
func TestHunt2CoreReachNoLeak(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	port, open := countingSSHD(t)
	tgt := &Server{ID: "tgtleak2", Name: "tgt", IPv4: "127.0.0.1", SSHPort: port, Password: "x"}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{tgt}; return nil })
	a := &App{store: st, jobs: newJobs()}
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	hosts := make([]Host, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h, _, err := a.reach(context.Background(), tgt, nil)
			if err != nil {
				t.Errorf("reach: %v", err)
			}
			hosts[i] = h
		}(i)
	}
	close(start)
	wg.Wait()
	time.Sleep(300 * time.Millisecond)
	if during := open.Load(); during != 1 {
		t.Errorf("%d concurrent reach() calls opened %d SSH connections, want 1", n, during)
	}
	for _, h := range hosts[1:] {
		if h != hosts[0] {
			t.Errorf("the callers got different hosts")
			break
		}
	}
	dropHost(tgt.ID)
	time.Sleep(time.Second)
	if left := open.Load(); left > 0 {
		t.Errorf("%d SSH connections leaked", left)
	}
}

// a preflight that moves a path's tunnel port keeps only that key in the path's options.
func TestHunt2CorePathOptsMovedKeyOnly(t *testing.T) {
	cacheDir = t.TempDir()
	_ = os.WriteFile(filepath.Join(cacheDir, "backhaul-v0.7.2-amd64"), []byte("bin"), 0o755)
	hsOnly = []string{"gre", "backhaul"}
	defer func() { hsOnly = nil }()
	ir, kh := &h2Host{name: "ir"}, &h2Host{name: "kh"}
	kh.fn = func(_ context.Context, s string) (string, error, bool) {
		if strings.Contains(s, "echo OK ") && strings.Contains(s, "probe rtt") {
			return "OK 8443\n", nil, true // only 8443 gets through from abroad
		}
		return "", nil, false
	}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, HotStandby: true,
		Options: map[string]map[string]string{"backhaul": {"transport": "tcp", "mux_con": "8"}}}
	a, st := h2App(t, tn, ir, kh)
	j, err := a.Apply(tn, "gre")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "ok" {
		t.Fatalf("apply %s:\n%s", s.Status, strings.Join(s.Lines, "\n"))
	}
	var bh HSPath
	st.View(func(*State) {
		for _, p := range tn.Paths {
			if p.Method == "backhaul" {
				bh = p
			}
		}
	})
	if bh.Opts["tunnel_port"] != "8443" {
		t.Fatalf("the moved tunnel port is not kept in the path: %v", bh.Opts)
	}
	if _, ok := bh.Opts["transport"]; ok {
		t.Errorf("the path froze options the preflight didn't move: %v", bh.Opts)
	}
	_ = st.Update(func(*State) error { tn.setOption("backhaul", "transport", "wsmux"); return nil })
	if got := pathTunnel(tn, bh).Options["backhaul"]["transport"]; got != "wsmux" {
		t.Errorf("the path keeps transport %q — the user's change never reaches it", got)
	}
}

func TestHunt2CoreMovedOpts(t *testing.T) {
	got := movedOpts(map[string]string{"a": "1"}, map[string]string{"t": "tcp", "p": ""}, map[string]string{"a": "1", "t": "tcp", "p": "8443"})
	if len(got) != 2 || got["a"] != "1" || got["p"] != "8443" {
		t.Errorf("movedOpts = %v", got)
	}
}

// the tunnel ports of another tunnel's hot-standby paths (a moved one too) count as taken.
func TestHunt2CorePortClashSeesPaths(t *testing.T) {
	a := &Tunnel{ID: "aaaaaaaaaaaa", Name: "A", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", HotStandby: true,
		Options: map[string]map[string]string{}, Paths: []HSPath{{Method: "gre", Family: "v4", Index: 1},
			{Method: "backhaul", Family: "v4", Index: 2, Opts: map[string]string{"tunnel_port": "8443"}},
			{Method: "frp", Family: "v4", Index: 5}}}
	b := &Tunnel{ID: "bbbbbbbbbbbb", Name: "B", ServerID: "ir", ForeignID: "kh2", Family: "v4", Ports: "8443", Index: 3, Options: map[string]map[string]string{}}
	st := &State{Tunnels: []*Tunnel{a, b}}
	if err := portClash(st, b, "gre"); err == nil {
		t.Error("no clash with A's backhaul path on Iran:8443")
	}
	if _, ok := iranPorts(a, "")[40000+5*4]; !ok {
		t.Error("the frp path's own tunnel port is not counted")
	}
	// the tunnel's own path is no clash with the tunnel
	if err := portClash(&State{Tunnels: []*Tunnel{a}}, pathTunnel(a, a.Paths[1]), "backhaul"); err != nil {
		t.Errorf("a path clashes with its own tunnel: %v", err)
	}
}

// TP Tunnel / TP Reverse: Iran's tunnel port is opened and counted, and preflighted (TCP).
func TestHunt2CoreTPKListenPort(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.1", Arch: "x86_64"}
	for _, c := range []struct {
		mid, transport string
		rev            bool
	}{{"tpk", "", true}, {"tpk", "udp", false}, {"tpk_rev", "", true}} {
		tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: c.mid,
			Options: map[string]map[string]string{}, Secrets: map[string]string{}}
		if c.transport != "" {
			tn.setOption(c.mid, "transport", c.transport)
		}
		irP, _, err := buildPlans(methodByID[c.mid], tn, srv, fsrv, Settings{})
		if err != nil {
			t.Fatalf("%s: %v", c.mid, err)
		}
		fw := string(irP.Files["/etc/tunnel-panel/t/t1/fw-in-up.sh"].Content)
		if !strings.Contains(fw, "--dport 40004 -j ACCEPT") {
			t.Errorf("%s/%s: Iran's tunnel port 40004 is not opened", c.mid, c.transport)
		}
		_, held := iranPorts(tn, "")[40004]
		if held != c.rev {
			t.Errorf("%s/%s: tunnel port counted in iranPorts=%v, want %v", c.mid, c.transport, held, c.rev)
		}
		if key, rev := reverseTCPPort(methodByID[c.mid], tn); rev != c.rev || (rev && key != "port") {
			t.Errorf("%s/%s: reverseTCPPort = %q %v", c.mid, c.transport, key, rev)
		}
	}
}

// Trace on a tunnel without ports: an error, not an index-out-of-range panic.
func TestHunt2CoreTraceNoPorts(t *testing.T) {
	ir := &h2Host{name: "ir"}
	tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "", Index: 1, Active: "gre", Selected: "gre"}
	a, _ := h2App(t, tn, ir, ir)
	j, err := a.Trace(tn, 10)
	if err == nil || !strings.Contains(err.Error(), "no ports") {
		t.Errorf("Trace without ports: job %v, err %v", j, err)
	}
}

// limitedSSHD: an SSH server that, like sshd's MaxSessions, refuses session channels beyond
// max. Every accepted "exec" hangs until release is closed; started counts them.
func limitedSSHD(t *testing.T, max int32, release chan struct{}, started *atomic.Int32) (port int) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
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
				var cur atomic.Int32
				for nc := range chans {
					if nc.ChannelType() != "session" || cur.Load() >= max {
						_ = nc.Reject(ssh.Prohibited, "open failed")
						continue
					}
					cur.Add(1)
					ch, rq, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer cur.Add(-1)
						for r := range rq {
							if r.Type == "exec" {
								_ = r.Reply(true, nil)
								started.Add(1)
								in := make(chan struct{})
								go func() { _, _ = io.Copy(io.Discard, ch); close(in) }()
								<-release
								<-in // the whole script was read (closing before that fails the client's stdin copy)
								_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								ch.Close()
								return
							}
							_ = r.Reply(false, nil)
						}
					}()
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func h2SSHHost(t *testing.T, max int32, release chan struct{}, started *atomic.Int32) Host {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	srv := &Server{ID: "lim" + strings.ReplaceAll(t.Name(), "/", ""), Name: "lim", IPv4: "127.0.0.1", SSHPort: limitedSSHD(t, max, release, started), Password: "x"}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{srv}; return nil })
	a := &App{store: st, jobs: newJobs()}
	h, _, err := a.reach(context.Background(), srv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropHost(srv.ID) })
	return h
}

// runBusy starts n hanging commands on h; the returned channel gets their errors.
func runBusy(h Host, n int) chan error {
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := h.Run(context.Background(), "long deploy script", nil)
			errc <- err
		}()
	}
	return errc
}

// a session the server refuses (MaxSessions) leaves the connection and its commands alone.
func TestHunt2CoreRefusedSessionKeepsConnection(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	h := h2SSHHost(t, 3, release, &started)
	errc := runBusy(h, 3)
	for i := 0; started.Load() < 3 && i < 250; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.Run(ctx, "one more status check", nil); err == nil {
		t.Fatal("the server should have refused the 4th session")
	}
	left := 3
	select {
	case err := <-errc:
		t.Errorf("a refused session ended a running command: %v", err)
		left--
	case <-time.After(500 * time.Millisecond):
	}
	close(release)
	waitErrs(t, errc, left)
}

// waitErrs reads n command results, failing on errors (and on a hang).
func waitErrs(t *testing.T, errc chan error, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("command: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%d commands still running", n-i)
		}
	}
}

// at most sshSessions sessions at once: the next waits (and honours its ctx) instead of
// being refused by sshd's MaxSessions.
func TestHunt2CoreSessionCap(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	h := h2SSHHost(t, 10, release, &started)
	errc := runBusy(h, 10)
	time.Sleep(700 * time.Millisecond)
	if n := started.Load(); n != sshSessions {
		t.Errorf("%d sessions run at once, want %d", n, sshSessions)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := h.Run(ctx, "status", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a command waiting for a session slot: %v, want its deadline", err)
	}
	close(release)
	waitErrs(t, errc, 10)
	if n := started.Load(); n != 10 {
		t.Errorf("%d of 10 commands ran", n)
	}
}

// hsUpdatePathsRun: the switcher deploy fails — the panel keeps the running switcher's state.
func TestHunt2CorePathUpdateSwitcherFails(t *testing.T) {
	hsOnly = []string{"gre", "wg"}
	defer func() { hsOnly = nil }()
	ir := &h2SwFail{h2Host{name: "ir"}}
	kh := &h2Host{name: "kh"}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1,
		Active: "gre", Selected: "gre", HotStandby: true, HSPin: "wg|v4", Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1}, {Method: "wg", Family: "v4", Index: 2}}}
	a, st := h2App(t, tn, ir, kh)
	a.setRouteSkip("ir", "kh", "gre", "v4", true)
	j, err := a.hsUpdatePaths(tn)
	if err != nil || j == nil {
		t.Fatalf("update job: %v %v", j, err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status == "ok" {
		t.Fatal("the update should have failed at the switcher")
	}
	var act, fam, pin string
	var keys []string
	st.View(func(*State) {
		act, fam, pin = tn.Active, tn.Family, tn.HSPin
		for _, p := range tn.Paths {
			keys = append(keys, p.String())
		}
	})
	if act != "gre" || fam != "v4" || pin != "wg|v4" || strings.Join(keys, " ") != "gre|v4 wg|v4" {
		t.Errorf("after the failed switcher update: active=%q family=%q pin=%q paths %v", act, fam, pin, keys)
	}
}

// applyHot: the switcher fails to deploy — the paths it would have used stop again.
func TestHunt2CoreApplyHotSwitcherFailTearsDown(t *testing.T) {
	hsOnly = []string{"gre", "wg"}
	defer func() { hsOnly = nil }()
	ir := &h2SwFail{h2Host{name: "ir"}}
	kh := &h2Host{name: "kh"}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, HotStandby: true}
	a, _ := h2App(t, tn, ir, kh)
	j, err := a.Apply(tn, "gre")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "error" {
		t.Fatalf("apply ended %s", s.Status)
	}
	runs := ir.snapshot()
	at := -1
	for i, r := range runs {
		if strings.HasPrefix(r, "WRITE-FAIL") {
			at = i
		}
	}
	if at < 0 {
		t.Fatal("the switcher was never deployed")
	}
	down := false
	for _, r := range runs[at+1:] {
		down = down || (strings.Contains(r, "systemctl disable --now") && strings.Contains(r, tn.ID+"x"))
	}
	if !down {
		t.Error("the paths keep running after the switcher failed to deploy")
	}
}
