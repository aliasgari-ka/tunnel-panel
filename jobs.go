package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Job struct {
	ID      string   `json:"id"`
	Tunnel  string   `json:"tunnel"`
	Kind    string   `json:"kind"`
	Status  string   `json:"status"` // running | ok | error
	Lines   []string `json:"lines"`
	Started int64    `json:"started"`
	Ended   int64    `json:"ended"`
	mu      sync.Mutex
	onLine  func(string)
}

func (j *Job) log(format string, a ...any) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, a...)
	j.mu.Lock()
	j.Lines = append(j.Lines, line)
	cb := j.onLine
	j.mu.Unlock()
	if cb != nil {
		cb(line)
	}
}

func (j *Job) finish(status string) {
	j.mu.Lock()
	j.Status = status
	j.Ended = time.Now().Unix()
	j.mu.Unlock()
}

func (j *Job) snapshot() *Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	return &Job{ID: j.ID, Tunnel: j.Tunnel, Kind: j.Kind, Status: j.Status,
		Started: j.Started, Ended: j.Ended, Lines: append([]string(nil), j.Lines...)}
}

type Jobs struct {
	mu   sync.Mutex
	m    map[string]*Job
	busy map[string]string // tunnel id -> running job id
}

func newJobs() *Jobs { return &Jobs{m: map[string]*Job{}, busy: map[string]string{}} }

func (js *Jobs) get(id string) *Job {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.m[id]
}

// latestFor returns the most recent job of a tunnel.
func (js *Jobs) latestFor(tunnel string) *Job {
	js.mu.Lock()
	defer js.mu.Unlock()
	var best *Job
	for _, j := range js.m {
		if j.Tunnel == tunnel && (best == nil || j.Started > best.Started) {
			best = j
		}
	}
	return best
}

// start registers a job; it fails if the tunnel already has one running.
func (js *Jobs) start(tunnel, kind string) (*Job, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if tunnel != "" {
		if id, ok := js.busy[tunnel]; ok {
			return nil, fmt.Errorf("another job (%s) is still running on this tunnel", id)
		}
	}
	j := &Job{ID: newID(), Tunnel: tunnel, Kind: kind, Status: "running", Started: time.Now().Unix()}
	js.m[j.ID] = j
	if tunnel != "" {
		js.busy[tunnel] = j.ID
	}
	if len(js.m) > 80 {
		var oldest string
		var ot int64 = 1 << 62
		for id, x := range js.m {
			if x.Status != "running" && x.Started < ot {
				ot, oldest = x.Started, id
			}
		}
		delete(js.m, oldest)
	}
	return j, nil
}

func (js *Jobs) done(j *Job) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.busy[j.Tunnel] == j.ID {
		delete(js.busy, j.Tunnel)
	}
}

// App ties the store, jobs and host execution together.
type App struct {
	store     *Store
	jobs      *Jobs
	agents    *AgentHub
	agentPort int
	notify    func(string) // optional push (Telegram) for finished jobs

	botMu sync.Mutex
	bot   *Bot

	benchMu  sync.Mutex
	benchRes map[string][]BenchResult // "iran|foreign|family" -> results
	benchRun *benchActive             // the running benchmark (nil when idle)
}

func (a *App) settings() Settings {
	var s Settings
	a.store.View(func(st *State) { s = st.Settings })
	return s
}

// build creates plans under the store lock (secrets may be created) and persists them.
func (a *App) build(m *Method, t *Tunnel, srv *Server) (SidePlan, SidePlan, error) {
	var ir, kh SidePlan
	var err error
	fsrv := a.store.Server(t.ForeignID)
	uerr := a.store.Update(func(st *State) error {
		ir, kh, err = buildPlans(m, t, srv, fsrv, st.Settings)
		return nil
	})
	if uerr != nil {
		return ir, kh, uerr
	}
	return ir, kh, err
}

// teardownScript stops the tunnel's unit (its ExecStop/ExecStopPost do the cleanup) and removes it.
func teardownScript(t *Tunnel) string {
	return fmt.Sprintf(`for u in %[1]s %[3]s; do
  if [ -f /etc/systemd/system/$u ]; then
    systemctl disable --now $u 2>&1 | grep -v "Removed" || true
    rm -f /etc/systemd/system/$u
  fi
done
systemctl daemon-reload 2>/dev/null || true
rm -rf %[2]s
`, unitName(t), tunnelDir(t), shapeUnitName(t))
}

// deploy installs a side plan on one host.
func (a *App) deploy(ctx context.Context, j *Job, label string, h Host, t *Tunnel, p SidePlan) error {
	logf := func(l string) { j.log("[%s] %s", label, l) }
	if err := pushArtifacts(ctx, j, label, h, p.Artifacts); err != nil {
		return err
	}
	for path, fs := range p.Files {
		j.log("[%s] write %s", label, path)
		if err := h.WriteFile(path, fs.Content, fs.Mode); err != nil {
			return err
		}
	}
	if p.Setup != "" {
		if out, err := h.Run(ctx, "set -e\n"+p.Setup, logf); err != nil {
			return withTail(fmt.Errorf("setup: %w", err), out)
		}
	}
	u := unitName(t)
	if err := h.WriteFile("/etc/systemd/system/"+u, []byte(renderUnit(p.Unit)), 0o644); err != nil {
		return err
	}
	script := fmt.Sprintf(`systemctl daemon-reload
systemctl enable %[1]s >/dev/null 2>&1
if ! systemctl restart %[1]s; then
  journalctl -u %[1]s -n 25 --no-pager
  exit 1
fi
sleep 2
st=$(systemctl is-active %[1]s)
echo "unit %[1]s: $st"
if [ "$st" != active ]; then journalctl -u %[1]s -n 25 --no-pager; exit 1; fi
`, u)
	out, err := h.Run(ctx, script, logf)
	return withTail(err, out)
}

// Apply starts or switches a tunnel to method mid.
func (a *App) Apply(t *Tunnel, mid string) (*Job, error) {
	j, err := a.jobs.start(t.ID, "apply:"+mid)
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		fail := func(f string, x ...any) {
			j.log("ERROR: "+f, x...)
			j.finish("error")
			a.push(fmt.Sprintf("❌ %s: %s failed — %s", t.Name, mid, fmt.Sprintf(f, x...)))
		}
		srv := a.store.Server(t.ServerID)
		m := methodByID[mid]
		if srv == nil || m == nil {
			fail("server or method not found")
			return
		}
		j.log("connecting to Iran server %s", srv.Name)
		irHost, path, err := a.reach(ctx, srv, j)
		if err != nil {
			fail("cannot reach Iran server: %v", err)
			return
		}
		j.log("Iran reachable via %s", path)
		khHost, kpath, err := a.foreignHost(ctx, t, j)
		if err != nil {
			fail("cannot reach foreign server: %v", err)
			return
		}
		j.log("foreign side: %s", kpath)

		j.log("building %s config", m.Title)
		irP, khP, err := a.build(m, t, srv)
		if err != nil {
			fail("build: %v", err)
			return
		}

		if t.Active != "" {
			j.log("stopping current method (%s) on both servers", t.Active)
		}
		_, _ = irHost.Run(ctx, teardownScript(t), func(l string) { j.log("[IR] %s", l) })
		_, _ = khHost.Run(ctx, teardownScript(t), func(l string) { j.log("[KH] %s", l) })
		a.setActive(t, "")

		j.log("== foreign server (this one) ==")
		if err := a.deploy(ctx, j, "KH", khHost, t, khP); err != nil {
			fail("foreign: %v", err)
			return
		}
		j.log("== Iran server ==")
		if err := a.deploy(ctx, j, "IR", irHost, t, irP); err != nil {
			fail("Iran: %v", err)
			return
		}
		if t.Shape.Enabled {
			j.log("applying traffic shaping (%s) on Iran", t.Shape.Qdisc)
			if err := a.deployShape(ctx, j, "IR", irHost, t); err != nil {
				j.log("WARNING: shaping on Iran failed: %v", err)
			}
			if t.Shape.OnBoth {
				if err := a.deployShape(ctx, j, "KH", khHost, t); err != nil {
					j.log("WARNING: shaping on foreign failed: %v", err)
				}
			}
		}
		a.setActive(t, mid)
		j.log("DONE — %s is active on both servers", m.Title)
		j.finish("ok")
		a.push(fmt.Sprintf("✅ %s now runs %s", t.Name, m.Title))
	}()
	return j, nil
}

// Stop tears down the active method on both sides.
func (a *App) Stop(t *Tunnel) (*Job, error) {
	j, err := a.jobs.start(t.ID, "stop")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if srv := a.store.Server(t.ServerID); srv != nil {
			if irHost, path, err := a.reach(ctx, srv, j); err == nil {
				j.log("Iran reachable via %s", path)
				_, _ = irHost.Run(ctx, teardownScript(t), func(l string) { j.log("[IR] %s", l) })
			} else {
				j.log("WARNING: Iran unreachable (%v) — only the foreign side was stopped", err)
			}
		}
		if kh, _, err := a.foreignHost(ctx, t, j); err == nil {
			_, _ = kh.Run(ctx, teardownScript(t), func(l string) { j.log("[KH] %s", l) })
		} else {
			j.log("WARNING: foreign server unreachable (%v)", err)
		}
		a.setActive(t, "")
		j.log("stopped")
		j.finish("ok")
		a.push("⏹ " + t.Name + " stopped")
	}()
	return j, nil
}

func (a *App) setActive(t *Tunnel, mid string) {
	_ = a.store.Update(func(*State) error {
		t.Active = mid
		if mid != "" {
			t.Selected = mid
		}
		t.LastJob = time.Now().Format(time.RFC3339)
		t.Updated = time.Now().Unix()
		return nil
	})
}

func (a *App) push(msg string) {
	if a.notify != nil {
		go a.notify(msg)
	}
}

// Status returns the unit state on both sides ("active", "inactive", "unreachable", ...).
func (a *App) Status(ctx context.Context, t *Tunnel) (ir, kh string) {
	cmd := "systemctl is-active " + unitName(t) + " 2>/dev/null || true"
	if kHost, _, err := a.foreignHost(ctx, t, nil); err == nil {
		out, _ := kHost.Run(ctx, cmd, nil)
		kh = lastLine(out)
	} else {
		kh = "unreachable"
	}
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return "no server", kh
	}
	h, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return "unreachable", kh
	}
	out, _ := h.Run(ctx, cmd, nil)
	return lastLine(out), kh
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// foreignHost returns the host for the tunnel's foreign side.
func (a *App) foreignHost(ctx context.Context, t *Tunnel, j *Job) (Host, string, error) {
	if t.ForeignID == "" {
		return LocalHost{}, "this panel host", nil
	}
	f := a.store.Server(t.ForeignID)
	if f == nil {
		return nil, "", fmt.Errorf("foreign server %s not found", t.ForeignID)
	}
	h, path, err := a.reach(ctx, f, j)
	if err != nil {
		return nil, "", err
	}
	return labeled{h, "KH"}, f.Name + " via " + path, nil
}

// labeled overrides a host's label (SSH/agent hosts default to IR).
type labeled struct {
	Host
	l string
}

func (l labeled) Label() string { return l.l }
