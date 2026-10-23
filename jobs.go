package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	cancel  context.CancelFunc
	// tornDown: an apply got as far as taking the previous method down (ApplyRoute then
	// brings that one back if the new one fails)
	tornDown atomic.Bool
}

// context returns the job's context; Jobs.cancel ends it, which kills whatever
// remote command the job is waiting on (SSH sessions and agent runs honour ctx).
func (j *Job) context(d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	j.mu.Lock()
	j.cancel = cancel
	j.mu.Unlock()
	return ctx, cancel
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
	if j.Status == "cancelled" {
		status = "cancelled" // a cancelled job stays cancelled whatever its goroutine reports
	}
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

// cancel aborts a running job; the tunnel is released at once so Stop/Apply can run.
func (js *Jobs) cancel(id string) (*Job, error) {
	j := js.get(id)
	if j == nil {
		return nil, fmt.Errorf("job not found")
	}
	j.mu.Lock()
	running, cancel := j.Status == "running", j.cancel
	if running {
		j.Status = "cancelled"
		j.Ended = time.Now().Unix()
	}
	j.mu.Unlock()
	if !running {
		return j, nil
	}
	j.log("CANCELLED by user")
	if cancel != nil {
		cancel()
	}
	// a benchmark still tears down its probe/port after cancel; keep its slot until then
	if j.Tunnel != "bench" {
		js.done(j)
	}
	return j, nil
}

// running returns the id of the job running on a tunnel ("" = none).
func (js *Jobs) running(tunnel string) string {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.busy[tunnel]
}

// anyRunning: some job (apply, stop, benchmark, failover…) is in progress.
func (js *Jobs) anyRunning() bool {
	js.mu.Lock()
	defer js.mu.Unlock()
	return len(js.busy) > 0
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

	// hostFor, when set (tests only), supplies the Host for a server instead of agent/SSH.
	hostFor func(*Server) Host

	srvMon      *serverMon // the SSH-port server monitor (nil until it runs)
	healthMu    sync.Mutex
	hsViews     map[string]*hsView   // hot-standby switchers' state, as last read
	healthCache map[string]string    // tunnel id -> "" healthy / reason, from the monitor
	foNext      map[string]time.Time // tunnel id -> next automatic failover allowed

	traffic  *trafficMon
	speedMu  sync.Mutex
	speedRes map[string]*SpeedResult // tunnel id -> last speed test
}

func (a *App) settings() Settings {
	var s Settings
	a.store.View(func(st *State) { s = st.Settings })
	return s
}

// build creates plans under the store lock (secrets may be created) and persists them.
func (a *App) build(m *Method, t *Tunnel, srv *Server, redir ...map[int]int) (SidePlan, SidePlan, error) {
	var ir, kh SidePlan
	var err error
	fsrv := a.store.Server(t.ForeignID)
	var rd map[int]int
	if len(redir) > 0 {
		rd = redir[0]
	}
	uerr := a.store.Update(func(st *State) error {
		ir, kh, err = buildPlansRedirect(m, t, srv, fsrv, st.Settings, rd)
		if err == nil && t.ID != "bench" {
			err = portClash(st, t, m.ID)
		}
		if err == nil && m.ID == "golden" {
			if o := goldenConflict(st, t); o != "" {
				err = fmt.Errorf("tunnel %q already runs Golden-GRE between these two servers — set a different \"DNS port\" (e.g. 5353) in this tunnel's Golden-GRE options", o)
			}
		}
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
[ -x %[2]s/fw-in-down.sh ] && %[2]s/fw-in-down.sh >/dev/null 2>&1
rm -rf %[2]s
# an IPsec config left by a failed deploy would keep strongSwan trying (or failing to start)
if [ -f /etc/swanctl/conf.d/tp%[5]d.conf ]; then
  swanctl --terminate --ike tp%[5]d >/dev/null 2>&1
  rm -f /etc/swanctl/conf.d/tp%[5]d.conf
  swanctl --load-all --noprompt >/dev/null 2>&1 || true
fi
%[4]s`, unitName(t), tunnelDir(t), shapeUnitName(t), acctDown(t), t.Index)
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
jl() { inv=$(systemctl show -p InvocationID --value %[1]s 2>/dev/null)
  if [ -n "$inv" ]; then journalctl _SYSTEMD_INVOCATION_ID=$inv -n 25 --no-pager -o cat; else journalctl -u %[1]s -n 25 --no-pager -o cat; fi; }
if ! systemctl restart %[1]s; then
  jl
  exit 1
fi
sleep 2
st=$(systemctl is-active %[1]s)
echo "unit %[1]s: $st"
if [ "$st" != active ]; then jl; exit 1; fi
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
	a.clearHealth(t.ID)
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(20 * time.Minute)
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
		if t.Family == "v6" {
			if n := a.fixIPv6(ctx, irHost, srv.ID, srv.IPv6); n != "" {
				j.log("[IR] %s", n)
			}
			if f := a.store.Server(t.ForeignID); f != nil {
				if n := a.fixIPv6(ctx, khHost, f.ID, f.IPv6); n != "" {
					j.log("[KH] %s", n)
				}
			} else if n := a.fixIPv6(ctx, khHost, "", a.settings().LocalIPv6); n != "" {
				j.log("[KH] %s", n)
			}
			srv = a.store.Server(t.ServerID)
		}

		if t.HotStandby {
			a.applyHot(ctx, j, t, m, srv, irHost, khHost, fail)
			return
		}
		if len(t.Paths) > 0 { // hot standby was turned off: remove its paths and switcher
			j.log("removing the hot-standby paths")
			_, _ = irHost.Run(ctx, hsTeardown(t), nil)
			_, _ = khHost.Run(ctx, hsTeardown(t), nil)
			_ = a.store.Update(func(*State) error { t.Paths = nil; return nil })
		}

		if ro := a.routeOpts(t, mid, t.Family); len(ro) > 0 {
			j.log("using %s — the route benchmark found the default passes no traffic between these servers", altLabel(ro))
			_ = a.store.Update(func(*State) error {
				no := make(map[string]map[string]string, len(t.Options)+1)
				for k, v := range t.Options {
					no[k] = v
				}
				cp := map[string]string{}
				for k, v := range t.Options[mid] {
					cp[k] = v
				}
				for k, v := range ro {
					cp[k] = v
				}
				no[mid] = cp
				t.Options = no // copy-on-write: readers use Options without the lock
				return nil
			})
		}
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
		j.tornDown.Store(t.Active != "")
		a.setActive(t, "")

		// the ports this method binds on Iran must really be free now; a user port another
		// program holds is redirected to a free internal port the daemon listens on instead
		redir, err := a.freeIranPorts(ctx, j, irHost, t, m)
		if err != nil {
			fail("%v", err)
			return
		}
		if len(redir) > 0 {
			if irP, khP, err = a.build(m, t, srv, redir); err != nil {
				fail("build: %v", err)
				return
			}
		}

		// reverse methods: make sure the foreign server can actually dial Iran first
		changed, err := a.reversePreflight(ctx, j, t, m, irHost, khHost)
		if err != nil {
			fail("%v", err)
			return
		}
		if changed {
			if irP, khP, err = a.build(m, t, srv, redir); err != nil {
				fail("build: %v", err)
				return
			}
		}

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
		// a first verdict for the card now, not at the monitor's next round (reverse links
		// need a few seconds to dial in)
		go func() {
			time.Sleep(8 * time.Second)
			c, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			if t.Active == mid {
				a.checkHealth(c, t)
			}
		}()
	}()
	return j, nil
}

// purge removes a tunnel's leftovers (units, rules, interface) from both servers, best
// effort; it returns a warning for servers it could not reach.
func (a *App) purge(parent context.Context, t *Tunnel) string {
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	var warn []string
	if srv := a.store.Server(t.ServerID); srv != nil {
		if h, _, err := a.reach(ctx, srv, nil); err != nil || !a.teardownOn(ctx, h, t.ServerID, t, nil) {
			a.deferCleanup(t.ServerID, t)
			warn = append(warn, "Iran server unreachable — its leftovers are removed automatically once it answers again")
		}
	}
	if h, _, err := a.foreignHost(ctx, t, nil); err == nil {
		if !a.teardownOn(ctx, h, t.ForeignID, t, nil) {
			warn = append(warn, "foreign server didn't finish the cleanup — it is retried automatically once it answers again")
		}
	} else {
		a.deferCleanup(t.ForeignID, t)
		warn = append(warn, "foreign server unreachable — its leftovers are removed automatically once it answers again")
	}
	return strings.Join(warn, "; ")
}

// Stop tears down the active method on both sides.
func (a *App) Stop(t *Tunnel) (*Job, error) {
	j, err := a.jobs.start(t.ID, "stop")
	if err != nil {
		return nil, err
	}
	a.clearHealth(t.ID)
	go func() {
		defer a.jobs.done(j)
		// Stop must run even right after a cancelled job, so it never inherits one
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if srv := a.store.Server(t.ServerID); srv != nil {
			if irHost, path, err := a.reach(ctx, srv, j); err == nil {
				j.log("Iran reachable via %s", path)
				if !a.teardownOn(ctx, irHost, t.ServerID, t, func(l string) {
					if l != "TP-TEARDOWN-DONE" {
						j.log("[IR] %s", l)
					}
				}) {
					j.log("WARNING: the Iran side didn't finish stopping — it is finished automatically as soon as the server answers again")
				}
			} else {
				a.deferCleanup(t.ServerID, t)
				j.log("WARNING: Iran unreachable (%v) — only the foreign side was stopped; the Iran side is stopped automatically as soon as it answers again", err)
			}
		}
		if kh, _, err := a.foreignHost(ctx, t, j); err == nil {
			if !a.teardownOn(ctx, kh, t.ForeignID, t, func(l string) {
				if l != "TP-TEARDOWN-DONE" {
					j.log("[KH] %s", l)
				}
			}) {
				j.log("WARNING: the foreign side didn't finish stopping — finished automatically as soon as it answers again")
			}
		} else {
			a.deferCleanup(t.ForeignID, t)
			j.log("WARNING: foreign server unreachable (%v) — stopped there automatically as soon as it answers again", err)
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

// Health is Status plus whether the tunnel link itself carries traffic: "up", "down",
// or "" when it can't be judged (e.g. Spoof-Tunnel). L3 methods ping the peer's tunnel
// address; reverse/port-forward methods look for the peer's established connection on
// the Iran tunnel port.
func (a *App) Health(ctx context.Context, t *Tunnel) (ir, kh, link string) {
	cmd := "systemctl is-active " + unitName(t) + " 2>/dev/null || true"
	if kHost, _, err := a.foreignHost(ctx, t, nil); err == nil {
		out, _ := kHost.Run(ctx, cmd, nil)
		kh = lastLine(out)
	} else {
		kh = "unreachable"
	}
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return "no server", kh, ""
	}
	h, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return "unreachable", kh, ""
	}
	if t.HotStandby && len(t.Paths) > 0 {
		// the switcher's own verdict: the path it keeps the users on works
		v, events, err := a.hsRead(ctx, h, t, t.HSSeen)
		a.hsReport(t, v, events)
		switch {
		case err != nil:
			return err.Error(), kh, ""
		case v.Active >= 0 && v.Active < len(v.OK) && v.OK[v.Active]:
			return "active", "active", "up"
		}
		return "active", "active", "down"
	}
	chk := linkCheck(t, srv, a.store.Server(t.ForeignID), a.settings())
	out, _ := h.Run(ctx, cmd+"\n"+chk, nil)
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "LINK "):
			link = strings.TrimPrefix(l, "LINK ")
		case l != "" && ir == "":
			ir = l
		}
	}
	if ir == "" {
		ir = "unknown"
	}
	// users' traffic flowing both ways through the tunnel right now is proof enough
	if link == "down" && a.trafficFlowing(t.ID) {
		link = "up"
	}
	return ir, kh, link
}

// linkCheck is the shell that prints "LINK up|down" on the Iran side.
func linkCheck(t *Tunnel, srv, fsrv *Server, set Settings) string {
	m := methodByID[t.Active]
	if m == nil || m.ID == "spoof" {
		return ""
	}
	d := deriveFor(t, srv, fsrv, set)
	if benchIsL3(m, t.Options[m.ID]) {
		// ping first; many servers drop ICMP, so a TCP connect (or RST) through the tunnel
		// to the forwarded service port also proves the link carries traffic
		return fmt.Sprintf("if ping -n -c 2 -i 0.3 -W 2 %[1]s >/dev/null 2>&1; then echo 'LINK up'; else\n%[2]s | sed 's/^open$/LINK up/; s/^refused$/LINK up/; s/^timeout$/LINK down/'\nfi", d.KHv4, tcpReach(d.KHv4, probePortOf(t)))
	}
	// only a TCP control/pool connection shows up as an established socket; for udp/kcp/
	// quic/pck/xdi transports the link can't be judged this way, so report "unknown"
	key, ok := reverseTCPPort(m, t)
	if !ok {
		return ""
	}
	get, _ := resolveOptions(m, t.Options[m.ID])
	p := portOr(get(key), d.BasePort)
	// plain "ss -tn" (old iproute2 has no -H and no state filters), netstat as a fallback
	return fmt.Sprintf(`if { ss -tn 2>/dev/null || netstat -tn 2>/dev/null; } | awk '($1=="ESTAB" || $6=="ESTABLISHED") && ($4 ~ /:%[1]s$/) {f=1} END {exit !f}'; then echo 'LINK up'; else echo 'LINK down'; fi`, p)
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
