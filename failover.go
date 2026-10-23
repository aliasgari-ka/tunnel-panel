package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Automatic failover. When a tunnel has been down for failoverAfter, the panel tries
// other paths — other methods, and the other address family (v4 ⇄ v6) when both servers
// have it — best benchmark result first. A candidate is kept only when a connection to the
// tunnel's forwarded port really reaches the service on the foreign server (or, with no
// service there yet, the probe passes through the tunnel). Every failbackEvery the
// original path is re-tested on the benchmark slot, without touching the live tunnel; if
// it works again the tunnel moves back, otherwise it stays on the working backup.
const (
	failoverAfter  = 5 * time.Minute
	failbackEvery  = time.Hour
	failoverTries  = 6
	failoverJobKey = "failover:"
)

type pathChoice struct{ method, family string }

func (p pathChoice) String() string { return methodTitle(p.method) + " (" + p.family + ")" }

// failoverCandidates lists paths to try, best first: benchmark results for this route
// (both families), then a sensible default order. The current path is excluded.
func (a *App) failoverCandidates(t *Tunnel) []pathChoice {
	ir, fg := a.store.Server(t.ServerID), a.store.Server(t.ForeignID)
	set := a.settings()
	has := func(fam string) bool {
		if ir == nil {
			return false
		}
		d := deriveFor(&Tunnel{Family: fam}, ir, fg, set)
		return d.IRPub != "" && d.KHPub != ""
	}
	seen := map[pathChoice]bool{{t.Active, t.Family}: true}
	var out []pathChoice
	add := func(mid, fam string) {
		p := pathChoice{mid, fam}
		m := methodByID[mid]
		if m == nil || seen[p] || mid == "spoof" || !supportsFamily(m, fam) || !has(fam) || a.routeSkipped(t.ServerID, t.ForeignID, mid, fam) {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	// 1. benchmarks of this route, best score first
	type scored struct {
		p pathChoice
		s float64
	}
	var sc []scored
	for _, fam := range []string{"v4", "v6"} {
		for _, r := range a.benchResults(t.ServerID, t.ForeignID, fam) {
			if r.OK {
				sc = append(sc, scored{pathChoice{r.Method, fam}, r.Score})
			}
		}
	}
	sort.SliceStable(sc, func(i, j int) bool { return sc[i].s > sc[j].s })
	for _, x := range sc {
		add(x.p.method, x.p.family)
	}
	// 2. defaults: the other family first (a dead path is often family-specific)
	fams := []string{"v4", "v6"}
	if t.Family == "v4" {
		fams = []string{"v6", "v4"}
	}
	for _, fam := range fams {
		for _, mid := range []string{"bp_l3", "gre", "direct6", "golden", "backhaul", "bp_reverse", "frp", "ipsec6"} {
			add(mid, fam)
		}
	}
	return out
}

// applyAndWait runs Apply and waits for it to end.
func (a *App) applyAndWait(ctx context.Context, t *Tunnel, mid string) error {
	j, err := a.Apply(t, mid)
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		time.Sleep(2 * time.Second)
		s := j.snapshot()
		if s.Status == "running" {
			continue
		}
		if s.Status != "ok" {
			for i := len(s.Lines) - 1; i >= 0; i-- {
				if strings.Contains(s.Lines[i], "ERROR") {
					return fmt.Errorf("%s", strings.TrimSpace(s.Lines[i][strings.Index(s.Lines[i], "ERROR"):]))
				}
			}
			return fmt.Errorf("apply %s", s.Status)
		}
		return nil
	}
	return ctx.Err()
}

// verifyPath checks that this tunnel carries traffic end to end: the per-tunnel probe must
// pass through it (unique port, so no other tunnel or client can fake it), and when a
// service listens on the forwarded port's target it must be reachable the way the tunnel
// delivers (L3: a SYN from this tunnel's Iran address arrives; forwarders: the service
// accepts on the foreign host's loopback).
func (a *App) verifyPath(ctx context.Context, t *Tunnel) (bool, string) {
	srv := a.store.Server(t.ServerID)
	m := methodByID[t.Active]
	if srv == nil || m == nil {
		return false, "not running"
	}
	ir, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return false, "Iran unreachable"
	}
	kh, _, err := a.foreignHost(ctx, t, nil)
	if err != nil {
		return false, "foreign unreachable"
	}
	d := deriveFor(t, srv, a.store.Server(t.ForeignID), a.settings())
	l3 := benchIsL3(m, t.Options[m.ID])
	run := func(h Host, s string) string { out, _ := h.Run(ctx, s, nil); return strings.TrimSpace(out) }

	// 1. the tunnel itself (spoof carries UDP only: skip the TCP probe)
	if m.ID != "spoof" {
		if err := pushArtifacts(ctx, &Job{}, "IR", ir, []Artifact{probeArt}); err != nil {
			return false, "probe: " + err.Error()
		}
		if err := pushArtifacts(ctx, &Job{}, "KH", kh, []Artifact{probeArt}); err != nil {
			return false, "probe: " + err.Error()
		}
		port := probePortFor(t)
		if err := probeStarted(ctx, kh, probeServerUpLife(port, 90)); err != nil {
			_, _ = kh.Run(context.Background(), probeServerDown(port), nil)
			return false, "probe server on the foreign side: " + err.Error()
		}
		target := fmt.Sprintf("127.0.0.1:%d", port)
		if l3 {
			target = fmt.Sprintf("%s:%d", d.KHv4, port)
		}
		passed := false
		for i := 0; i < 8 && !passed; i++ {
			if _, err := runProbe[probeRTT](ctx, ir, "probe rtt -addr "+target+" -n 3", 15); err == nil {
				passed = true
			} else {
				time.Sleep(3 * time.Second)
			}
		}
		_, _ = kh.Run(context.Background(), probeServerDown(port), nil)
		if !passed {
			return false, "no traffic passes through the tunnel"
		}
	}
	// 2. the service behind the forwarded port
	ps := firstPorts(t.Ports, 1)
	if len(ps) == 0 {
		return true, "traffic passes through the tunnel"
	}
	dst := ps[0].dst
	if i := strings.LastIndex(dst, ":"); i >= 0 {
		dst = dst[i+1:]
	}
	if run(kh, "ss -Hltn 'sport = :"+dst+"' 2>/dev/null | head -1") == "" {
		return true, "traffic passes through the tunnel (no service listens on port " + dst + " yet)"
	}
	if !l3 || m.ID == "bp_l3" {
		if run(kh, fmt.Sprintf("timeout 4 bash -c '</dev/tcp/127.0.0.1/%s' 2>/dev/null && echo open", dst)) == "open" {
			return true, fmt.Sprintf("traffic passes through the tunnel and the service on port %s accepts it", dst)
		}
		if m.ID != "bp_l3" {
			return false, "the service on port " + dst + " doesn't accept connections on 127.0.0.1, where the tunnel delivers"
		}
	}
	_, _ = kh.Run(ctx, traceRules(true, []string{dst}, false, d.IRv4), nil)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = kh.Run(c, traceRules(false, []string{dst}, false, d.IRv4), nil)
	}()
	for i := 0; i < 5; i++ {
		run(ir, "timeout 5 bash -c '</dev/tcp/"+d.KHv4+"/"+dst+"' 2>/dev/null")
		if c := parseTrace(run(kh, traceRead))[dst]; c != nil && c.syn > 0 {
			return true, fmt.Sprintf("connections through the tunnel reach the service on port %s", dst)
		}
		time.Sleep(2 * time.Second)
	}
	return false, "nothing from this tunnel arrives at the service on port " + dst
}

// failoverNotBefore is when the next automatic failover attempt for a tunnel may start
// (after one that found no working path, wait failoverRetry instead of looping).
func (a *App) failoverNotBefore(id string) time.Time {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	return a.foNext[id]
}

func (a *App) setFailoverNotBefore(id string, at time.Time) {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	if a.foNext == nil {
		a.foNext = map[string]time.Time{}
	}
	a.foNext[id] = at
}

const failoverRetry = 30 * time.Minute

// clearFailover forgets the backup state (the user chose a path by hand).
func (a *App) clearFailover(t *Tunnel) {
	if t.Failover != nil {
		_ = a.store.Update(func(*State) error { t.Failover = nil; return nil })
	}
}

// routeFamilies lists the address families both of a tunnel's servers can use.
func (a *App) routeFamilies(t *Tunnel) []string {
	ir, fg := a.store.Server(t.ServerID), a.store.Server(t.ForeignID)
	if ir == nil {
		return nil
	}
	var out []string
	for _, fam := range []string{"v4", "v6"} {
		d := deriveFor(&Tunnel{Family: fam}, ir, fg, a.settings())
		if d.IRPub != "" && d.KHPub != "" {
			out = append(out, fam)
		}
	}
	return out
}

// routeFamiliesLocked is routeFamilies for callers already inside store.View/Update.
func (a *App) routeFamiliesLocked(st *State, t *Tunnel) []string {
	var ir, fg *Server
	for _, s := range st.Servers {
		if s.ID == t.ServerID {
			ir = s
		}
		if s.ID == t.ForeignID {
			fg = s
		}
	}
	out := []string{}
	if ir == nil {
		return out
	}
	for _, fam := range []string{"v4", "v6"} {
		d := deriveFor(&Tunnel{Family: fam}, ir, fg, st.Settings)
		if d.IRPub != "" && d.KHPub != "" {
			out = append(out, fam)
		}
	}
	return out
}

// switchFamily validates method m over fam for this tunnel and, when fam differs from
// the tunnel's current family, switches it (the following Apply tears the old one down).
func (a *App) switchFamily(t *Tunnel, m *Method, fam string) error {
	if fam != "v4" && fam != "v6" {
		return fmt.Errorf("family must be v4 or v6")
	}
	if !supportsFamily(m, fam) {
		return fmt.Errorf("%s does not work over %s", m.Title, map[string]string{"v4": "IPv4", "v6": "IPv6"}[fam])
	}
	if !contains(a.routeFamilies(t), fam) {
		return fmt.Errorf("%s isn't available on this route: a server has no public %s address (set it on the Servers page or run Test connection)", map[string]string{"v4": "IPv4", "v6": "IPv6"}[fam], fam)
	}
	if t.Family != fam {
		a.setFamily(t, fam)
	}
	return nil
}

// ApplyRoute is a hand-picked Apply of method mid over family fam (empty = the tunnel's
// current one): the user's choice wins over a running automatic failover, and the family
// is put back if the apply cannot start.
func (a *App) ApplyRoute(t *Tunnel, mid, fam string) (*Job, error) {
	m := methodByID[mid]
	if m == nil {
		return nil, fmt.Errorf("unknown method")
	}
	// one consistent read: a Stop or apply running now changes these under the lock
	var old, prev, pin string
	var hot, running bool
	a.store.View(func(*State) {
		old, prev, pin, hot = t.Family, t.Active, t.HSPin, t.HotStandby
		if fam == "" {
			fam = t.Family
		}
		running = hot && prev != "" && len(t.Paths) > 0 && hsIndex(t, mid, fam) >= 0
	})
	// hot standby: another running path (or back to the tunnel's own from a chosen one) is
	// a selector swap, not a rebuild — nobody is cut
	if running && (mid != prev || fam != old || pin != "") {
		return a.hsSwitchJob(t, mid, fam)
	}
	if err := a.switchFamily(t, m, fam); err != nil {
		return nil, err
	}
	if id := a.jobs.running(failoverJobKey + t.ID); id != "" {
		_, _ = a.jobs.cancel(id)
	}
	j, err := a.Apply(t, mid)
	if err != nil {
		if t.Family != old {
			a.setFamily(t, old)
		}
		return nil, err
	}
	a.clearFailover(t)
	if prev != "" && !hot && (prev != mid || old != fam) {
		go a.restoreOnFail(j, t, prev, old, mid)
	}
	return j, nil
}

// restoreOnFail: switching a running tunnel to another method took the old one down, and
// the new one failed — bring the old one back instead of leaving the users without a tunnel.
func (a *App) restoreOnFail(j *Job, t *Tunnel, prev, prevFam, tried string) {
	for j.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
	active := ""
	a.store.View(func(*State) { active = t.Active })
	if j.snapshot().Status != "error" || !j.tornDown.Load() || active != "" {
		return // it worked, was cancelled, or failed before touching the running tunnel
	}
	for i := 0; i < 30 && a.jobs.running(t.ID) != ""; i++ {
		time.Sleep(time.Second)
	}
	a.push(fmt.Sprintf("↩ %s: %s failed — bringing back %s (%s), which ran before", t.Name, methodTitle(tried), methodTitle(prev), famName(prevFam)))
	a.setFamily(t, prevFam)
	if _, err := a.Apply(t, prev); err != nil {
		a.push(fmt.Sprintf("❌ %s: could not bring back %s: %v", t.Name, methodTitle(prev), err))
	}
}

// setFamily switches a stopped-or-being-replaced tunnel's underlay family.
func (a *App) setFamily(t *Tunnel, fam string) {
	_ = a.store.Update(func(*State) error { t.Family = fam; return nil })
}

// Failover moves a dead tunnel to the first candidate path that really works.
func (a *App) Failover(t *Tunnel, reason string) {
	j, err := a.jobs.start(failoverJobKey+t.ID, "failover")
	if err != nil {
		return
	}
	defer a.jobs.done(j)
	ctx, cancel := j.context(40 * time.Minute)
	defer cancel()
	orig := t.Failover
	if orig == nil {
		orig = &FailoverState{Method: t.Active, Family: t.Family, Reason: reason}
	}
	from := pathChoice{t.Active, t.Family}
	j.log("%s has been down for %s (%s) — looking for a working path", t.Name, failoverAfter, reason)
	tries := a.failoverCandidates(t)
	if len(tries) > failoverTries {
		tries = tries[:failoverTries]
	}
	for _, p := range tries {
		if ctx.Err() != nil {
			j.log("cancelled — leaving the tunnel as the user set it")
			return
		}
		j.log("trying %s", p)
		if t.Family != p.family {
			a.setFamily(t, p.family)
		}
		if err := a.applyAndWait(ctx, t, p.method); err != nil {
			j.log("  ✕ %v", err)
			continue
		}
		if ok, why := a.verifyPath(ctx, t); ok {
			now := time.Now().Unix()
			_ = a.store.Update(func(*State) error {
				orig.Since, orig.LastCheck = now, now
				t.Failover = orig
				return nil
			})
			j.log("  ✓ %s — staying on %s", why, p)
			j.finish("ok")
			a.push(fmt.Sprintf("🔁 Failover: %s\n%s was down (%s) → now on %s\n✓ %s\nThe original path is re-checked every hour.", t.Name, from, reason, p, why))
			return
		} else {
			j.log("  ✕ %s", why)
		}
	}
	if ctx.Err() != nil {
		j.log("cancelled — leaving the tunnel as the user set it")
		return
	}
	// nothing worked: put the original back so it resumes by itself when the path recovers
	j.log("no working path found — restoring %s", pathChoice{orig.Method, orig.Family})
	if t.Family != orig.Family {
		a.setFamily(t, orig.Family)
	}
	if err := a.applyAndWait(ctx, t, orig.Method); err != nil {
		// keep it marked as running so the monitor keeps watching (and retrying) it
		j.log("restoring failed too (%v) — the monitor keeps watching it", err)
		_ = a.store.Update(func(*State) error { t.Active, t.Selected = orig.Method, orig.Method; return nil })
	}
	_ = a.store.Update(func(*State) error { t.Failover = nil; return nil })
	a.setFailoverNotBefore(t.ID, time.Now().Add(failoverRetry))
	j.finish("error")
	a.push(fmt.Sprintf("❌ Failover for %s found no working path (tried %d). It stays on %s, alerts you when it recovers and tries failover again in %s.", t.Name, len(tries), pathChoice{orig.Method, orig.Family}, failoverRetry))
}

// Failback re-tests the original path on the benchmark slot (the live tunnel keeps running)
// and moves the tunnel back when the original works again.
func (a *App) Failback(t *Tunnel) {
	fo := t.Failover
	if fo == nil {
		return
	}
	j, err := a.jobs.start("bench", "failback-check")
	if err != nil {
		return // a benchmark is running; try next round
	}
	ctx, cancel := j.context(15 * time.Minute)
	defer cancel()
	_ = a.store.Update(func(*State) error { fo.LastCheck = time.Now().Unix(); return nil })
	ok := a.testPathOnBenchSlot(ctx, j, t, fo.Method, fo.Family)
	a.jobs.done(j)
	j.finish("ok")
	if !ok {
		j.log("original %s still down — staying on %s", pathChoice{fo.Method, fo.Family}, pathChoice{t.Active, t.Family})
		return
	}
	cur := pathChoice{t.Active, t.Family}
	if t.Family != fo.Family {
		a.setFamily(t, fo.Family)
	}
	if err := a.applyAndWait(ctx, t, fo.Method); err == nil {
		if ok2, _ := a.verifyPath(ctx, t); ok2 {
			_ = a.store.Update(func(*State) error { t.Failover = nil; return nil })
			a.push(fmt.Sprintf("↩ %s is back on its original path %s (backup %s ran for %s)", t.Name, pathChoice{fo.Method, fo.Family}, cur, time.Since(time.Unix(fo.Since, 0)).Round(time.Minute)))
			return
		}
	}
	// original failed on the live tunnel after all: return to the backup
	if t.Family != cur.family {
		a.setFamily(t, cur.family)
	}
	_ = a.applyAndWait(ctx, t, cur.method)
}

// testPathOnBenchSlot deploys method/family on the throwaway benchmark tunnel and reports
// whether traffic passes, without touching the live tunnel.
func (a *App) testPathOnBenchSlot(ctx context.Context, j *Job, t *Tunnel, mid, fam string) bool {
	m := methodByID[mid]
	srv := a.store.Server(t.ServerID)
	if m == nil || srv == nil {
		return false
	}
	probePort := 40000 + 250*4 + 2
	bt := &Tunnel{ID: "bench", Name: "failback-check", ServerID: t.ServerID, ForeignID: t.ForeignID, Family: fam,
		Ports: fmt.Sprint(probePort), Index: 250, Options: map[string]map[string]string{mid: t.Options[mid]}, Secrets: map[string]string{}}
	irHost, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return false
	}
	khHost, _, err := a.foreignHost(ctx, bt, nil)
	if err != nil {
		return false
	}
	if pushArtifacts(ctx, j, "IR", irHost, []Artifact{probeArt}) != nil || pushArtifacts(ctx, j, "KH", khHost, []Artifact{probeArt}) != nil {
		return false
	}
	_, _ = khHost.Run(ctx, probeServerUp(probePort), nil)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = khHost.Run(c, probeServerDown(probePort), nil)
		_, _ = irHost.Run(c, teardownScript(bt), nil)
		_, _ = khHost.Run(c, teardownScript(bt), nil)
	}()
	r := BenchResult{Method: mid, Kind: "forward"}
	if benchIsL3(m, bt.Options[mid]) {
		r.Kind = "l3"
	}
	return a.benchOne(ctx, j, bt, m, irHost, khHost, 2, 4, true, probePort, &r) == nil && r.OK
}
