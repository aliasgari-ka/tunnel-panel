package main

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Saving the edit window of a running tunnel puts the change into effect itself:
//   - other ports: only the paths whose files change are rebuilt (a forwarder that sends to
//     another port), the switcher gets its new rules (a new listening port), nothing else;
//     a tunnel without hot standby re-applies its one method
//   - another address family (no hot standby): the method is applied over that family
//   - other servers: stopped on the old ones, then started with the same method on the new
//
// With "Keep users connected" the tunnel's family is the path the users are on now (the
// switcher moves them between IPv4 and IPv6 paths by itself), not a setting: an edit form
// opened before such a move sent the old family, and Save refused it as a family change.

// editPortPlan is, per method, the running hot-standby paths whose own files differ between
// before and after (as optRebuild would deploy them). A path whose plan can't be built with
// the new values counts as changed: its rebuild says why.
func (a *App) editPortPlan(before, after *Tunnel) map[string][]HSPath {
	srv := a.store.Server(after.ServerID)
	out := map[string][]HSPath{}
	if srv == nil {
		return out
	}
	// keys a build makes (a path never built yet) land on the stored tunnel: both sides are
	// built with those, or every new token would read as a change
	b, n := *before, *after
	for _, p := range hsGood(after) {
		m := methodByID[p.Method]
		if m == nil {
			continue
		}
		_, _, _ = a.build(m, pathTunnel(&n, p), srv)
		a.store.View(func(st *State) {
			if cur := a.store.tunnelLocked(st, after.ID); cur != nil {
				b.Secrets, n.Secrets = cur.Secrets, cur.Secrets
			}
		})
		oi, ok, oerr := a.build(m, pathTunnel(&b, p), srv)
		ni, nk, nerr := a.build(m, pathTunnel(&n, p), srv)
		if oerr != nil || nerr != nil || !reflect.DeepEqual(oi, ni) || !reflect.DeepEqual(ok, nk) {
			out[p.Method] = append(out[p.Method], p)
		}
	}
	return out
}

// applyPortEdit puts t's new ports into effect (before = t as it ran). nil job: nothing on the
// servers depends on what changed.
func (a *App) applyPortEdit(t, before *Tunnel) (*Job, error) {
	var mid string
	var hs bool
	var after Tunnel
	a.store.View(func(*State) {
		mid, hs = t.Active, t.HotStandby && len(t.Paths) > 0
		after = *t
		after.Paths = append([]HSPath(nil), t.Paths...)
	})
	if mid == "" {
		return nil, nil
	}
	if !hs {
		return a.ApplyRoute(t, mid, "")
	}
	j, err := a.jobs.start(t.ID, "ports")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(25 * time.Minute)
		defer cancel()
		a.portEditRun(ctx, j, t, before, &after)
	}()
	return j, nil
}

func (a *App) portEditRun(ctx context.Context, j *Job, t, before, after *Tunnel) {
	begin := time.Now()
	j.log("ports changed (%s → %s) — rebuilding only what uses them; the other paths keep running", before.Ports, after.Ports)
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		j.log("ERROR: Iran server not found")
		j.finish("error")
		return
	}
	ir, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		j.log("ERROR: the Iran server can't be reached now (%v) — saved; press Re-apply once it answers", err)
		j.finish("error")
		return
	}
	kh, _, err := a.foreignHost(ctx, t, nil)
	if err != nil {
		j.log("ERROR: the foreign server can't be reached now (%v) — saved; press Re-apply once it answers", err)
		j.finish("error")
		return
	}
	plan := a.editPortPlan(before, after)
	mids := make([]string, 0, len(plan))
	mine := map[string]bool{}
	var keys []string
	for mid, ps := range plan {
		mids = append(mids, mid)
		for _, p := range ps {
			k := p.Method + "|" + p.Family
			mine[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(mids)
	sort.Strings(keys)
	errs := map[string]string{}
	if len(keys) > 0 {
		j.log("paths with new files: %s", strings.Join(keys, ", "))
		restore, _, _ := a.hsStepAside(ctx, j, ir, t, mine, "it restarts for the new ports")
		for _, mid := range mids {
			for k, e := range a.optRebuildPaths(ctx, j, srv, ir, kh, before, after, plan[mid], methodByID[mid]) {
				errs[k] = e
			}
		}
		defer restore()
	} else {
		j.log("no path's own files change — only the switcher's rules")
	}
	if !a.optSwitcherSync(ctx, j, ir, before, after) && len(keys) == 0 {
		j.log("DONE — nothing on the servers uses what changed")
		j.finish("ok")
		return
	}
	if len(keys) == 0 {
		j.log("DONE in %s — runs on ports %s", optSecs(time.Since(begin)), after.Ports)
		j.finish("ok")
		return
	}
	okNow, v := a.optWait(ctx, j, ir, t, keys)
	var down []string
	for _, k := range keys {
		if okNow[k] && errs[k] == "" {
			j.log("  ✓ %s answers (%s)", k, optPathStat(v, k))
		} else {
			down = append(down, k)
			j.log("  ✕ %s doesn't answer: %s — the users stay on a working path", k, optWhy(v, k, errs[k]))
		}
	}
	if len(down) > 0 {
		j.log("FAILING — ports saved, %d of %d rebuilt path(s) don't answer (%s)", len(down), len(keys), optSecs(time.Since(begin)))
		j.finish("error")
		return
	}
	j.log("DONE in %s — runs on ports %s", optSecs(time.Since(begin)), after.Ports)
	j.finish("ok")
}

// relayJob copies sub's lines into j as they come, until sub ends; sub's final status.
func (a *App) relayJob(ctx context.Context, j, sub *Job, prefix string) string {
	n := 0
	copyNew := func() string {
		sub.mu.Lock()
		lines, st := append([]string(nil), sub.Lines[n:]...), sub.Status
		n = len(sub.Lines)
		sub.mu.Unlock()
		for _, l := range lines {
			if i := strings.IndexByte(l, ' '); i > 0 {
				l = l[i+1:] // its own time stamp: j adds one
			}
			j.log("%s%s", prefix, l)
		}
		return st
	}
	for {
		if st := copyNew(); st != "running" {
			return st
		}
		select {
		case <-ctx.Done():
			_, _ = a.jobs.cancel(sub.ID)
			return "cancelled"
		case <-time.After(400 * time.Millisecond):
		}
	}
}

// moveJobKey is the move's own job slot: the Stop and Start it runs take the tunnel's.
const moveJobKey = "move:"

// moveTunnel moves a running tunnel to other servers (or family): Stop on the servers it runs
// on, then the same method started on the new ones. One job shows both steps.
func (a *App) moveTunnel(t *Tunnel, serverID, foreignID, fam string) (*Job, error) {
	var mid, curFam string
	a.store.View(func(*State) { mid, curFam = t.Active, t.Family })
	if mid == "" {
		return nil, fmt.Errorf("the tunnel is not running")
	}
	if fam == "" {
		fam = curFam
	}
	if id := a.jobs.running(t.ID); id != "" {
		return nil, fmt.Errorf("A job is still running on this tunnel — wait for it to end (or cancel it), then save again. Nothing was changed.")
	}
	j, err := a.jobs.start(moveJobKey+t.ID, "move")
	if err != nil {
		return nil, err
	}
	a.jobs.mu.Lock()
	j.Tunnel = t.ID // the tunnel's log shows it (its slot stays moveJobKey+id, freed below)
	a.jobs.mu.Unlock()
	go func() {
		defer func() {
			a.jobs.mu.Lock()
			if a.jobs.busy[moveJobKey+t.ID] == j.ID {
				delete(a.jobs.busy, moveJobKey+t.ID)
			}
			a.jobs.mu.Unlock()
		}()
		ctx, cancel := j.context(40 * time.Minute)
		defer cancel()
		j.log("== 1/2 stopping %s on the servers it runs on now ==", methodTitle(mid))
		if id := a.jobs.running(failoverJobKey + t.ID); id != "" {
			_, _ = a.jobs.cancel(id)
		}
		a.clearFailover(t)
		sj, err := a.Stop(t)
		if err != nil {
			j.log("ERROR: %v — nothing was moved", err)
			j.finish("error")
			return
		}
		if st := a.relayJob(ctx, j, sj, "  "); st != "ok" {
			j.log("ERROR: the stop ended %s — the tunnel keeps its servers; press Stop, then edit", st)
			j.finish("error")
			return
		}
		var nf string
		_ = a.store.Update(func(st *State) error {
			t.ServerID, t.ForeignID = serverID, foreignID
			t.Paths, t.HSPin, t.HSOff = nil, "", nil // the old route's paths: built again on the new one
			fams := a.routeFamiliesLocked(st, t)
			nf = fam
			if !contains(fams, nf) && len(fams) > 0 {
				nf = fams[0]
			}
			t.Family = nf
			t.Updated = time.Now().Unix()
			return nil
		})
		if nf != fam {
			j.log("%s isn't available on the new route — starting over %s", famLabel(fam), famLabel(nf))
		}
		j.log("== 2/2 starting %s on %s → %s ==", methodTitle(mid), serverName(a, serverID), serverName(a, foreignID))
		aj, err := a.ApplyRoute(t, mid, nf)
		if err != nil {
			j.log("ERROR: %v — the tunnel is saved on the new servers, stopped; press Start", err)
			j.finish("error")
			return
		}
		st := a.relayJob(ctx, j, aj, "  ")
		if st != "ok" {
			j.log("ERROR: the start on the new servers ended %s — saved there; see the log above", st)
			j.finish("error")
			return
		}
		j.log("DONE — moved")
		j.finish("ok")
	}()
	return j, nil
}

func famLabel(f string) string {
	if f == "v6" {
		return "IPv6"
	}
	return "IPv4"
}
