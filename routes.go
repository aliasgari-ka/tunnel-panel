package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Per-route exclusions: methods the user doesn't want between two servers (one that
// misbehaves on that route, or one they don't trust) are left out of everything automatic
// there — benchmark, hot-standby paths and failover. Picking one by hand still works.

func routeKey(iran, foreign string) string { return iran + "|" + foreign }

func (a *App) routeSkipped(iran, foreign, mid, fam string) bool {
	skip := false
	a.store.View(func(st *State) {
		for _, x := range st.RouteSkip[routeKey(iran, foreign)] {
			if x == mid+"|"+fam {
				skip = true
			}
		}
	})
	return skip
}

func (a *App) setRouteSkip(iran, foreign, mid, fam string, skip bool) {
	_ = a.store.Update(func(st *State) error {
		k, v := routeKey(iran, foreign), mid+"|"+fam
		var keep []string
		for _, x := range st.RouteSkip[k] {
			if x != v {
				keep = append(keep, x)
			}
		}
		if skip {
			keep = append(keep, v)
		}
		if st.RouteSkip == nil {
			st.RouteSkip = map[string][]string{}
		}
		if len(keep) == 0 {
			delete(st.RouteSkip, k)
		} else {
			st.RouteSkip[k] = keep
		}
		return nil
	})
}

// setRouteSkipAll replaces a route's exclusions with off.
func (a *App) setRouteSkipAll(iran, foreign string, off []string) {
	_ = a.store.Update(func(st *State) error {
		k := routeKey(iran, foreign)
		seen := map[string]bool{}
		var keep []string
		for _, v := range off {
			if !seen[v] {
				seen[v] = true
				keep = append(keep, v)
			}
		}
		if len(keep) == 0 {
			delete(st.RouteSkip, k)
			return nil
		}
		if st.RouteSkip == nil {
			st.RouteSkip = map[string][]string{}
		}
		st.RouteSkip[k] = keep
		return nil
	})
}

// routeSkip: GET → every route's exclusions; POST {iran, foreign, method, family, skip}, or {iran, foreign, off: [...]} for the whole list.
func (s *Server2) routeSkip(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Iran, Foreign, Method, Family string
			Skip                          bool
			// Off, when set, replaces the route's whole list ("method|family" each): the tunnel
			// window's checklist of which paths hot standby keeps running
			Off *[]string
		}
		if err := readJSON(r, &in); err != nil || (in.Off == nil && (methodByID[in.Method] == nil || (in.Family != "v4" && in.Family != "v6"))) {
			httpErr(w, 400, "bad request")
			return
		}
		if in.Off != nil {
			for _, v := range *in.Off {
				mid, fam, _ := strings.Cut(v, "|")
				if methodByID[mid] == nil || (fam != "v4" && fam != "v6") {
					httpErr(w, 400, "bad request")
					return
				}
			}
		}
		// the switches belong to the server pair (every tunnel on it, benchmarks and failover):
		// a user changes them only where both servers are their own, the same test the list
		// below uses — not on the admin's servers that merely carry a tunnel of theirs
		user, admin := s.who(r)
		own := admin
		if !own {
			s.app.store.View(func(st *State) {
				own = visible(user, admin, ownerOfLocked(st, in.Iran)) && visible(user, admin, ownerOfLocked(st, in.Foreign))
			})
		}
		if !own || !s.pairVisible(user, admin, in.Iran, in.Foreign) {
			httpErr(w, 404, "not found")
			return
		}
		if in.Off != nil {
			s.app.setRouteSkipAll(in.Iran, in.Foreign, *in.Off)
		} else {
			s.app.setRouteSkip(in.Iran, in.Foreign, in.Method, in.Family, in.Skip)
		}
		s.app.routeSkipChanged(in.Iran, in.Foreign)
	}
	out := map[string][]string{}
	user, admin := s.who(r)
	s.app.store.View(func(st *State) {
		for k, v := range st.RouteSkip {
			if !admin {
				iran, foreign, _ := strings.Cut(k, "|")
				if foreign == "" || !visible(user, admin, ownerOfLocked(st, iran)) || !visible(user, admin, ownerOfLocked(st, foreign)) {
					continue
				}
			}
			out[k] = append([]string(nil), v...)
		}
	})
	writeJSON(w, out)
}

// A change of a route's exclusions reaches the hot-standby tunnels running there by itself:
// a left-out path is stopped and taken out of the switcher, one put back is started and
// added — without a rebuild, so users on the other paths aren't cut. It waits a little
// (several ⊘ in a row become one update) and runs as a job on each tunnel.
const routeSkipDelay = 3 * time.Second

var routeSkipTimers = struct {
	sync.Mutex
	m map[string]*time.Timer
}{m: map[string]*time.Timer{}}

func (a *App) routeSkipChanged(iran, foreign string) {
	k := routeKey(iran, foreign)
	routeSkipTimers.Lock()
	defer routeSkipTimers.Unlock()
	if t := routeSkipTimers.m[k]; t != nil {
		t.Stop()
	}
	routeSkipTimers.m[k] = time.AfterFunc(routeSkipDelay, func() {
		routeSkipTimers.Lock()
		delete(routeSkipTimers.m, k)
		routeSkipTimers.Unlock()
		var ts []*Tunnel
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.ServerID == iran && t.ForeignID == foreign && t.HotStandby {
					ts = append(ts, t)
				}
			}
		})
		for _, t := range ts {
			go a.hsSyncPaths(t)
		}
	})
}

// hsSyncPaths applies the route's switches to a hot-standby tunnel as soon as it can. A job
// already on the tunnel (a Start still bringing its paths up, a retry) is waited for: the
// change used to be dropped then and waited for the next Repair pass, many minutes later.
func (a *App) hsSyncPaths(t *Tunnel) {
	deadline := time.Now().Add(hsSyncWait)
	for {
		var up bool
		a.store.View(func(*State) { up = t.Active != "" && t.HotStandby && len(t.Paths) > 0 })
		if up {
			if _, err := a.hsUpdatePaths(t); err == nil {
				return
			}
		} else if a.jobs.running(t.ID) == "" {
			return // stopped: its next Start plans the paths from the switches
		}
		if time.Now().After(deadline) {
			a.pushTInfo(t, fmt.Sprintf("⚠ %s: the route's switches are applied on its next Start/Re-apply (a job kept the tunnel busy)", t.Name))
			return
		}
		time.Sleep(hsSyncPoll)
	}
}

var (
	hsSyncWait = 40 * time.Minute
	hsSyncPoll = 5 * time.Second
)

// hsActiveRemap: the switcher keeps the users' path as its place in the list (the active
// file) and the restarted switcher starts there. Taking a path out moves the ones after it
// up, so users on Paqet v6 behind a dropped Paqet v4 would land on the next path, or on the
// first one past the end. This rewrites the place for the new list before the restart; when
// the users' own path is the one dropped, the switcher starts on the first path, as before.
// The old list's keys go too: the place is already the new list's, and hsKeepActive (the
// switcher's own setup, run next) must not move it a second time by the old list.
func hsActiveRemap(dir string, before, after []HSPath) string {
	at := map[string]int{}
	for k, p := range after {
		at[p.Method+"|"+p.Family] = k
	}
	var cases strings.Builder
	for k, p := range before {
		if n, ok := at[p.Method+"|"+p.Family]; ok {
			fmt.Fprintf(&cases, " %d) n=%d ;;", k, n)
		}
	}
	return fmt.Sprintf(`( cd %s && if [ -s active ] && read -r a rest < active; then
  n=""; case "$a" in%s esac
  if [ -n "$n" ]; then echo "$n $rest" > active.new && mv active.new active; else rm -f active; fi
fi; rm -f keys )
`, shq(dir), cases.String())
}

// hsPathDiff: the running paths now left out on the route, and the methods put back that
// aren't running.
func (a *App) hsPathDiff(t *Tunnel) (drop, add []HSPath) {
	var paths []HSPath
	a.store.View(func(*State) { paths = append([]HSPath(nil), t.Paths...) })
	have := map[string]bool{}
	for _, p := range paths {
		have[p.Method+"|"+p.Family] = true
		if a.routeSkipped(t.ServerID, t.ForeignID, p.Method, p.Family) {
			drop = append(drop, p)
		}
	}
	for _, f := range a.routeFamilies(t) {
		for _, m := range methods {
			if !have[m.ID+"|"+f] && a.hsCandidate(t, m, f) {
				add = append(add, HSPath{Method: m.ID, Family: f})
			}
		}
	}
	return drop, add
}

// hsUpdatePaths brings a running hot-standby tunnel's paths in line with its route's
// exclusions (nil job: nothing to change).
func (a *App) hsUpdatePaths(t *Tunnel) (*Job, error) {
	drop, add := a.hsPathDiff(t)
	if len(drop)+len(add) == 0 {
		return nil, nil
	}
	j, err := a.jobs.start(t.ID, "paths")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(20 * time.Minute)
		defer cancel()
		if err := a.hsUpdatePathsRun(ctx, j, t, drop, add, false); err != nil {
			j.log("ERROR: %v", err)
			j.finish("failed")
			a.pushT(t, fmt.Sprintf("⚠ %s: updating its paths to the route's choices failed: %v", t.Name, err))
			return
		}
		j.finish("ok")
	}()
	return j, nil
}

// hsDropPaths takes the left-out paths drop out of a running hot-standby tunnel: the
// switcher moves to stay (the running paths that remain; left is the new t.Paths), then
// the dropped paths stop. Returns the names of the paths that were running. t.Paths is
// shortened only once the switcher is up: a failed deploy keeps them all (and their retry).
func (a *App) hsDropPaths(ctx context.Context, j *Job, t *Tunnel, ir, kh Host, before, left, stay, drop []HSPath) ([]string, error) {
	var names []string
	var pin, act, fam string
	_ = a.store.Update(func(*State) error {
		pin, act, fam = t.HSPin, t.Active, t.Family
		pinned := false
		for _, p := range stay {
			pinned = pinned || p.Method+"|"+p.Family == t.HSPin
		}
		if !pinned {
			t.HSPin = ""
		}
		for _, d := range drop {
			if d.Method == t.Active && d.Family == t.Family {
				t.Active, t.Family = stay[0].Method, stay[0].Family
			}
			if d.Failed == "" {
				names = append(names, d.label())
			}
		}
		return nil
	})
	j.log("== switcher: %d paths (left-out ones removed first) ==", len(stay))
	sw := a.hsSwitcherPlan(t, stay)
	sw.Setup = hsActiveRemap(hsDir(t), before, stay) + sw.Setup
	if err := a.deploy(ctx, j, "IR", ir, hsUnitTunnel(t), sw); err != nil {
		_ = a.store.Update(func(*State) error { t.HSPin, t.Active, t.Family = pin, act, fam; return nil })
		return nil, fmt.Errorf("switcher: %w", err)
	}
	_ = a.store.Update(func(*State) error { t.Paths = append([]HSPath(nil), left...); return nil })
	for _, d := range drop {
		if d.Failed != "" {
			continue
		}
		j.log("stopping %s (left out on this route)", d.label())
		a.teardownPaths(ctx, ir, kh, t, []HSPath{d})
	}
	return names, nil
}

// retry: add is a failed path tried again (drop holds its old entry) — when it fails again
// nothing changed, so the switcher is left alone and nobody is told.
func (a *App) hsUpdatePathsRun(ctx context.Context, j *Job, t *Tunnel, drop, add []HSPath, retry bool) error {
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return fmt.Errorf("Iran server not found")
	}
	ir, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return fmt.Errorf("Iran server: %w", err)
	}
	kh, _, err := a.foreignHost(ctx, t, nil)
	if err != nil {
		return fmt.Errorf("foreign server: %w", err)
	}
	var left, before []HSPath
	a.store.View(func(*State) {
		before = hsGood(t) // the running switcher's order
		for _, p := range t.Paths {
			gone := false
			for _, d := range drop {
				if d.Method == p.Method && d.Family == p.Family {
					gone = true
				}
			}
			if !gone {
				left = append(left, p)
			}
		}
	})
	// left-out paths stop first, before anything new is installed (that can take minutes): the
	// switcher moves to the paths that stay, then the dropped ones are torn down. A retry
	// (or a drop of paths that never ran) has nothing running to stop: the switcher stays
	running := false
	for _, d := range drop {
		running = running || d.Failed == ""
	}
	var early []string // paths already removed by the step below
	if !retry && running && len(add) > 0 {
		var stay []HSPath
		for _, p := range left {
			if p.Failed == "" {
				stay = append(stay, p)
			}
		}
		if len(stay) > 0 {
			names, err := a.hsDropPaths(ctx, j, t, ir, kh, before, left, stay, drop)
			if err != nil {
				return err
			}
			early = names
			before, drop = stay, nil
		}
	}
	// new paths get a free index, like hsPlan gives them
	_ = a.store.Update(func(st *State) error {
		used := pendingIndices(st)
		for _, o := range st.Tunnels {
			used[o.Index] = true
			for _, p := range o.Paths {
				used[p.Index] = true
			}
		}
		for i := range add {
			add[i].Index = hsFreeIndex(used)
		}
		return nil
	})
	var added []HSPath
	for _, p := range add {
		if p.Index == 0 {
			continue
		}
		p.Opts = a.routeOpts(t, p.Method, p.Family)
		pt, pm := pathTunnel(t, p), methodByID[p.Method]
		j.log("== adding %s ==", p.label())
		err := func() error {
			irP, khP, err := a.build(pm, pt, srv)
			if err != nil {
				return err
			}
			if changed, err := a.reversePreflight(ctx, j, pt, pm, ir, kh); err != nil {
				return err
			} else if changed {
				if irP, khP, err = a.build(pm, pt, srv); err != nil {
					return err
				}
				p.Opts = pt.Options[pm.ID]
			}
			if err := a.deploy(ctx, j, "KH", kh, pt, khP); err != nil {
				return fmt.Errorf("foreign: %w", err)
			}
			if err := a.deploy(ctx, j, "IR", ir, pt, irP); err != nil {
				return fmt.Errorf("Iran: %w", err)
			}
			return nil
		}()
		if err != nil {
			j.log("  ✕ left out: %v", err)
			p.Failed, p.FailedAt = err.Error(), time.Now().Unix()
			_, _ = ir.Run(ctx, teardownScript(pt), nil)
			_, _ = kh.Run(ctx, teardownScript(pt), nil)
		} else {
			j.log("  ✓ up")
		}
		added = append(added, p)
	}
	var good []HSPath
	up := 0
	for _, p := range append(append([]HSPath(nil), left...), added...) {
		if p.Failed == "" {
			good = append(good, p)
		}
	}
	for _, p := range added {
		if p.Failed == "" {
			up++
		}
	}
	if len(good) == 0 {
		return fmt.Errorf("no path would be left — put a method back on the route first")
	}
	if up == 0 && (retry || !running) {
		// nothing new came up and nothing that runs was taken out: the running paths and their
		// switcher stay as they are (only the list in the panel changes)
		_ = a.store.Update(func(*State) error {
			t.Paths = append(left, added...)
			for _, d := range drop {
				if !retry && d.Method == t.Active && d.Family == t.Family {
					t.Active, t.Family = good[0].Method, good[0].Family // as the switcher already has it
				}
			}
			return nil
		})
		if retry {
			j.log("DONE — still not possible on this route; tried again in %s", hsRetryEvery)
			return nil
		}
		j.log("DONE — no new path came up; %d paths running, the switcher left as it was", len(good))
		if len(added) > 0 {
			a.pushTInfo(t, fmt.Sprintf("🔀 %s: paths updated to this route's choices — the added ones could not start (%d running)", t.Name, len(good)))
		}
		return nil
	}
	// the switcher moves to the new list first, then the left-out paths stop: users on one
	// of them go over to the first path the moment the switcher restarts
	var names []string
	_ = a.store.Update(func(*State) error {
		t.Paths = append(left, added...)
		pinned := false
		for _, p := range good {
			pinned = pinned || p.Method+"|"+p.Family == t.HSPin
		}
		if !pinned {
			t.HSPin = ""
		}
		for _, d := range drop {
			if d.Method == t.Active && d.Family == t.Family {
				t.Active, t.Family = good[0].Method, good[0].Family
			}
			if d.Failed == "" { // a path that never ran isn't "removed"
				names = append(names, d.label())
			}
		}
		return nil
	})
	j.log("== switcher: %d paths ==", len(good))
	sw := a.hsSwitcherPlan(t, good)
	sw.Setup = hsActiveRemap(hsDir(t), before, good) + sw.Setup
	if err := a.deploy(ctx, j, "IR", ir, hsUnitTunnel(t), sw); err != nil {
		// the old switcher still runs the left-out paths: they stay in t.Paths (next to the added
		// ones, which run too), so a Stop, a delete or the next update still removes them
		_ = a.store.Update(func(*State) error {
			for _, d := range drop {
				if d.Failed == "" {
					t.Paths = append(t.Paths, d)
				}
			}
			return nil
		})
		return fmt.Errorf("switcher: %w", err)
	}
	for _, d := range drop {
		if d.Failed != "" {
			continue // was never up: nothing to stop
		}
		j.log("stopping %s (left out on this route)", d.label())
		a.teardownPaths(ctx, ir, kh, t, []HSPath{d})
	}
	names = append(early, names...)
	var msg []string
	if len(names) > 0 {
		msg = append(msg, "removed "+strings.Join(names, ", "))
	}
	var an []string
	for _, p := range added {
		if p.Failed == "" {
			an = append(an, p.label())
		}
	}
	if len(an) > 0 {
		msg = append(msg, "added "+strings.Join(an, ", "))
	}
	j.log("DONE — %s; %d paths running", strings.Join(msg, "; "), len(good))
	if retry {
		a.pushTInfo(t, fmt.Sprintf("✅ %s: %s runs again as a hot-standby path (%d running) — it had been refused on this route and was tried again", t.Name, strings.Join(an, ", "), len(good)))
		return nil
	}
	a.pushTInfo(t, fmt.Sprintf("🔀 %s: paths updated to this route's choices — %s (%d running)", t.Name, strings.Join(msg, "; "), len(good)))
	return nil
}
