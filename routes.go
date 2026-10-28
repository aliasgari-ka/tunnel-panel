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

// routeSkip: GET → every route's exclusions; POST {iran, foreign, method, family, skip}.
func (s *Server2) routeSkip(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Iran, Foreign, Method, Family string
			Skip                          bool
		}
		if err := readJSON(r, &in); err != nil || methodByID[in.Method] == nil || (in.Family != "v4" && in.Family != "v6") {
			httpErr(w, 400, "bad request")
			return
		}
		if user, admin := s.who(r); !s.pairVisible(user, admin, in.Iran, in.Foreign) {
			httpErr(w, 404, "not found")
			return
		}
		s.app.setRouteSkip(in.Iran, in.Foreign, in.Method, in.Family, in.Skip)
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
const routeSkipDelay = 20 * time.Second

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
				if t.ServerID == iran && t.ForeignID == foreign && t.Active != "" && t.HotStandby && len(t.Paths) > 0 {
					ts = append(ts, t)
				}
			}
		})
		for _, t := range ts {
			if _, err := a.hsUpdatePaths(t); err != nil {
				a.pushT(t, fmt.Sprintf("⚠ %s: the route's left-out methods are applied on its next Start/Re-apply (%v)", t.Name, err))
			}
		}
	})
}

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
		if err := a.hsUpdatePathsRun(ctx, j, t, drop, add); err != nil {
			j.log("ERROR: %v", err)
			j.finish("failed")
			a.pushT(t, fmt.Sprintf("⚠ %s: updating its paths to the route's choices failed: %v", t.Name, err))
			return
		}
		j.finish("ok")
	}()
	return j, nil
}

func (a *App) hsUpdatePathsRun(ctx context.Context, j *Job, t *Tunnel, drop, add []HSPath) error {
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
			for n := 1; n < 250; n++ {
				if !used[n] {
					add[i].Index, used[n] = n, true
					break
				}
			}
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
			p.Failed = err.Error()
			_, _ = ir.Run(ctx, teardownScript(pt), nil)
			_, _ = kh.Run(ctx, teardownScript(pt), nil)
		} else {
			j.log("  ✓ up")
		}
		added = append(added, p)
	}
	var good []HSPath
	for _, p := range append(append([]HSPath(nil), left...), added...) {
		if p.Failed == "" {
			good = append(good, p)
		}
	}
	if len(good) == 0 {
		return fmt.Errorf("no path would be left — put a method back on the route first")
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
			names = append(names, d.label())
		}
		return nil
	})
	j.log("== switcher: %d paths ==", len(good))
	sw := a.hsSwitcherPlan(t, good)
	sw.Setup = hsActiveRemap(hsDir(t), before, good) + sw.Setup
	if err := a.deploy(ctx, j, "IR", ir, hsUnitTunnel(t), sw); err != nil {
		return fmt.Errorf("switcher: %w", err)
	}
	for _, d := range drop {
		pt := pathTunnel(t, d)
		j.log("stopping %s (left out on this route)", d.label())
		_, _ = ir.Run(ctx, teardownScript(pt), nil)
		_, _ = kh.Run(ctx, teardownScript(pt), nil)
	}
	var msg []string
	if len(names) > 0 {
		msg = append(msg, "removed "+strings.Join(names, ", "))
	}
	if len(added) > 0 {
		var an []string
		for _, p := range added {
			an = append(an, p.label())
		}
		msg = append(msg, "added "+strings.Join(an, ", "))
	}
	j.log("DONE — %s; %d paths running", strings.Join(msg, "; "), len(good))
	a.pushT(t, fmt.Sprintf("🔀 %s: paths updated to this route's choices — %s (%d running)", t.Name, strings.Join(msg, "; "), len(good)))
	return nil
}
