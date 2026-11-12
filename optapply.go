package main

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Options saved on a tunnel's method take effect at once: Save & apply (the options form)
// stores them and starts a job that rebuilds only what runs with that method — the method's
// hot-standby paths (both families), or the tunnel itself when it runs that method without
// hot standby. Before, Save only stored them and the running path kept its old settings
// until a Re-apply (seen live: تانل انگلیس, IPX carrier set to udp, the core still on tcp).
//
// Hot standby: users on a path being rebuilt are moved to another working path first, the
// path is torn down and deployed with the new options, the switcher has to see it answer,
// then the users go back where they were. A key the user set is marked manual (OptsManual)
// and stays as set: no rollback, and nothing automatic (the benchmark's carrier, a path's
// own options) replaces it. A path that doesn't answer with it is reported as failing, with
// the reason; the users stay on a working path. ↺ Defaults clears the manual marks.


// optWaitUp is how long a rebuilt path has to answer the switcher's checks.
var optWaitUp = 90 * time.Second

// optPoll is how often the switcher's state is read meanwhile.
var optPoll = 3 * time.Second

// optFull is a method's options with the defaults filled in, for comparing two of them.
func optFull(m *Method, o map[string]string) map[string]string {
	out := map[string]string{}
	for _, f := range m.Fields {
		out[f.Key] = f.Default
	}
	for k, v := range o {
		if v == "" {
			if f := methodField(m, k); f != nil {
				v = f.Default
			}
		}
		out[k] = v
	}
	return out
}

// optChanged: the keys whose value differs between prev and next (defaults filled in).
func optChanged(m *Method, prev, next map[string]string) []string {
	a, b := optFull(m, prev), optFull(m, next)
	var out []string
	for k := range b {
		if a[k] != b[k] {
			out = append(out, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// optPathOpts is a path's own options once the user set keys by hand: the user's value
// wins over what the benchmark or a preflight put on the path for those keys (a path kept
// the benchmark's carrier over the one picked in the form, so the change never reached it).
func optPathOpts(own map[string]string, changed []string) map[string]string {
	if len(own) == 0 {
		return own
	}
	out := map[string]string{}
	for k, v := range own {
		out[k] = v
	}
	for _, k := range changed {
		delete(out, k)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// manualOpt: key of method mid was set by hand (see OptsManual).
func (t *Tunnel) manualOpt(mid, key string) bool {
	for _, k := range t.OptsManual[mid] {
		if k == key {
			return true
		}
	}
	return false
}

// markManual adds keys to mid's hand-set keys (reset: clears them). Copy-on-write, inside
// store.Update (pathTunnel and routeOpts read the list without the lock).
func (t *Tunnel) markManual(mid string, keys []string, reset bool) {
	nm := make(map[string][]string, len(t.OptsManual)+1)
	for k, v := range t.OptsManual {
		nm[k] = v
	}
	if reset {
		delete(nm, mid)
	} else {
		nm[mid] = optUnion(nm[mid], keys)
	}
	if len(nm) == 0 {
		nm = nil
	}
	t.OptsManual = nm
}

// optUnion is a and b without repeats, sorted.
func optUnion(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range append(append([]string(nil), a...), b...) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// withOpts is a copy of t with method mid's options set to o (and the paths given), for
// building plans without touching the stored tunnel.
func withOpts(t *Tunnel, mid string, o map[string]string, paths []HSPath) *Tunnel {
	c := *t
	c.Options = map[string]map[string]string{}
	for k, v := range t.Options {
		c.Options[k] = v
	}
	c.Options[mid] = o
	if paths != nil {
		c.Paths = paths
	}
	return &c
}

// tunnelOptions saves method options and puts them into effect on the servers.
func (s *Server2) tunnelOptions(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID, Method string
		Options    map[string]string
		Reset      bool // ↺ Defaults: the method's defaults, nothing marked manual
		Confirm    bool // the user agreed to restart the users' path (no other path answers)
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	t := s.app.store.Tunnel(in.ID)
	user, admin := s.who(r)
	owner := ""
	if t != nil {
		s.app.store.View(func(*State) { owner = t.Owner })
	}
	if t == nil || !visible(user, admin, owner) {
		httpErr(w, 404, "tunnel not found")
		return
	}
	res, code, err := s.app.SaveOptionsAsk(t, in.Method, in.Options, in.Reset, in.Confirm)
	if err != nil {
		httpErr(w, code, err.Error())
		return
	}
	writeJSON(w, res)
}

// optUse is what runs with method mid on t now.
type optUse struct {
	plain bool     // the tunnel itself, no hot standby
	run   []HSPath // running hot-standby paths of mid
	fail  []HSPath // hot-standby paths of mid that couldn't start last time
}

func (a *App) optUseOf(t *Tunnel, mid string) optUse {
	var u optUse
	a.store.View(func(*State) {
		if t.Active == "" {
			return
		}
		if !t.HotStandby || len(t.Paths) == 0 {
			u.plain = t.Active == mid
			return
		}
		for _, p := range t.Paths {
			if p.Method != mid {
				continue
			}
			if p.Failed == "" {
				u.run = append(u.run, p)
			} else {
				u.fail = append(u.fail, p)
			}
		}
	})
	return u
}

// SaveOptions validates, stores and applies method mid's options on t. The result has
// "job" when something is rebuilt, "note" otherwise. A value that is refused, or a plan
// that can't be built with it, changes nothing.
func (a *App) SaveOptions(t *Tunnel, mid string, opts map[string]string, reset bool) (map[string]string, int, error) {
	return a.SaveOptionsAsk(t, mid, opts, reset, true)
}

// SaveOptionsAsk is SaveOptions; without confirmed, a change that would restart the users'
// path while no other path answers is not saved: the result has "confirm" (what would happen)
// and the panel asks first.
func (a *App) SaveOptionsAsk(t *Tunnel, mid string, opts map[string]string, reset, confirmed bool) (map[string]string, int, error) {
	m := methodByID[mid]
	if m == nil {
		return nil, 400, fmt.Errorf("unknown method %q", mid)
	}
	if opts == nil || reset {
		opts = map[string]string{}
	}
	for k, v := range opts { // a Persian keypad: ۱۴۰۰ is 1400
		if f := methodField(m, k); f != nil && f.Type == "number" {
			opts[k] = latinNum(v)
		}
	}
	if err := validateOptions(map[string]map[string]string{mid: opts}); err != nil {
		return nil, 400, err
	}
	if id := a.jobs.running(t.ID); id != "" {
		return nil, 409, fmt.Errorf("A job is still running on this tunnel — wait for it to end (or cancel it), then save again. Nothing was changed.")
	}
	var prev map[string]string
	var cand *Tunnel
	var wasManual []string
	a.store.View(func(*State) {
		prev, wasManual = t.Options[mid], t.OptsManual[mid]
		cand = withOpts(t, mid, opts, append([]HSPath(nil), t.Paths...))
	})
	changed := optChanged(m, prev, opts)
	if reset {
		// the manual marks go too: what was set by hand may now be what the benchmark picks
		changed = optUnion(changed, wasManual)
	}
	u := a.optUseOf(t, mid)
	if !confirmed && len(changed) > 0 && len(u.run) > 0 {
		if msg := a.optRestartsUsers(t, u.run); msg != "" {
			return map[string]string{"confirm": msg}, 200, nil
		}
	}
	// the plans are built with the new values before anything is stored: one that can't be
	// built (a port another tunnel holds, a value the method can't use) is refused here
	if srv := a.store.Server(t.ServerID); srv != nil && len(changed) > 0 {
		if u.plain {
			if _, _, err := a.build(m, cand, srv); err != nil {
				return nil, 400, fmt.Errorf("Not saved — %s can't run with these options: %v", m.Title, err)
			}
		}
		for _, p := range u.run {
			p.Opts = optPathOpts(p.Opts, changed)
			if _, _, err := a.build(m, pathTunnel(cand, p), srv); err != nil {
				return nil, 400, fmt.Errorf("Not saved — %s can't run with these options: %v", p.label(), err)
			}
		}
	}
	err := a.store.Update(func(st *State) error {
		if err := portClash(st, cand, ""); err != nil {
			return err
		}
		// copy-on-write: the monitor and traffic collector read Options without the lock
		no := make(map[string]map[string]string, len(t.Options)+1)
		for k, v := range t.Options {
			no[k] = v
		}
		no[mid] = opts
		t.Options = no
		t.markManual(mid, changed, reset)
		if len(changed) > 0 {
			// the user's values win on the paths of this method from now on (see optPathOpts)
			np := append([]HSPath(nil), t.Paths...)
			for i := range np {
				if np[i].Method == mid {
					np[i].Opts = optPathOpts(np[i].Opts, changed)
				}
			}
			t.Paths = np
		}
		t.Updated = time.Now().Unix()
		return nil
	})
	if err != nil {
		return nil, 400, err
	}
	if reset && len(changed) > 0 {
		// back to defaults: the benchmark's pick for this route applies again where it has one
		for _, p := range u.run {
			ro := a.routeOpts(cand, p.Method, p.Family)
			_ = a.store.Update(func(*State) error {
				for i := range t.Paths {
					if t.Paths[i].Index != p.Index || len(ro) == 0 {
						continue
					}
					o := map[string]string{}
					for k, v := range ro {
						o[k] = v
					}
					for k, v := range t.Paths[i].Opts {
						o[k] = v
					}
					t.Paths[i].Opts = o
				}
				return nil
			})
		}
	}
	out := map[string]string{"ok": "1"}
	switch {
	case len(changed) == 0:
		out["note"] = "Saved — nothing changed, so nothing was rebuilt."
		return out, 200, nil
	case u.plain:
		j, err := a.ApplyRoute(t, mid, "")
		if err != nil {
			out["note"] = "Saved, but not applied: " + err.Error()
			return out, 200, nil
		}
		out["job"] = j.ID
		return out, 200, nil
	case len(u.run)+len(u.fail) > 0:
		j, err := a.jobs.start(t.ID, "options:"+mid)
		if err != nil {
			out["note"] = "Saved, but not applied: " + err.Error()
			return out, 200, nil
		}
		go func() {
			defer a.jobs.done(j)
			ctx, cancel := j.context(25 * time.Minute)
			defer cancel()
			a.optApplyHS(ctx, j, t, m, prev, opts, changed, u)
		}()
		out["job"] = j.ID
		return out, 200, nil
	}
	if t.Active == "" {
		out["note"] = "Saved — the tunnel is stopped; these options are used when it starts."
	} else {
		out["note"] = "Saved — " + m.Title + " doesn't run on this tunnel now; these options are used when it does."
	}
	return out, 200, nil
}

// optRestartsUsers: the users are on one of paths ps and no other path answers — the
// rebuild restarts their path with them on it. The message says so ("" = they aren't).
func (a *App) optRestartsUsers(t *Tunnel, ps []HSPath) string {
	v := a.hsViewOf(t.ID)
	if v == nil || v.Active < 0 || v.Active >= len(v.Keys) {
		return ""
	}
	mine := map[string]bool{}
	for _, p := range ps {
		mine[p.Method+"|"+p.Family] = true
	}
	users := v.Keys[v.Active]
	if !mine[users] || hsBestOther(v, mine) != "" {
		return ""
	}
	return "The users are on " + users + " and no other path answers now: this change restarts it with them on it — open connections drop for a few seconds and clients reconnect."
}

// optWhy is what is known about a path that doesn't answer: its deploy error, else what
// the switcher read about its core on the Iran server.
func optWhy(v *hsView, key, deployErr string) string {
	if deployErr != "" {
		return deployErr
	}
	if v != nil {
		for k, kk := range v.Keys {
			if kk == key && k < len(v.Why) && v.Why[k] != "" {
				return v.Why[k]
			}
		}
	}
	return "it runs on both servers but nothing comes through it on this route"
}

// optPathsState reads the switcher once: which path the users are on ("method|family")
// and, per key, whether it answers.
func (a *App) optPathsState(ctx context.Context, ir Host, t *Tunnel) (users string, ok map[string]bool, v *hsView) {
	var seen int64
	a.store.View(func(*State) { seen = t.HSSeen })
	v, events, err := a.hsRead(ctx, ir, t, seen)
	if err != nil || v == nil {
		return "", nil, nil
	}
	a.hsReport(t, v, events)
	ok = map[string]bool{}
	for k, key := range v.Keys {
		ok[key] = k < len(v.OK) && v.OK[k]
	}
	if v.Active >= 0 && v.Active < len(v.Keys) {
		users = v.Keys[v.Active]
	}
	return users, ok, v
}

// optPathStat is a short "rtt 42 ms, loss 0%, 85 Mbit/s" for a path the switcher measured.
func optPathStat(v *hsView, key string) string {
	if v == nil {
		return ""
	}
	for k, kk := range v.Keys {
		if kk != key {
			continue
		}
		var s []string
		if k < len(v.RTT) && v.RTT[k] >= 0 {
			s = append(s, fmt.Sprintf("rtt %d ms", v.RTT[k]))
		}
		if k < len(v.Loss) && v.Loss[k] >= 0 {
			s = append(s, fmt.Sprintf("loss %.0f%%", v.Loss[k]))
		}
		if k < len(v.Kbps) && v.Kbps[k] > 0 {
			s = append(s, fmt.Sprintf("%.1f Mbit/s", float64(v.Kbps[k])/1000))
		}
		return strings.Join(s, ", ")
	}
	return ""
}

// optRebuild tears path set ps down as built from `from` and deploys it as built from `to`,
// on both servers (foreign first). Returns the paths that deployed, by key, and why the
// others didn't. The switcher is redeployed (same paths, same order, users kept on their
// path) only when its own files for these paths change (an L3 path became a forwarder…).
func (a *App) optRebuild(ctx context.Context, j *Job, srv *Server, ir, kh Host, from, to *Tunnel, ps []HSPath, m *Method) map[string]string {
	errs := map[string]string{}
	for _, p := range ps {
		key := p.Method + "|" + p.Family
		var np HSPath
		for _, q := range to.Paths {
			if q.Index == p.Index {
				np = q
			}
		}
		if np.Method == "" {
			np = p
		}
		j.log("== rebuilding %s on both servers ==", p.label())
		a.teardownPaths(ctx, ir, kh, from, []HSPath{p})
		pt := pathTunnel(to, np)
		err := func() error {
			irP, khP, err := a.build(m, pt, srv)
			if err != nil {
				return err
			}
			if changed, err := a.reversePreflight(ctx, j, pt, m, ir, kh); err != nil {
				return err
			} else if changed {
				if irP, khP, err = a.build(m, pt, srv); err != nil {
					return err
				}
				moved := movedOpts(np.Opts, to.Options[m.ID], pt.Options[m.ID])
				_ = a.store.Update(func(*State) error {
					for i := range to.Paths {
						if to.Paths[i].Index == np.Index {
							to.Paths[i].Opts = moved
						}
					}
					return nil
				})
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
			j.log("  ✕ %v", err)
			errs[key] = err.Error()
		} else {
			j.log("  ✓ deployed — waiting for the switcher to see it answer")
		}
	}
	// the switcher's own files for the paths (selector rules, flush, targets) follow the
	// options too: compared without the pin, which this job may have moved for the users
	good := hsGood(from)
	swOld, swNew := a.hsSwitcherPlan(from, good), a.hsSwitcherPlan(to, good)
	delete(swOld.Files, hsDir(from)+"/pin.new")
	delete(swNew.Files, hsDir(to)+"/pin.new")
	if !reflect.DeepEqual(swOld.Files, swNew.Files) {
		j.log("== switcher: same paths, new rules for the rebuilt ones (users stay on their path) ==")
		sw := a.hsSwitcherPlan(a.pinNow(to), good)
		sw.Setup = hsActiveRemap(hsDir(to), good, good) + sw.Setup
		if err := a.deploy(ctx, j, "IR", ir, hsUnitTunnel(to), sw); err != nil {
			j.log("  WARN: switcher: %v", err)
		}
	}
	return errs
}

// pinNow is to with the pin as stored now (the switcher's pin.new must name the users' choice).
func (a *App) pinNow(to *Tunnel) *Tunnel {
	c := *to
	a.store.View(func(st *State) {
		if cur := a.store.tunnelLocked(st, to.ID); cur != nil {
			c.HSPin, c.HSAuto = cur.HSPin, cur.HSAuto
		}
	})
	return &c
}

// optWait polls the switcher until every key in keys answers (or optWaitUp passes).
func (a *App) optWait(ctx context.Context, ir Host, t *Tunnel, keys []string) (map[string]bool, *hsView) {
	var ok map[string]bool
	var v *hsView
	for end := time.Now().Add(optWaitUp); ctx.Err() == nil; {
		_, ok, v = a.optPathsState(ctx, ir, t)
		all := ok != nil
		for _, k := range keys {
			all = all && ok[k]
		}
		if all || !time.Now().Before(end) {
			break
		}
		time.Sleep(optPoll)
	}
	if ok == nil {
		ok = map[string]bool{}
	}
	return ok, v
}

// optApplyHS rebuilds the hot-standby paths of method m with its new options (see the top).
func (a *App) optApplyHS(ctx context.Context, j *Job, t *Tunnel, m *Method, prev, next map[string]string, changed []string, u optUse) {
	j.log("%s options changed (%s) — rebuilding only its paths; the other paths keep running", m.Title, strings.Join(changed, ", "))
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
	var oldPaths []HSPath
	// the paths as they ran before the save: their own options from before optPathOpts
	// (the store already has the new ones; the paths' old Opts came in with u)
	oldByIdx := map[int]HSPath{}
	for _, p := range append(append([]HSPath(nil), u.run...), u.fail...) {
		oldByIdx[p.Index] = p
	}
	a.store.View(func(*State) {
		for _, p := range t.Paths {
			if o, ok := oldByIdx[p.Index]; ok {
				oldPaths = append(oldPaths, o)
			} else {
				oldPaths = append(oldPaths, p)
			}
		}
	})
	before := withOpts(t, m.ID, prev, oldPaths)
	mine := map[string]bool{}
	var keys []string
	for _, p := range u.run {
		k := p.Method + "|" + p.Family
		mine[k] = true
		keys = append(keys, k)
	}
	// users on a path being rebuilt go to the best other working one for the meantime
	restore, _, _ := a.hsStepAside(ctx, j, ir, t, mine, "it restarts with them on it (open connections may drop for a few seconds)")
	var after *Tunnel
	a.store.View(func(*State) { after = withOpts(t, m.ID, next, append([]HSPath(nil), t.Paths...)) })
	errs := a.optRebuild(ctx, j, srv, ir, kh, before, after, u.run, m)
	okNow, v := a.optWait(ctx, ir, t, keys)
	// the user's values stay whatever happens: a path that doesn't answer with them is shown
	// as failing, with the reason, and the switcher keeps the users on a working path
	var up, down []string
	for _, k := range keys {
		if okNow[k] && errs[k] == "" {
			up = append(up, k)
		} else {
			down = append(down, k)
		}
	}
	// a path that couldn't start last time: tried again with the new options
	for _, p := range u.fail {
		j.log("== %s couldn't start last time — trying it again with the new options ==", p.label())
		var cur HSPath
		a.store.View(func(*State) {
			for _, q := range t.Paths {
				if q.Index == p.Index {
					cur = q
				}
			}
		})
		if cur.Method == "" {
			continue
		}
		if err := a.hsUpdatePathsRun(ctx, j, t, []HSPath{cur}, []HSPath{{Method: p.Method, Family: p.Family}}, true); err != nil {
			j.log("  ✕ %v", err)
		}
	}
	// back to the users' choice even when the path doesn't answer: the switcher moves them
	// only to a path that answers, so they stay on the working one and go back (manual mode)
	// once it does
	restore()
	for _, k := range up {
		j.log("  ✓ %s answers with your options (%s)", k, optPathStat(v, k))
	}
	for _, k := range down {
		j.log("  ✕ %s doesn't answer with these options: %s — your options are kept (nothing puts other ones back); ↺ Defaults returns to the method's defaults", k, optWhy(v, k, errs[k]))
	}
	switch {
	case len(keys) == 0:
		j.log("DONE — options saved")
	case len(down) == 0:
		j.log("DONE — %s runs with your options on %d path(s)", m.Title, len(up))
	default:
		j.log("FAILING — options saved and running, but %d of %d path(s) don't answer with them; the users stay on a working path", len(down), len(keys))
		a.pushTInfo(t, fmt.Sprintf("⚠ %s: %s doesn't answer with the options you set (%s) — kept as you set them; users stay on a working path", t.Name, m.Title, strings.Join(changed, ", ")))
		j.finish("error")
		return
	}
	j.finish("ok")
}
