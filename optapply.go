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

// Options saved on a tunnel's method take effect at once: Save options (the options form)
// stores them and starts a job that rebuilds only what runs with that method — the method's
// hot-standby paths (both families), or the tunnel itself when it runs that method without
// hot standby. Before, Save only stored them and the running path kept its old settings
// until a Re-apply (seen live: تانل انگلیس, IPX carrier set to udp, the core still on tcp).
//
// Hot standby: users on a path being rebuilt are moved to another working path first, the
// path is torn down and deployed with the new options, the switcher has to see it answer,
// then the users go back where they were. A path that worked before and doesn't with the
// new options gets the previous options back, at once and on its own.

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
	res, code, err := s.app.SaveOptions(t, in.Method, in.Options)
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
func (a *App) SaveOptions(t *Tunnel, mid string, opts map[string]string) (map[string]string, int, error) {
	m := methodByID[mid]
	if m == nil {
		return nil, 400, fmt.Errorf("unknown method %q", mid)
	}
	if opts == nil {
		opts = map[string]string{}
	}
	if err := validateOptions(map[string]map[string]string{mid: opts}); err != nil {
		return nil, 400, err
	}
	if id := a.jobs.running(t.ID); id != "" {
		return nil, 409, fmt.Errorf("A job is still running on this tunnel — wait for it to end (or cancel it), then save again. Nothing was changed.")
	}
	var prev map[string]string
	var cand *Tunnel
	a.store.View(func(*State) {
		prev = t.Options[mid]
		cand = withOpts(t, mid, opts, append([]HSPath(nil), t.Paths...))
	})
	changed := optChanged(m, prev, opts)
	u := a.optUseOf(t, mid)
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
		go a.optPlainRollback(j, t, mid, prev, opts)
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

// optPlainRollback: a tunnel without hot standby was re-applied with new options; when
// that failed, it goes back to the options it ran with (and is re-applied with them).
func (a *App) optPlainRollback(j *Job, t *Tunnel, mid string, prev, next map[string]string) {
	for j.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
	if j.snapshot().Status != "error" {
		return // it worked, or was cancelled
	}
	back := false
	_ = a.store.Update(func(*State) error {
		if !reflect.DeepEqual(t.Options[mid], next) {
			return nil // saved again meanwhile: that newer choice stays
		}
		no := make(map[string]map[string]string, len(t.Options))
		for k, v := range t.Options {
			no[k] = v
		}
		no[mid] = prev
		t.Options = no
		back = true
		return nil
	})
	if !back {
		return
	}
	j.log("↩ ROLLED BACK — %s failed with the new options; the previous options are saved again and the tunnel is re-applied with them", methodTitle(mid))
	for i := 0; i < 30 && a.jobs.running(t.ID) != ""; i++ {
		time.Sleep(time.Second)
	}
	a.pushTInfo(t, fmt.Sprintf("↩ %s: %s didn't come up with the new options — back to the previous ones", t.Name, methodTitle(mid)))
	if _, err := a.ApplyRoute(t, mid, ""); err != nil {
		a.pushTInfo(t, fmt.Sprintf("⚠ %s: re-applying %s with the previous options: %v", t.Name, methodTitle(mid), err))
	}
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
	var oldPin, own string
	var auto bool
	a.store.View(func(*State) {
		oldPin, own, auto = t.HSPin, t.Active+"|"+t.Family, t.HSAuto
	})
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
	users, wasOK, _ := a.optPathsState(ctx, ir, t)
	mine := map[string]bool{}
	var keys []string
	for _, p := range u.run {
		k := p.Method + "|" + p.Family
		mine[k] = true
		keys = append(keys, k)
	}
	// users on a path being rebuilt go to another working one for the meantime
	moved := false
	if mine[users] {
		other := ""
		var v *hsView
		if v = a.hsViewOf(t.ID); v != nil {
			for k, key := range v.Keys {
				if !mine[key] && k < len(v.OK) && v.OK[k] {
					other = key
					break
				}
			}
		}
		if other == "" {
			j.log("the users are on %s and no other path answers now — it restarts with them on it (open connections may drop for a few seconds)", users)
		} else {
			j.log("the users are on %s — moving them to %s while it is rebuilt", users, other)
			if msg, err := a.hsPinTo(ctx, t, other); err != nil {
				j.log("  WARN: %v — rebuilding with the users on it", err)
			} else {
				j.log("  %s", msg)
				moved = true
			}
		}
	}
	restore := func() {
		if !moved {
			return
		}
		// manual mode, or the path was the one chosen: back to that choice. Auto mode on a path
		// it picked itself: one press back to it, and the choice stays what it was
		back := oldPin
		if auto && users != oldPin && !(oldPin == "" && users == own) {
			back = users
		}
		j.log("moving the users back to %s", users)
		if msg, err := a.hsPinTo(ctx, t, back); err != nil {
			j.log("  WARN: %v", err)
		} else {
			j.log("  %s", msg)
		}
		if back != oldPin {
			_ = a.store.Update(func(*State) error { t.HSPin = oldPin; return nil })
		}
	}
	var after *Tunnel
	a.store.View(func(*State) { after = withOpts(t, m.ID, next, append([]HSPath(nil), t.Paths...)) })
	errs := a.optRebuild(ctx, j, srv, ir, kh, before, after, u.run, m)
	okNow, v := a.optWait(ctx, ir, t, keys)
	// a path that answered before and doesn't now: the new options broke it
	var broke, still, up []string
	for _, k := range keys {
		switch {
		case okNow[k] && errs[k] == "":
			up = append(up, k)
		case wasOK == nil || wasOK[k]:
			broke = append(broke, k)
		default:
			still = append(still, k)
		}
	}
	if len(broke) > 0 && ctx.Err() == nil {
		j.log("✕ %s answered before and doesn't with the new options — putting the previous options back", strings.Join(broke, ", "))
		rolled := false
		_ = a.store.Update(func(*State) error {
			if !reflect.DeepEqual(t.Options[m.ID], next) {
				return nil
			}
			no := make(map[string]map[string]string, len(t.Options))
			for k, v := range t.Options {
				no[k] = v
			}
			no[m.ID] = prev
			t.Options = no
			np := append([]HSPath(nil), t.Paths...)
			for i := range np {
				if o, ok := oldByIdx[np[i].Index]; ok {
					np[i].Opts = o.Opts
				}
			}
			t.Paths = np
			rolled = true
			return nil
		})
		if !rolled {
			j.log("the options were saved again meanwhile — that newer choice stays")
		} else {
			var cur *Tunnel
			a.store.View(func(*State) { cur = withOpts(t, m.ID, prev, append([]HSPath(nil), t.Paths...)) })
			a.optRebuild(ctx, j, srv, ir, kh, after, cur, u.run, m)
			okBack, vb := a.optWait(ctx, ir, t, broke)
			for _, k := range broke {
				if okBack[k] {
					j.log("  ✓ %s answers again with the previous options (%s)", k, optPathStat(vb, k))
				} else {
					j.log("  ✕ %s doesn't answer with the previous options yet either", k)
				}
			}
			restore()
			j.log("ROLLED BACK — %s didn't work on this route with the new options (%s); the previous options are saved and running again", m.Title, strings.Join(changed, ", "))
			a.pushTInfo(t, fmt.Sprintf("↩ %s: %s didn't come up with the new options (%s) — back to the previous ones", t.Name, m.Title, strings.Join(changed, ", ")))
			j.finish("error")
			return
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
	restore()
	for _, k := range up {
		j.log("  ✓ %s answers with the new options (%s)", k, optPathStat(v, k))
	}
	for _, k := range still {
		why := orStr(errs[k], "no answer through it")
		j.log("  ✕ %s still doesn't answer (%s) — it didn't before the change either, so your options are kept", k, why)
	}
	switch {
	case len(keys) == 0:
		j.log("DONE — options saved")
	case len(up) == len(keys):
		j.log("DONE — %s runs with the new options on %d path(s)", m.Title, len(up))
	default:
		j.log("DONE — options saved; %d of %d path(s) answer", len(up), len(keys))
	}
	j.finish("ok")
}
