package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Removing one hot-standby path from the tunnel card (⋯ → Remove), without the Edit form:
// the path goes on the tunnel's own HSOff list, so auto mode, Repair and the hourly retry
// never bring it back, and it is taken out like a path left out on the route — the switcher
// moves to the paths that stay first, then the path's units, files and firewall rules go on
// both servers. The users' path and the last working one can't be removed. "Put back" takes
// it off the list again and starts it as a new path.

// hsExcluded: the user doesn't want path mid|fam on t — left out on the route (Routes page,
// Edit's checklist) or removed from this tunnel.
func (a *App) hsExcluded(t *Tunnel, mid, fam string) bool {
	if a.routeSkipped(t.ServerID, t.ForeignID, mid, fam) {
		return true
	}
	off := false
	a.store.View(func(*State) { off = contains(t.HSOff, mid+"|"+fam) })
	return off
}

// hsUsersKeyLocked is "method|family" of the path the users are on: what the switcher last
// reported (v), else the chosen one, else the tunnel's own. Call inside the store lock.
func hsUsersKeyLocked(t *Tunnel, v *hsView) string {
	if v != nil && v.Active >= 0 && v.Active < len(v.Keys) {
		return v.Keys[v.Active]
	}
	if t.HSPin != "" {
		return t.HSPin
	}
	return t.Active + "|" + t.Family
}

// hsRemoveCheck says why path key can't be removed from t now ("" = it can), and the path.
// v is the switcher's last view (read outside the lock). Call inside the store lock.
func hsRemoveCheckLocked(t *Tunnel, v *hsView, key string) (HSPath, string) {
	if !t.HotStandby || t.Active == "" || len(t.Paths) == 0 {
		return HSPath{}, "this tunnel isn't running with hot standby"
	}
	var p HSPath
	found := false
	for _, o := range t.Paths {
		if o.Method+"|"+o.Family == key {
			p, found = o, true
		}
	}
	if !found {
		return HSPath{}, "that path isn't on this tunnel"
	}
	if p.Failed == "" {
		if hsUsersKeyLocked(t, v) == key {
			return p, "the users are on " + p.label() + " — move them to another path with \"use\" first"
		}
		if len(hsGood(t)) <= 1 {
			return p, p.label() + " is the last working path of this tunnel"
		}
		// working as the switcher sees it: with the users' path down, the one path still
		// answering is all they have to move to
		if v != nil && len(v.OK) == len(v.Keys) {
			self, others := false, 0
			for k, key2 := range v.Keys {
				if key2 == key {
					self = v.OK[k]
				} else if v.OK[k] {
					others++
				}
			}
			if self && others == 0 {
				return p, p.label() + " is the last working path of this tunnel"
			}
		}
	}
	return p, ""
}

// hsRemovePath takes path mid|fam off a running hot-standby tunnel for good (a "paths" job).
func (a *App) hsRemovePath(t *Tunnel, mid, fam string) (*Job, error) {
	key := mid + "|" + fam
	var why string
	v := a.hsViewOf(t.ID)
	a.store.View(func(*State) { _, why = hsRemoveCheckLocked(t, v, key) })
	if why != "" {
		return nil, fmt.Errorf("%s", why)
	}
	j, err := a.jobs.start(t.ID, "paths")
	if err != nil {
		return nil, err
	}
	// checked again with the job held: nothing else changes the paths now
	var p HSPath
	v = a.hsViewOf(t.ID)
	_ = a.store.Update(func(*State) error {
		if p, why = hsRemoveCheckLocked(t, v, key); why == "" && !contains(t.HSOff, key) {
			t.HSOff = append(append([]string(nil), t.HSOff...), key)
		}
		return nil
	})
	if why != "" {
		j.log("ERROR: %s", why)
		j.finish("error")
		a.jobs.done(j)
		return nil, fmt.Errorf("%s", why)
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(5 * time.Minute)
		defer cancel()
		j.log("removing %s from this tunnel's hot-standby paths (by hand) — auto mode and Repair won't add it back; the other paths and their users are left alone", p.label())
		if err := a.hsUpdatePathsRun(ctx, j, t, []HSPath{p}, nil, false); err != nil {
			j.log("ERROR: %v", err)
			j.finish("failed")
			return
		}
		// a Stop + Start plans the paths from the tunnel's own method: that is never the
		// removed one (hsUpdatePathsRun moved Active off it; Selected follows)
		_ = a.store.Update(func(*State) error {
			if contains(t.HSOff, t.Selected+"|"+t.Family) {
				t.Selected = t.Active
			}
			return nil
		})
		j.finish("ok")
	}()
	return j, nil
}

// hsUnremove takes mid|fam off t's removed list (no job). Reports whether it was on it.
func (a *App) hsUnremove(t *Tunnel, mid, fam string) bool {
	key, was := mid+"|"+fam, false
	_ = a.store.Update(func(*State) error {
		var keep []string
		for _, k := range t.HSOff {
			if k == key {
				was = true
			} else {
				keep = append(keep, k)
			}
		}
		if was {
			t.HSOff = keep
		}
		return nil
	})
	return was
}

// hsRestorePath puts a removed path back: off the list, and started on a running tunnel
// (nil job: nothing to start now — stopped, busy, or the route leaves it out).
func (a *App) hsRestorePath(t *Tunnel, mid, fam string) (*Job, error) {
	if !a.hsUnremove(t, mid, fam) {
		return nil, fmt.Errorf("that path isn't removed on this tunnel")
	}
	var up bool
	a.store.View(func(*State) { up = t.HotStandby && t.Active != "" && len(t.Paths) > 0 })
	if !up {
		return nil, nil
	}
	return a.hsUpdatePaths(t)
}

func hsPathArg(path string) (mid, fam string, ok bool) {
	mid, fam, _ = strings.Cut(path, "|")
	return mid, fam, methodByID[mid] != nil && (fam == "v4" || fam == "v6")
}

// tunnelHSRemove: POST {id, path: "method|family"} → {job}.
func (s *Server2) tunnelHSRemove(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Path string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	mid, fam, ok := hsPathArg(in.Path)
	if !ok {
		httpErr(w, 400, "bad path")
		return
	}
	j, err := s.app.hsRemovePath(t, mid, fam)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

// tunnelHSRestore: POST {id, path} → {job} ("" when nothing had to start now).
func (s *Server2) tunnelHSRestore(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Path string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	mid, fam, ok := hsPathArg(in.Path)
	if !ok {
		httpErr(w, 400, "bad path")
		return
	}
	j, err := s.app.hsRestorePath(t, mid, fam)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	out := map[string]string{"job": ""}
	if j != nil {
		out["job"] = j.ID
	}
	writeJSON(w, out)
}
