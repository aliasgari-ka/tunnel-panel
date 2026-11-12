package main

import (
	"context"
	"net/http"
	"time"
)

// Repair from the panel (repair.go): /api/repair/check only reads and says what would be
// fixed; /api/repair/apply runs the chosen items; /api/repair/status is the run in progress,
// the last one and the automatic mode. An account sees and repairs only its own tunnels.

// visibleRun keeps the tunnels of a run this account may see (nil when none is left).
func visibleRun(r *RepairRun, user string, admin bool) *RepairRun {
	if r == nil || admin {
		return r
	}
	c := *r
	c.Tunnels = nil
	for _, t := range r.Tunnels {
		if visible(user, admin, t.Owner) {
			c.Tunnels = append(c.Tunnels, t)
		}
	}
	if len(c.Tunnels) == 0 {
		return nil
	}
	c.By = ""
	return &c
}

// repairCheckH: POST {IDs} (none = every running tunnel of this account) → the check.
func (s *Server2) repairCheckH(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct{ IDs []string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	var ts []*Tunnel
	for _, t := range s.app.runningTunnels(in.IDs) {
		if s.tunnelVisible(user, admin, t.ID) {
			ts = append(ts, t)
		}
	}
	if len(in.IDs) > 0 && len(ts) == 0 {
		httpErr(w, 404, "not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 80*time.Second)
	defer cancel()
	writeJSON(w, map[string]any{"tunnels": s.app.repairCheckAll(ctx, ts), "at": time.Now().Unix()})
}

// repairApplyH: POST {Picks: {tunnel id: [kinds]}, AllowUsers} → the job.
func (s *Server2) repairApplyH(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct {
		Picks      map[string][]string
		AllowUsers bool
	}
	if err := readJSON(r, &in); err != nil || len(in.Picks) == 0 {
		httpErr(w, 400, "choose what to fix")
		return
	}
	for id := range in.Picks {
		if !s.tunnelVisible(user, admin, id) {
			httpErr(w, 404, "not found")
			return
		}
	}
	by := user
	j, err := s.app.RepairPicked("from the panel", by, in.Picks, in.AllowUsers)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

// repairStatusH: GET → {run (in progress or just ended), last, auto}.
func (s *Server2) repairStatusH(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var last *RepairRun
	var mode string
	s.app.store.View(func(st *State) { last, mode = copyRun(st.LastRepair), st.RepairAuto })
	out := map[string]any{"run": visibleRun(s.app.repair.snapshot(), user, admin), "last": visibleRun(last, user, admin)}
	if admin {
		out["auto"] = mode
	}
	writeJSON(w, out)
}

// repairAutoH: POST {Mode: "" | "all" | "off"} (admin) sets what the automatic Repair may do.
func (s *Server2) repairAutoH(w http.ResponseWriter, r *http.Request) {
	var in struct{ Mode string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	switch in.Mode {
	case repairAutoSafe, repairAutoAll, repairAutoOff:
	default:
		httpErr(w, 400, "unknown mode")
		return
	}
	_ = s.app.store.Update(func(st *State) error { st.RepairAuto = in.Mode; return nil })
	writeJSON(w, map[string]string{"auto": in.Mode})
}
