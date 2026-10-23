package main

import "net/http"

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
		s.app.setRouteSkip(in.Iran, in.Foreign, in.Method, in.Family, in.Skip)
	}
	out := map[string][]string{}
	s.app.store.View(func(st *State) {
		for k, v := range st.RouteSkip {
			out[k] = append([]string(nil), v...)
		}
	})
	writeJSON(w, out)
}
