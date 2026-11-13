package main

import (
	"fmt"
	"net/http"
)

// The benchmark's "Every method" measures every method that can run on the route: all the
// methods of the address family, also the ones left out on the route (the Routes page's /
// Edit checklist — a choice of what runs there, not a sign the method can't work: the
// benchmark only measures, on its temporary tunnel, and the result says whether it would).
// What stays out has a hard reason, said on the dialog and in the job log.

// BenchLeft is a method a run leaves out, and why.
type BenchLeft struct {
	Method string `json:"method"`
	Title  string `json:"title"`
	Why    string `json:"why"`
}

// BenchPlan is what a run of every method on a route measures.
type BenchPlan struct {
	Methods []string    `json:"methods"`       // measured, in order
	Off     []string    `json:"off,omitempty"` // measured though left out on the route
	Left    []BenchLeft `json:"left"`          // not measured
	MaxMB   int         `json:"maxMB"`
}

// benchLeftWhy: the hard reason method m can't be measured on the route over fam ("" = it can).
func benchLeftWhy(st *State, iran, foreign, fam string, m *Method) string {
	if !supportsFamily(m, fam) {
		if fam == "v4" {
			return "IPv6 only"
		}
		return "IPv4 only"
	}
	if m.ID == "spoof" {
		return "UDP-only pipe with forged source IPs — set it up on a tunnel and test with your UDP app"
	}
	if m.ID == "golden" {
		probe := &Tunnel{ID: "bench", ServerID: iran, ForeignID: foreign, Family: fam}
		if o := goldenConflict(st, probe); o != "" {
			return fmt.Sprintf("tunnel %q runs Golden-GRE on this route: a test copy would take its DNS packets", o)
		}
	}
	return ""
}

// benchPlanLocked lists what a run of every method measures on the route over fam. all:
// also the methods left out on the route (the dialog's "Every method"); without it they
// are left out (the automatic weekly run, and older clients). Call inside the store lock.
func benchPlanLocked(st *State, iran, foreign, fam string, all bool) BenchPlan {
	p := BenchPlan{Methods: []string{}, Left: []BenchLeft{}, MaxMB: benchMaxMB}
	skip := map[string]bool{}
	for _, x := range st.RouteSkip[routeKey(iran, foreign)] {
		skip[x] = true
	}
	for _, m := range methods {
		if why := benchLeftWhy(st, iran, foreign, fam, m); why != "" {
			p.Left = append(p.Left, BenchLeft{m.ID, m.Title, why})
			continue
		}
		if skip[m.ID+"|"+fam] {
			if !all {
				p.Left = append(p.Left, BenchLeft{m.ID, m.Title, benchRouteOff})
				continue
			}
			p.Off = append(p.Off, m.ID)
		}
		p.Methods = append(p.Methods, m.ID)
	}
	return p
}

func (a *App) benchPlan(iran, foreign, fam string, all bool) (p BenchPlan) {
	if fam != "v6" {
		fam = "v4"
	}
	a.store.View(func(st *State) { p = benchPlanLocked(st, iran, foreign, fam, all) })
	return
}

// GET /api/bench/plan?iran=&foreign=&family= — what "Every method" measures there.
func (s *Server2) benchPlanAPI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if user, admin := s.who(r); !s.pairVisible(user, admin, q.Get("iran"), q.Get("foreign")) {
		httpErr(w, 404, "not found")
		return
	}
	writeJSON(w, s.app.benchPlan(q.Get("iran"), q.Get("foreign"), q.Get("family"), true))
}

// benchRouteOff is the reason a method left out on the route has in a plan without all.
const benchRouteOff = "left out on this route (Routes page)"

// benchEarlier: method mid's result in the route's earlier results (nil = none).
func benchEarlier(earlier []BenchResult, at int64, mid string) *BenchResult {
	for _, r := range earlier {
		if r.Method == mid && !r.Skipped {
			if r.At == 0 {
				r.At = at
			}
			return &r
		}
	}
	return nil
}
