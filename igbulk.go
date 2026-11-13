package main

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// IG Routing's "All servers" actions and the route table's Apply: jobs over several servers.
// Each server's part of the job ends with one verdict line ("<< ✓ name — what it did") that the
// page turns into one row per server, and the run is kept (IgRun) so the page can say when each
// action last ran and what it found.

// IgRun is the last run of one action over several servers by one account.
type IgRun struct {
	Action string     `json:"action"`
	At     int64      `json:"at"`
	End    int64      `json:"end,omitempty"`
	Job    string     `json:"job"`
	Status string     `json:"status"` // running | ok | error | cancelled
	Res    []IgRunRes `json:"res"`
}

// IgRunRes is one server's result: St = ok | warn | fail | skip.
type IgRunRes struct {
	Srv  string `json:"srv"`
	Name string `json:"name"`
	St   string `json:"st"`
	Say  string `json:"say,omitempty"`
}

var igMark = map[string]string{"ok": "✓", "warn": "!", "fail": "✕", "skip": "–"}

// igTally collects the per-server verdicts of one job and says each one as a line.
type igTally struct{ res []IgRunRes }

func (t *igTally) add(x *Server, st, say string, out func(string)) {
	say = strings.TrimSpace(strings.ReplaceAll(say, "\n", " "))
	if len(say) > 160 {
		say = say[:157] + "..."
	}
	t.res = append(t.res, IgRunRes{x.ID, igLabel(x), st, say})
	l := "<< " + igMark[st] + " " + igLabel(x)
	if say != "" {
		l += " — " + say
	}
	out(l)
}

func (t *igTally) bad() int {
	n := 0
	for _, r := range t.res {
		if r.St == "fail" || r.St == "warn" {
			n++
		}
	}
	return n
}

func igRunKey(user, act string) string { return user + "|" + act }

// igRunStart / igRunEnd keep the account's last run of an action (in the state: it outlives a restart).
func (a *App) igRunStart(user, act, job string) {
	_ = a.store.Update(func(st *State) error {
		if st.IgRuns == nil {
			st.IgRuns = map[string]*IgRun{}
		}
		st.IgRuns[igRunKey(user, act)] = &IgRun{Action: act, At: time.Now().Unix(), Job: job, Status: "running", Res: []IgRunRes{}}
		return nil
	})
}

func (a *App) igRunEnd(user, act, job string, t *igTally) {
	status := "ok"
	if j := a.jobs.get(job); j != nil {
		if j.cancelled() {
			status = "cancelled"
		}
	}
	if status == "ok" && t.bad() > 0 {
		status = "error"
	}
	_ = a.store.Update(func(st *State) error {
		r := st.IgRuns[igRunKey(user, act)]
		if r == nil || r.Job != job { // a newer run of the same action replaced it
			return nil
		}
		r.End, r.Status, r.Res = time.Now().Unix(), status, t.res
		return nil
	})
}

// GET /api/igproxy/runs: this account's last run of each action (only its own servers' rows).
func (s *Server2) igRunsGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	out := map[string]*IgRun{}
	s.app.store.View(func(st *State) {
		for k, v := range st.IgRuns {
			u, act, _ := strings.Cut(k, "|")
			if u != user {
				continue
			}
			c := *v
			c.Res = nil
			for _, x := range v.Res {
				if srv := s.app.store.serverLocked(st, x.Srv); srv == nil || visible(user, admin, srv.Owner) {
					c.Res = append(c.Res, x)
				}
			}
			if c.Res == nil {
				c.Res = []IgRunRes{}
			}
			if c.Status == "running" && s.app.jobs.get(c.Job) == nil { // the panel restarted mid-run
				c.Status = "error"
			}
			out[act] = &c
		}
	})
	writeJSON(w, out)
}

var (
	igOKPair = regexp.MustCompile(`(\w+) (\d+)/(\d+) OK`)
	igSpaces = regexp.MustCompile(`\s+`)
)

// igVerdict sums up one server's output of an action: [st, say].
func igVerdict(act string, rc int, said string) (string, string) {
	said = strings.TrimSpace(said)
	if rc == 255 {
		return "fail", "not reached: " + lastLineOf(said)
	}
	if rc != 0 {
		return "fail", lastLineOf(said)
	}
	switch act {
	case "status_short":
		// "IG=warp6 GOOGLE=direct YTM=ipv6 | proxy 3/3 OK | WARP 1/7 OK | router active | caught 538"
		l := lastLineOf(said)
		parts := strings.Split(l, "|")
		st := "ok"
		if !strings.Contains(l, "router active") {
			st = "fail"
		}
		for _, m := range igOKPair.FindAllStringSubmatch(l, -1) {
			if m[2] == "0" && m[3] != "0" && st == "ok" {
				st = "warn"
			}
		}
		if len(parts) > 1 {
			l = strings.Join(parts[1:], "·")
		}
		return st, igSpaces.ReplaceAllString(strings.TrimSpace(l), " ")
	case "google_rotate":
		for _, l := range strings.Split(said, "\n") {
			if strings.Contains(l, "Google now uses WARP") {
				return "ok", strings.TrimSpace(l)
			}
		}
		if strings.Contains(said, "Google is not on WARP here") {
			return "skip", "Google is not on WARP here"
		}
		return "warn", "not moved: " + lastLineOf(said)
	case "gemusers":
		for _, l := range strings.Split(said, "\n") {
			if _, v, ok := strings.Cut(l, "last "); ok && strings.Contains(l, "Gemini connections") {
				if _, v2, ok := strings.Cut(v, ":"); ok {
					v = strings.TrimSpace(v2)
					if v == "" {
						return "ok", "none"
					}
					return "ok", v
				}
			}
		}
		return "ok", lastLineOf(said)
	case "logs":
		n := 0
		for _, l := range strings.Split(said, "\n") {
			if strings.TrimSpace(l) != "" {
				n++
			}
		}
		return "ok", strconv.Itoa(n) + " lines"
	}
	return "ok", lastLineOf(said)
}

// ---- route table: one Apply for many changes

type igRouteChange struct {
	Srv, Svc, Via string
}

// POST /api/igproxy/routes {changes:[{srv,svc,via}]}: one job; per server its changes one after the
// other, then the agent's info is read again and each change is checked against what it really uses
// (the agent answers 0 also when it leaves a route as it was: IPv6 for a domain-only service).
func (s *Server2) igRoutesApply(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	raw, _ := p["changes"].([]any)
	if len(raw) == 0 {
		httpErr(w, 400, "no changes")
		return
	}
	var order []*Server
	per := map[string][]igRouteChange{}
	for _, x := range raw {
		m, _ := x.(map[string]any)
		c := igRouteChange{igStr(m["srv"]), strings.ToUpper(igStr(m["svc"])), igStr(m["via"])}
		if !contains(igServices, c.Svc) || !igVia.MatchString(c.Via) {
			httpErr(w, 400, "bad change: "+c.Svc+" "+c.Via)
			return
		}
		srv, err := s.igServer(user, admin, c.Srv)
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		if gemHomeRouteBad(srv, c.Svc, c.Via) {
			httpErr(w, 400, igLabel(srv)+": "+gemHomeRefusal)
			return
		}
		if _, ok := per[srv.ID]; !ok {
			order = append(order, srv)
		}
		per[srv.ID] = append(per[srv.ID], c)
	}
	idc := make(chan string, 1)
	t := &igTally{}
	id, err := s.app.igJob(user, "route changes", time.Duration(len(raw))*4*time.Minute+time.Minute, func(ctx context.Context, out func(string)) bool {
		jid := <-idc
		defer s.app.igRunEnd(user, "routes", jid, t)
		out(fmt.Sprintf(">> %d servers", len(order)))
		for _, x := range order {
			if ctx.Err() != nil {
				break
			}
			out("== " + igLabel(x))
			failed := []string{}
			for _, c := range per[x.ID] {
				out("-> igproxy route " + c.Svc + " " + c.Via)
				if rc, said := s.app.igRun(ctx, x, []string{"route", c.Svc, c.Via}, "", 180, out); rc != 0 {
					failed = append(failed, igSvcName(c.Svc)+": "+lastLineOf(said))
				}
			}
			s.app.igForget(x.ID)
			inf := s.app.igInfo(ctx, x)
			okN, notes := 0, failed
			for _, c := range per[x.ID] {
				got := inf[strings.ToLower(c.Svc)]
				switch {
				case inf["ig"] == "":
					// no answer: said once below
				case got == c.Via:
					okN++
				case got != "":
					notes = append(notes, fmt.Sprintf("%s: asked %s, the agent kept %s", igSvcName(c.Svc), c.Via, got))
				}
			}
			if inf["ig"] == "" {
				t.add(x, "fail", "could not read the routes back: "+orStr(inf["err"], inf["state"]), out)
			} else if len(notes) > 0 {
				st := "warn"
				if okN == 0 {
					st = "fail"
				}
				t.add(x, st, fmt.Sprintf("%d of %d applied · %s", okN, len(per[x.ID]), strings.Join(notes, " · ")), out)
			} else {
				t.add(x, "ok", fmt.Sprintf("%d applied", okN), out)
			}
			out("")
		}
		return t.bad() == 0 && ctx.Err() == nil
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	s.app.igRunStart(user, "routes", id)
	idc <- id
	writeJSON(w, map[string]string{"job": id})
}

func igSvcName(g string) string {
	return map[string]string{"IG": "Instagram", "GOOGLE": "Google", "YTM": "YouTube Music", "ADULT": "Adult", "SPOTIFY": "Spotify", "SCLOUD": "SoundCloud", "SNAP": "Snapchat", "CUSTOM": "My sites"}[g]
}
