package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// IG routing HTTP API (all "self": each handler keeps an account to its own servers).

// igServersOf: the servers on the IG routing page this account may use (admin: all).
func (s *Server2) igServersOf(user string, admin bool, view string) []*Server {
	var out []*Server
	s.app.store.View(func(st *State) {
		for _, x := range st.Servers {
			if !x.Igproxy || !visible(user, admin, x.Owner) {
				continue
			}
			if admin && view != "" && ((view == "-" && x.Owner != "") || (view != "-" && x.Owner != view)) {
				continue
			}
			out = append(out, x)
		}
	})
	return out
}

// igServer: one server of this account that is on the page.
func (s *Server2) igServer(user string, admin bool, id string) (*Server, error) {
	x := s.app.store.Server(id)
	if x == nil || !x.Igproxy || !visible(user, admin, x.Owner) {
		return nil, errors.New("no such server (the list changed - reload the page)")
	}
	return x, nil
}

// igTargets: "all" (the servers in view), a list of ids, or one id.
func (s *Server2) igTargets(user string, admin bool, srv any, view string) ([]*Server, error) {
	switch v := srv.(type) {
	case string:
		if v == "all" {
			return s.igServersOf(user, admin, view), nil
		}
		x, err := s.igServer(user, admin, v)
		if err != nil {
			return nil, err
		}
		return []*Server{x}, nil
	case []any:
		var out []*Server
		for _, id := range v {
			x, err := s.igServer(user, admin, igStr(id))
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	}
	return nil, errors.New("no servers")
}

type igServerView struct {
	ID      string            `json:"id"`
	Owner   string            `json:"owner"`
	Name    string            `json:"name"`
	Host    string            `json:"host"`
	Country string            `json:"country,omitempty"`
	Info    map[string]string `json:"info"`
}

func (s *Server2) igServers(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	list := s.igServersOf(user, admin, "")
	infos := s.app.igInfos(list, r.URL.Query().Get("fresh") == "1")
	out := []igServerView{}
	for _, x := range list {
		host := x.IPv4
		if host == "" {
			host = x.IPv6
		}
		out = append(out, igServerView{x.ID, x.Owner, x.Name, host, x.Country, infos[x.ID]})
	}
	// servers that could join: foreign servers of this account not on the page yet
	type cand struct {
		ID, Name, Owner, Host string
	}
	cands := []cand{}
	s.app.store.View(func(st *State) {
		for _, x := range st.Servers {
			// Role "" is an Iran server, as everywhere else (only "foreign" is a foreign one)
			if x.Igproxy || x.Role != "foreign" || !visible(user, admin, x.Owner) {
				continue
			}
			cands = append(cands, cand{x.ID, x.Name, x.Owner, orStr(x.IPv4, x.IPv6)})
		}
	})
	_, sum := igAgent()
	pending := 0
	for _, x := range out {
		if x.Info["state"] == "CHECKING" {
			pending++
		}
	}
	writeJSON(w, map[string]any{"servers": out, "candidates": cands, "agent": sum, "t": time.Now().Unix(), "pending": pending})
}

func (s *Server2) igInfoGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	x, err := s.igServer(user, admin, r.URL.Query().Get("id"))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	writeJSON(w, s.app.igInfo(ctx, x))
}

func igBody(r *http.Request) (map[string]any, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	p := map[string]any{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, errors.New("bad json")
		}
	}
	return p, nil
}

func (s *Server2) igAction(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	tl, err := s.igTargets(user, admin, p["srv"], igStr(p["view"]))
	if err == nil && len(tl) == 0 {
		err = errors.New("no servers")
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	act := igStr(p["action"])
	// several servers (all in view, or a list): one verdict line per server and the run is kept
	_, list := p["srv"].([]any)
	multi := list || igStr(p["srv"]) == "all" || len(tl) > 1
	idc := make(chan string, 1)
	t := &igTally{}
	runEnd := func() {
		if multi {
			s.app.igRunEnd(user, act, <-idc, t)
		}
	}
	var id string
	if act == "deploy" {
		onlyOld := igStr(p["old"]) != ""
		_, sum := igAgent()
		id, err = s.app.igJob(user, "install / update agent", time.Duration(len(tl))*12*time.Minute, func(ctx context.Context, out func(string)) bool {
			defer runEnd()
			if multi {
				out(fmt.Sprintf(">> %d servers", len(tl)))
			}
			n, bad := 0, 0
			for _, x := range tl {
				if ctx.Err() != nil {
					break
				}
				if multi {
					out("== " + igLabel(x))
				}
				if onlyOld {
					if inf := s.app.igInfo(ctx, x); inf["state"] != "UPDATE" && inf["state"] != "NOAGENT" && inf["outdated"] != "1" {
						if multi {
							t.add(x, "skip", "runs the current agent", out)
							out("")
						}
						continue
					}
				}
				n++
				if !s.app.igDeploy(ctx, x, out) {
					bad++
					if multi {
						t.add(x, "fail", "still does not run the new agent", out)
					}
				} else if multi {
					t.add(x, "ok", "updated to "+sum, out)
				}
				out("")
			}
			if sum == "" {
				return false
			}
			msg := fmt.Sprintf("updated: %d/%d", n-bad, n)
			if bad > 0 {
				msg += fmt.Sprintf("   failed: %d", bad)
			}
			out(msg)
			return bad == 0
		})
	} else {
		var c igCmd
		c, err = igBuild(act, p)
		if err == nil && act == "uninstall" && len(tl) != 1 {
			err = errors.New("uninstall one server at a time")
		}
		if err == nil && act == "route" {
			for _, x := range tl {
				if gemHomeRouteBad(x, c.args[1], c.args[2]) {
					err = errors.New(igLabel(x) + ": " + gemHomeRefusal)
				}
			}
		}
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		title := c.title + " - " + igLabel(tl[0])
		if multi {
			title = c.title + " - ALL servers"
		}
		id, err = s.app.igJob(user, title, time.Duration(len(tl))*time.Duration(c.tmo+40)*time.Second, func(ctx context.Context, out func(string)) bool {
			defer runEnd()
			ok := true
			var rot *igRotTally
			if act == "google_rotate" {
				rot = &igRotTally{}
			}
			if multi {
				out(fmt.Sprintf(">> %d servers", len(tl)))
			}
			for _, x := range tl {
				if ctx.Err() != nil {
					break
				}
				if multi {
					out("== " + igLabel(x))
				} else {
					out("-> " + igLabel(x) + ": igproxy " + strings.Join(c.args, " "))
				}
				rc, said := s.app.igRun(ctx, x, c.args, c.input, c.tmo, out)
				if rc != 0 {
					ok = false
					if !multi && rc != 255 {
						out(fmt.Sprintf("(exit code %d)", rc))
					}
				}
				if rot != nil {
					rot.add(igLabel(x), rc, said)
				}
				s.app.igForget(x.ID)
				if multi {
					st, say := igVerdict(act, rc, said)
					t.add(x, st, say, out)
					out("")
				}
			}
			if rot != nil {
				for _, l := range rot.lines() {
					out(l)
				}
				ok = ok && rot.ok()
			}
			return ok
		})
	}
	if err == nil && multi {
		s.app.igRunStart(user, act, id)
		idc <- id
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": id})
}

// igEnable puts a server on the page (installing the agent when it has none) or takes it off.
func (s *Server2) igEnable(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct {
		ID     string
		On     bool
		Deploy bool
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	x := s.app.store.Server(in.ID)
	if x == nil || !visible(user, admin, x.Owner) {
		httpErr(w, 404, "server not found")
		return
	}
	if in.On && x.Role != "foreign" { // the page never offers one; the API took it ("" = iran)
		httpErr(w, 400, "IG Routing runs on foreign servers only")
		return
	}
	if in.On && x.Owner != "" && s.app.isPanelHost(x) {
		httpErr(w, 400, "this address is the panel server itself")
		return
	}
	wasOn := x.Igproxy
	_ = s.app.store.Update(func(st *State) error {
		if y := s.app.store.serverLocked(st, in.ID); y != nil {
			y.Igproxy = in.On
		}
		return nil
	})
	s.app.igForget(in.ID)
	if !in.On {
		writeJSON(w, map[string]string{"ok": "1"})
		return
	}
	id, err := s.app.igJob(user, "add server "+x.Name, 15*time.Minute, func(ctx context.Context, out func(string)) bool {
		ok := func() bool {
			inf := s.app.igInfo(ctx, x)
			if inf["state"] == "OFFLINE" {
				out("!! the panel can't reach it now: " + inf["err"])
				return false
			}
			out(fmt.Sprintf("%s reached (state %s)", x.Name, inf["state"]))
			if st := inf["state"]; st == "NOAGENT" || st == "UPDATE" || inf["outdated"] == "1" || in.Deploy {
				return s.app.igDeploy(ctx, x, out)
			}
			return true
		}()
		if !ok && !wasOn {
			// a server that couldn't be set up goes back off the page: left there OFFLINE it
			// also dropped out of the Add list, so it couldn't be tried again
			_ = s.app.store.Update(func(st *State) error {
				if y := s.app.store.serverLocked(st, in.ID); y != nil {
					y.Igproxy = false
				}
				return nil
			})
			s.app.igForget(in.ID)
			out("not added: fix the above and add it again")
		} else if ok {
			out(x.Name + " added")
		}
		return ok
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": id})
}

func (s *Server2) igCopy(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	from, err := s.igServer(user, admin, igStr(p["from"]))
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	parts := igStr(p["parts"])
	if parts == "" {
		parts = "routes proxies ig tg opts"
	}
	if !igParts.MatchString(parts) {
		httpErr(w, 400, "bad parts")
		return
	}
	all, err := s.igTargets(user, admin, p["to"], igStr(p["view"]))
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	var tl []*Server
	for _, x := range all {
		if x.ID != from.ID {
			tl = append(tl, x)
		}
	}
	if len(tl) == 0 {
		httpErr(w, 400, "no target servers")
		return
	}
	id, err := s.app.igJob(user, "copy settings from "+igLabel(from), time.Duration(len(tl)+1)*6*time.Minute, func(ctx context.Context, out func(string)) bool {
		rc, data := s.app.igRun(ctx, from, append([]string{"export"}, strings.Fields(parts)...), "", 60, nil)
		data = lastLineOf(data)
		if rc != 0 || data == "" {
			out("!! cannot read the settings of " + igLabel(from))
			return false
		}
		ok := true
		for _, x := range tl {
			if ctx.Err() != nil {
				break
			}
			out("-> " + igLabel(x))
			if rc, _ := s.app.igRun(ctx, x, []string{"import"}, data, 300, out); rc != 0 {
				ok = false
			}
			s.app.igForget(x.ID)
			out("")
		}
		return ok
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": id})
}

func lastLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

func (s *Server2) igBackupRun(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct{ View string }
	_ = readJSON(r, &in)
	tl := s.igServersOf(user, admin, in.View)
	if len(tl) == 0 {
		httpErr(w, 400, "no servers")
		return
	}
	id, err := s.app.igJob(user, "backup ALL servers", time.Duration(len(tl))*2*time.Minute, func(ctx context.Context, out func(string)) bool {
		ok := true
		for _, x := range tl {
			if ctx.Err() != nil {
				break
			}
			rc, data := s.app.igRun(ctx, x, []string{"export"}, "", 30, nil)
			data = lastLineOf(data)
			if rc != 0 || data == "" {
				out("!!  " + igLabel(x) + ": could not read / save")
				ok = false
				continue
			}
			name, err := igSaveBackup(x, data)
			if err != nil {
				out("!!  " + igLabel(x) + ": " + err.Error())
				ok = false
				continue
			}
			out("OK  " + igLabel(x) + " -> " + name)
		}
		return ok
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": id})
}

func (s *Server2) igBackupList(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	owners := []string{user}
	if admin {
		owners = []string{""}
		s.app.store.View(func(st *State) {
			for _, u := range st.Users {
				if !isAdminRole(u.Role) {
					owners = append(owners, u.Username)
				}
			}
		})
	}
	writeJSON(w, map[string]any{"files": igBackups(owners)})
}

func (s *Server2) igRestore(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct{ File, Owner, Srv string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	x, err := s.igServer(user, admin, in.Srv)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if !admin {
		in.Owner = user // a user restores only its own backups
	} else if in.Owner != "" && !validUsername(in.Owner) {
		httpErr(w, 400, "no such backup")
		return
	}
	name := filepath.Base(in.File)
	b, err := os.ReadFile(filepath.Join(igBackupDir(in.Owner), name))
	if !strings.HasSuffix(name, ".igpx") || err != nil {
		httpErr(w, 400, "no such backup")
		return
	}
	data := string(b)
	id, err := s.app.igJob(user, "restore "+name+" -> "+igLabel(x), 6*time.Minute, func(ctx context.Context, out func(string)) bool {
		rc, _ := s.app.igRun(ctx, x, []string{"import"}, data, 300, out)
		s.app.igForget(x.ID)
		return rc == 0
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": id})
}

// igRotTally sums up "Google -> fresh IP" over servers. The agent answers 0 whether Google moved
// or not (not on WARP there, no other WARP opens Gemini), so the job read "finished" while on
// some servers - or all - nothing had moved; the summary says which servers moved and which not.
type igRotTally struct{ moved, stayed, off, failed []string }

func (t *igRotTally) add(name string, rc int, said string) {
	switch {
	case rc != 0:
		t.failed = append(t.failed, name)
	case strings.Contains(said, "Google now uses WARP"):
		t.moved = append(t.moved, name)
	case strings.Contains(said, "Google is not on WARP here"):
		t.off = append(t.off, name)
	default: // "only WARP n works here", "no other WARP works + opens Gemini now"
		t.stayed = append(t.stayed, name)
	}
}

// ok: every server where Google is on WARP got a fresh IP
func (t *igRotTally) ok() bool { return len(t.stayed) == 0 && len(t.failed) == 0 }

func (t *igRotTally) lines() []string {
	l := []string{"== Summary"}
	add := func(n []string, what string) {
		if len(n) > 0 {
			l = append(l, fmt.Sprintf("%s: %d (%s)", what, len(n), strings.Join(n, ", ")))
		}
	}
	add(t.moved, "OK moved to a fresh IP")
	add(t.stayed, "!! not moved - no other WARP opens Gemini there now")
	add(t.off, "Google is not on WARP there (nothing to move)")
	add(t.failed, "!! not reached / error")
	return l
}
