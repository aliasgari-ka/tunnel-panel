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
			if x.Igproxy || x.Role == "iran" || !visible(user, admin, x.Owner) {
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
	var id string
	if act == "deploy" {
		onlyOld := igStr(p["old"]) != ""
		_, sum := igAgent()
		id, err = s.app.igJob(user, "install / update agent", time.Duration(len(tl))*12*time.Minute, func(ctx context.Context, out func(string)) bool {
			n, bad := 0, 0
			for _, x := range tl {
				if ctx.Err() != nil {
					break
				}
				if onlyOld {
					if st := s.app.igInfo(ctx, x)["state"]; st != "UPDATE" && st != "NOAGENT" {
						continue
					}
				}
				n++
				if !s.app.igDeploy(ctx, x, out) {
					bad++
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
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		title := c.title + " - " + igLabel(tl[0])
		if len(tl) > 1 {
			title = c.title + " - ALL servers"
		}
		id, err = s.app.igJob(user, title, time.Duration(len(tl))*time.Duration(c.tmo+40)*time.Second, func(ctx context.Context, out func(string)) bool {
			ok := true
			for _, x := range tl {
				if ctx.Err() != nil {
					break
				}
				if len(tl) > 1 {
					out("== " + igLabel(x))
				} else {
					out("-> " + igLabel(x) + ": igproxy " + strings.Join(c.args, " "))
				}
				if rc, _ := s.app.igRun(ctx, x, c.args, c.input, c.tmo, out); rc != 0 {
					ok = false
					if len(tl) == 1 && rc != 255 {
						out(fmt.Sprintf("(exit code %d)", rc))
					}
				}
				s.app.igForget(x.ID)
				if len(tl) > 1 {
					out("")
				}
			}
			return ok
		})
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
	if in.On && x.Owner != "" && s.app.isPanelHost(x) {
		httpErr(w, 400, "this address is the panel server itself")
		return
	}
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
		inf := s.app.igInfo(ctx, x)
		out(fmt.Sprintf("%s added (state %s)", x.Name, inf["state"]))
		if st := inf["state"]; st == "NOAGENT" || st == "UPDATE" || in.Deploy {
			return s.app.igDeploy(ctx, x, out)
		}
		if inf["state"] == "OFFLINE" {
			out("!! the panel can't reach it now: " + inf["err"])
			return false
		}
		return true
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
