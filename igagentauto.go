package main

// Automatic IG agent update: when the agent script on the panel host changes (a panel update,
// or a new igproxy.sh next to igpm.sh), every IG server gets it by itself — one server at a
// time, half a minute apart, the same clean update as "Update agents" (settings, routes and
// WARPs are kept; a few seconds of direct routing on that one server).
//
// The first server of a new script is a canary: when it fails, the rollout of that script
// stops and the admin chat is told, so a broken script never reaches every server. A server
// that fails later is retried with a growing pause (30 min … 6 h).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type IgAgentUpd struct {
	Sum     string                    `json:"sum"`               // the agent script this rollout is for
	Good    int                       `json:"good"`              // servers that took it (auto or by hand)
	Halt    bool                      `json:"halt,omitempty"`    // the canary failed: stopped until the script changes or a hand update works
	HaltWhy string                    `json:"haltWhy,omitempty"` // on which server, and its last line
	Done    bool                      `json:"done,omitempty"`    // every server runs it (the admin chat was told)
	Srv     map[string]*IgAgentUpdSrv `json:"srv,omitempty"`
}

type IgAgentUpdSrv struct {
	At    int64  `json:"at"`
	OK    bool   `json:"ok"`
	Err   string `json:"err,omitempty"`
	Tries int    `json:"tries,omitempty"`
	Next  int64  `json:"next,omitempty"` // not before (unix)
}

const (
	igAgentAutoFirst = 2 * time.Minute  // after the panel starts (the servers' info is read by then)
	igAgentAutoEvery = 5 * time.Minute  // a pass
	igAgentAutoGap   = 30 * time.Second // between two servers
)

// igDeployBusy: one agent install per server at a time (the automatic one and "Update agents")
var igDeployBusy sync.Map

func igAgentBackoff(tries int) time.Duration {
	d := 30 * time.Minute
	for i := 1; i < tries && d < 6*time.Hour; i++ {
		d *= 2
	}
	if d > 6*time.Hour {
		d = 6 * time.Hour
	}
	return d
}

// igAgentOld: the server runs an older agent and can be updated now (reachable, an agent on it)
func igAgentOld(inf map[string]string, sum string) bool {
	if inf == nil || sum == "" {
		return false
	}
	switch inf["state"] {
	case "", "CHECKING", "OFFLINE", "NOAGENT", "SUDO", "PAUSED", "DOWN":
		return false // unreachable, no agent (removed on purpose), paused by hand, or its router is down
	}
	return inf["state"] == "UPDATE" || inf["outdated"] == "1" || inf["sum"] != "" && inf["sum"] != sum
}

// igAgentNoted records one server's result for the script sum (auto or by hand).
func (a *App) igAgentNoted(srv, sum string, ok bool, why string, auto bool) {
	_ = a.store.Update(func(st *State) error {
		u := st.IgAgentUpd
		if u == nil || u.Sum != sum {
			u = &IgAgentUpd{Sum: sum}
			st.IgAgentUpd = u
		}
		if u.Srv == nil {
			u.Srv = map[string]*IgAgentUpdSrv{}
		}
		r := u.Srv[srv]
		if r == nil {
			r = &IgAgentUpdSrv{}
			u.Srv[srv] = r
		}
		r.At = time.Now().Unix()
		r.OK = ok
		if ok {
			r.Err, r.Tries, r.Next = "", 0, 0
			u.Good++
			u.Halt, u.HaltWhy = false, ""
		} else {
			r.Err = why
			if auto {
				r.Tries++
				r.Next = time.Now().Add(igAgentBackoff(r.Tries)).Unix()
			}
		}
		return nil
	})
}

func (a *App) igAgentAutoLoop() {
	time.Sleep(igAgentAutoFirst)
	for {
		a.igAgentAutoPass()
		time.Sleep(igAgentAutoEvery)
	}
}

func (a *App) igAgentAutoPass() {
	_, sum := igAgent()
	if sum == "" {
		return
	}
	var list []*Server
	var u IgAgentUpd
	a.store.View(func(st *State) {
		for _, x := range st.Servers {
			if x.Igproxy {
				c := *x
				list = append(list, &c)
			}
		}
		if st.IgAgentUpd != nil && st.IgAgentUpd.Sum == sum {
			u = *st.IgAgentUpd
		}
	})
	if u.Sum == "" { // a new script: a fresh rollout
		_ = a.store.Update(func(st *State) error { st.IgAgentUpd = &IgAgentUpd{Sum: sum}; return nil })
		u = IgAgentUpd{Sum: sum}
	}
	if u.Halt || len(list) == 0 {
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	ctx := context.Background()
	infos := a.igInfos(list, false)
	now := time.Now().Unix()
	var todo []*Server
	waiting := 0
	for _, x := range list {
		if !igAgentOld(infos[x.ID], sum) {
			continue
		}
		if r := u.Srv[x.ID]; r != nil && r.Next > now {
			waiting++
			continue
		}
		todo = append(todo, x)
	}
	if len(todo) == 0 {
		if waiting == 0 && !u.Done && u.Good > 0 {
			cur := 0
			for _, x := range list {
				if infos[x.ID]["sum"] == sum {
					cur++
				}
			}
			if cur == len(list) {
				_ = a.store.Update(func(st *State) error {
					if st.IgAgentUpd != nil && st.IgAgentUpd.Sum == sum {
						st.IgAgentUpd.Done = true
					}
					return nil
				})
				a.pushInfo(fmt.Sprintf("🧩 IG agent %s now runs on all %d servers (updated by itself)", sum, cur))
			}
		}
		return
	}
	for i, x := range todo {
		if i > 0 {
			time.Sleep(igAgentAutoGap)
		}
		if _, s := igAgent(); s != sum {
			return // the script changed meanwhile: the next pass starts over
		}
		var last []string
		out := func(l string) {
			if l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "!!")); l != "" {
				last = append(last, l)
				if len(last) > 3 {
					last = last[1:]
				}
			}
		}
		dctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		ok := a.igDeployAs(dctx, x, out, true)
		cancel()
		why := strings.Join(last, " · ")
		if ok {
			a.igAutoLog(x, "AGENT", "info", fmt.Sprintf("agent updated by itself to %s", sum))
			u.Good++
			continue
		}
		a.igAutoLog(x, "AGENT", "fail", "the automatic agent update failed: "+why)
		if u.Good == 0 { // the canary: stop this script's rollout here
			_ = a.store.Update(func(st *State) error {
				if st.IgAgentUpd != nil && st.IgAgentUpd.Sum == sum {
					st.IgAgentUpd.Halt = true
					st.IgAgentUpd.HaltWhy = igLabel(x) + ": " + why
				}
				return nil
			})
			a.push(fmt.Sprintf("⚠️ IG agent %s failed on %s, the first server of its automatic update — the other servers keep their agent. %s", sum, igLabel(x), why))
			return
		}
		a.store.View(func(st *State) {
			if st.IgAgentUpd != nil && st.IgAgentUpd.Srv[x.ID] != nil && st.IgAgentUpd.Srv[x.ID].Tries == 3 {
				a.push(fmt.Sprintf("⚠️ IG agent %s: %s failed its automatic update 3 times (tried again later). %s", sum, igLabel(x), why))
			}
		})
	}
}

// igAgentStatus: the rollout for the page (the servers list)
type igAgentStatusView struct {
	Sum     string `json:"sum"`
	Halt    bool   `json:"halt,omitempty"`
	HaltWhy string `json:"haltWhy,omitempty"`
	Failed  int    `json:"failed,omitempty"` // servers waiting for a retry
}

func (a *App) igAgentStatus() *igAgentStatusView {
	var v *igAgentStatusView
	a.store.View(func(st *State) {
		u := st.IgAgentUpd
		if u == nil {
			return
		}
		v = &igAgentStatusView{Sum: u.Sum, Halt: u.Halt, HaltWhy: u.HaltWhy}
		for _, r := range u.Srv {
			if !r.OK && r.Tries > 0 {
				v.Failed++
			}
		}
	})
	return v
}

// igDeployAs: igDeploy, one install per server at a time, the result recorded for the rollout
func (a *App) igDeployAs(ctx context.Context, srv *Server, out func(string), auto bool) bool {
	if _, busy := igDeployBusy.LoadOrStore(srv.ID, true); busy {
		out("!! " + srv.Name + ": an agent update of this server is already running")
		return false
	}
	defer igDeployBusy.Delete(srv.ID)
	var last string
	ok := a.igDeploy(ctx, srv, func(l string) {
		if t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "!!")); t != "" {
			last = t
		}
		out(l)
	})
	if _, sum := igAgent(); sum != "" {
		a.igAgentNoted(srv.ID, sum, ok, last, auto)
	}
	return ok
}
