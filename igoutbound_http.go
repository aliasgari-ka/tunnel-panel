package main

// Outbounds: adding many at once (links, a subscription, Xray JSON, proxies), and subscriptions
// that are kept and refreshed. See igoutbound.go for the parsing and the line the agent keeps.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IgSub is a subscription URL added to some servers. The URL carries its token: it never goes to
// the page (only its host) nor to a log.
type IgSub struct {
	ID      string              `json:"id"`
	Owner   string              `json:"owner"`
	URL     string              `json:"url"`
	Servers []string            `json:"servers"`
	Keys    map[string][]string `json:"keys,omitempty"` // per server: the outbound keys it added
	Gone    map[string][]string `json:"gone,omitempty"` // per server: keys no longer in the subscription
	At      int64               `json:"at,omitempty"`   // last refresh
	Count   int                 `json:"count,omitempty"`
	Err     string              `json:"err,omitempty"`
}

const (
	igOutMaxAdd   = 60 // outbounds per request
	igSubEvery    = 12 * time.Hour
	igOutPerItemS = 30 // agent seconds per tested item
)

// ---- adding many on one server

type igOutItem struct {
	I      int    `json:"i"` // index in the parsed list
	Status string `json:"status"`
	N      int    `json:"n,omitempty"`
	IP     string `json:"ip,omitempty"`
	Loc    string `json:"loc,omitempty"`
	MS     int    `json:"ms,omitempty"`
	Msg    string `json:"msg,omitempty"`
}

type igOutSrvRes struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Status string      `json:"status"` // done | unreachable | old
	Msg    string      `json:"msg,omitempty"`
	Items  []igOutItem `json:"items"`
	Added  int         `json:"added"`
	Exists int         `json:"exists"`
	Failed int         `json:"failed"`
}

var igAddManyLine = regexp.MustCompile(`^\s*\[(\d+)\]\s+(?:OK - exit IP (\S*) \(([^)]*)\)\s+(\d+)ms -> proxy (\d+)|already in the list as proxy (\d+)|(.*))$`)

// igOutAddMany: one agent call, every line tested there, one router reload. An agent from before
// Outbounds has no "addmany": plain proxies are then added one by one, Xray ones refused.
func (a *App) igOutAddMany(ctx context.Context, x *Server, lines []igProxyIn) igOutSrvRes {
	res := igOutSrvRes{ID: x.ID, Name: igLabel(x), Status: "done"}
	var in []string
	for _, l := range lines {
		in = append(in, l.line())
	}
	rc, out := a.igRun(ctx, x, []string{"proxy", "addmany"}, strings.Join(in, "\n"), 30+igOutPerItemS*len(lines), nil)
	a.igForget(x.ID)
	if rc == 255 {
		res.Status, res.Msg = "unreachable", strings.TrimSpace(lastLineOf(out))
		return res
	}
	if rc != 0 && strings.Contains(out, "usage: proxy") { // the old agent
		res.Status = "old"
		for i, l := range lines {
			if l.Type == "xray" {
				res.Items = append(res.Items, igOutItem{I: i, Status: "failed", Msg: "this server's agent is too old for Xray configs - press «Update agents» first"})
				continue
			}
			r := a.igProxyAddOne(ctx, x, l)
			it := igOutItem{I: i, Status: r.Status, N: r.N, IP: r.IP, Loc: r.Loc, MS: r.MS, Msg: r.Msg}
			if it.Status == "unreachable" {
				it.Status = "failed"
			}
			res.Items = append(res.Items, it)
		}
		res.count()
		return res
	}
	got := map[int]bool{}
	for _, l := range strings.Split(out, "\n") {
		m := igAddManyLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		k, _ := strconv.Atoi(m[1])
		if k < 1 || k > len(lines) || got[k] {
			continue
		}
		got[k] = true
		it := igOutItem{I: k - 1}
		px := lines[k-1]
		key := igProxyKey(px.Type, px.Host, px.Port, px.User)
		switch {
		case m[5] != "":
			it.Status, it.IP, it.Loc = "added", m[2], m[3]
			it.MS, _ = strconv.Atoi(m[4])
			it.N, _ = strconv.Atoi(m[5])
			igPxRemember(x.ID, key, igProxyTest{OK: true, MS: it.MS, IP: it.IP, Loc: it.Loc, Google: true, At: time.Now().Unix()})
		case m[6] != "":
			it.Status = "exists"
			it.N, _ = strconv.Atoi(m[6])
		default:
			it.Status, it.Msg = "failed", strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(m[7]), "!!"))
		}
		res.Items = append(res.Items, it)
	}
	for i := range lines {
		if !got[i+1] {
			msg := "no answer about it"
			if rc != 0 {
				msg = igLastErr(out, rc)
			}
			res.Items = append(res.Items, igOutItem{I: i, Status: "failed", Msg: msg})
		}
	}
	res.count()
	return res
}

func (r *igOutSrvRes) count() {
	r.Added, r.Exists, r.Failed = 0, 0, 0
	for _, it := range r.Items {
		switch it.Status {
		case "added":
			r.Added++
		case "exists":
			r.Exists++
		default:
			r.Failed++
		}
	}
}

// igOutAddTo adds the outbounds to every server (6 servers at a time).
func (a *App) igOutAddTo(ctx context.Context, tl []*Server, lines []igProxyIn) []igOutSrvRes {
	out := make([]igOutSrvRes, len(tl))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, x := range tl {
		wg.Add(1)
		go func(i int, x *Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = a.igOutAddMany(ctx, x, lines)
		}(i, x)
	}
	wg.Wait()
	return out
}

func igOutLines(outs []*igOut) ([]igProxyIn, error) {
	var l []igProxyIn
	for _, o := range outs {
		p, err := o.line()
		if err != nil {
			return nil, err
		}
		l = append(l, p)
	}
	return l, nil
}

// ---- HTTP

// igOutParse: what would be added (shown before adding; nothing is sent to a server).
func (s *Server2) igOutParse(w http.ResponseWriter, r *http.Request) {
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	outs, errs, subs := igParseInput(ctx, igStr(p["text"]))
	hints := []string{}
	for _, u := range subs {
		hints = append(hints, igSubHint(u))
	}
	writeJSON(w, map[string]any{"items": igOutSummaries(outs), "errors": errs, "subs": hints, "max": igOutMaxAdd})
}

// igOutAdd: POST {srv, view, text}. The text may hold links, proxies, JSON and subscription URLs.
func (s *Server2) igOutAdd(w http.ResponseWriter, r *http.Request, p map[string]any) {
	user, admin := s.who(r)
	tl, err := s.igTargets(user, admin, p["srv"], igStr(p["view"]))
	if err == nil && len(tl) == 0 {
		err = errors.New("no servers")
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	pctx, pcancel := context.WithTimeout(r.Context(), 40*time.Second)
	outs, perrs, subs := igParseInput(pctx, igStr(p["text"]))
	pcancel()
	if len(outs) == 0 {
		msg := "nothing to add"
		if len(perrs) > 0 {
			msg = perrs[0].Item + ": " + perrs[0].Err
		}
		writeJSON(w, map[string]any{"ok": false, "msg": msg, "errors": perrs, "results": []any{}})
		return
	}
	if len(outs) > igOutMaxAdd {
		httpErr(w, 400, fmt.Sprintf("%d outbounds - at most %d at a time", len(outs), igOutMaxAdd))
		return
	}
	lines, err := igOutLines(outs)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(60+igOutPerItemS*len(lines))*time.Second)
	defer cancel()
	res := s.app.igOutAddTo(ctx, tl, lines)
	// a subscription is kept (refreshable) when everything pasted came from one
	if len(subs) == 1 {
		owner := user
		if len(tl) > 0 {
			owner = tl[0].Owner
		}
		s.app.igSubKeep(owner, subs[0], tl, lines, res)
	}
	ok := true
	n := map[string]int{}
	for _, x := range res {
		n["added"] += x.Added
		n["exists"] += x.Exists
		n["failed"] += x.Failed
		if x.Status == "unreachable" || x.Failed > 0 {
			ok = false
		}
	}
	writeJSON(w, map[string]any{"results": res, "items": igOutSummaries(outs), "errors": perrs, "ok": ok && len(perrs) == 0,
		"added": n["added"], "exists": n["exists"], "failed": n["failed"]})
}

// ---- subscriptions

func igSubID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func igKeyOf(l igProxyIn) string { return igProxyKey(l.Type, l.Host, l.Port, l.User) }

// igSubKeep records (or updates) a subscription after an add / refresh: which keys it brought to
// which server, and which of its earlier ones are gone from it now.
func (a *App) igSubKeep(owner, raw string, tl []*Server, lines []igProxyIn, res []igOutSrvRes) {
	now := map[string]bool{}
	for _, l := range lines {
		now[igKeyOf(l)] = true
	}
	a.store.Update(func(st *State) error {
		var sub *IgSub
		for _, x := range st.IgSubs {
			if x.URL == raw && x.Owner == owner {
				sub = x
			}
		}
		if sub == nil {
			sub = &IgSub{ID: igSubID(), Owner: owner, URL: raw}
			st.IgSubs = append(st.IgSubs, sub)
		}
		if sub.Keys == nil {
			sub.Keys = map[string][]string{}
		}
		if sub.Gone == nil {
			sub.Gone = map[string][]string{}
		}
		sub.At, sub.Count, sub.Err = time.Now().Unix(), len(lines), ""
		for i, x := range tl {
			if !contains(sub.Servers, x.ID) {
				sub.Servers = append(sub.Servers, x.ID)
			}
			have := map[string]bool{}
			var keep, gone []string
			for _, k := range sub.Gone[x.ID] { // still gone (deleted from the server is pruned by the page's list)
				if !now[k] {
					gone = append(gone, k)
				}
			}
			for _, k := range sub.Keys[x.ID] {
				if now[k] {
					keep = append(keep, k)
					have[k] = true
				} else {
					gone = append(gone, k)
				}
			}
			if i < len(res) {
				for _, it := range res[i].Items {
					if (it.Status == "added" || it.Status == "exists") && it.I < len(lines) {
						if k := igKeyOf(lines[it.I]); !have[k] {
							keep = append(keep, k)
							have[k] = true
						}
					}
				}
			}
			sub.Keys[x.ID] = keep
			if len(gone) > 0 {
				sub.Gone[x.ID] = gone
			} else {
				delete(sub.Gone, x.ID)
			}
		}
		return nil
	})
}

type igSubView struct {
	ID      string   `json:"id"`
	Host    string   `json:"host"`
	Servers []string `json:"servers"`
	At      int64    `json:"at"`
	Count   int      `json:"count"`
	Err     string   `json:"err,omitempty"`
	Gone    int      `json:"gone"`
}

// igSubsFor: the subscriptions of servers this account sees, and per server which row keys came
// from which subscription (the page marks them) and which are gone from it.
func (a *App) igSubsFor(user string, admin bool) (list []igSubView, from map[string]map[string]string, gone map[string]map[string]bool) {
	from, gone = map[string]map[string]string{}, map[string]map[string]bool{}
	a.store.View(func(st *State) {
		for _, x := range st.IgSubs {
			if !visible(user, admin, x.Owner) {
				continue
			}
			v := igSubView{ID: x.ID, Host: igSubHint(x.URL), Servers: x.Servers, At: x.At, Count: x.Count, Err: x.Err}
			for srv, ks := range x.Keys {
				if from[srv] == nil {
					from[srv] = map[string]string{}
				}
				for _, k := range ks {
					from[srv][k] = x.ID
				}
			}
			for srv, ks := range x.Gone {
				if gone[srv] == nil {
					gone[srv] = map[string]bool{}
				}
				for _, k := range ks {
					gone[srv][k] = true
					if from[srv] == nil {
						from[srv] = map[string]string{}
					}
					from[srv][k] = x.ID
				}
				v.Gone += len(ks)
			}
			list = append(list, v)
		}
	})
	return
}

// igSubRefresh downloads one subscription again and adds what is new to its servers.
func (a *App) igSubRefresh(ctx context.Context, id string) (*IgSub, []igOutSrvRes, error) {
	var sub IgSub
	var tl []*Server
	a.store.View(func(st *State) {
		for _, x := range st.IgSubs {
			if x.ID == id {
				sub = *x
			}
		}
		for _, sid := range sub.Servers {
			for _, x := range st.Servers {
				if x.ID == sid && x.Igproxy {
					tl = append(tl, x)
				}
			}
		}
	})
	if sub.ID == "" {
		return nil, nil, errors.New("no such subscription")
	}
	fail := func(err error) (*IgSub, []igOutSrvRes, error) {
		a.store.Update(func(st *State) error {
			for _, x := range st.IgSubs {
				if x.ID == id {
					x.Err, x.At = err.Error(), time.Now().Unix()
				}
			}
			return nil
		})
		return nil, nil, err
	}
	links, err := igFetchSub(ctx, sub.URL)
	if err != nil {
		return fail(err)
	}
	var outs []*igOut
	seen := map[string]bool{}
	for _, l := range links {
		os, err := igParseOne(l)
		if err != nil {
			continue
		}
		for _, o := range os {
			if p, err := o.line(); err == nil && !seen[igKeyOf(p)] {
				seen[igKeyOf(p)] = true
				outs = append(outs, o)
			}
		}
	}
	if len(outs) == 0 {
		return fail(errors.New("no usable link in the subscription now"))
	}
	if len(outs) > igOutMaxAdd {
		outs = outs[:igOutMaxAdd]
	}
	lines, err := igOutLines(outs)
	if err != nil {
		return fail(err)
	}
	if len(tl) == 0 {
		return fail(errors.New("its servers are gone"))
	}
	res := a.igOutAddTo(ctx, tl, lines)
	a.igSubKeep(sub.Owner, sub.URL, tl, lines, res)
	return &sub, res, nil
}

// igSubLoop refreshes every subscription each 12 h (adds new links; gone ones are only marked).
func (a *App) igSubLoop() {
	time.Sleep(5 * time.Minute)
	for {
		var due []string
		a.store.View(func(st *State) {
			for _, x := range st.IgSubs {
				if time.Since(time.Unix(x.At, 0)) >= igSubEvery {
					due = append(due, x.ID)
				}
			}
		})
		for _, id := range due {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
			a.igSubRefresh(ctx, id)
			cancel()
		}
		time.Sleep(15 * time.Minute)
	}
}

func (s *Server2) igSubCmd(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	id := igStr(p["id"])
	var sub *IgSub
	s.app.store.View(func(st *State) {
		for _, x := range st.IgSubs {
			if x.ID == id && visible(user, admin, x.Owner) {
				c := *x
				sub = &c
			}
		}
	})
	if sub == nil {
		httpErr(w, 404, "no such subscription")
		return
	}
	switch igStr(p["do"]) {
	case "refresh":
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
		defer cancel()
		_, res, err := s.app.igSubRefresh(ctx, id)
		if err != nil {
			httpErr(w, 502, err.Error())
			return
		}
		n := map[string]int{}
		for _, x := range res {
			n["added"] += x.Added
			n["failed"] += x.Failed
		}
		writeJSON(w, map[string]any{"ok": true, "results": res, "added": n["added"], "failed": n["failed"]})
	case "forget": // the outbounds stay on the servers; only the subscription is no longer kept
		s.app.store.Update(func(st *State) error {
			out := st.IgSubs[:0]
			for _, x := range st.IgSubs {
				if x.ID != id {
					out = append(out, x)
				}
			}
			st.IgSubs = out
			return nil
		})
		writeJSON(w, map[string]any{"ok": true})
	default:
		httpErr(w, 400, "unknown action")
	}
}

// ---- what each outbound number is, for the exit pickers (Routes, Auto menu): "n|badge|remark;…"

var igOutsSeen = struct {
	sync.Mutex
	m map[string]string
}{m: map[string]string{}}

func igOutsRemember(srv string, rows []*igProxyRow) {
	var b []string
	for _, r := range rows {
		b = append(b, strconv.Itoa(r.N)+"|"+r.Badge+"|"+r.Remark)
	}
	igOutsSeen.Lock()
	igOutsSeen.m[srv] = strings.Join(b, ";")
	igOutsSeen.Unlock()
}

// igWithOuts: a copy of the server's info with "pxk" (the cached map can be shared: never written)
func igWithOuts(srv string, info map[string]string) map[string]string {
	igOutsSeen.Lock()
	k, ok := igOutsSeen.m[srv]
	igOutsSeen.Unlock()
	if !ok || info == nil {
		return info
	}
	c := make(map[string]string, len(info)+1)
	for a, v := range info {
		c[a] = v
	}
	c["pxk"] = k
	return c
}
