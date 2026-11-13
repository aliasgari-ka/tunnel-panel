package main

// Deleting several proxies of a server at once (the Proxies tab's selection). One request, one
// script on the server, all-or-nothing on what it checks first:
//   - every selected line must still be the proxy the page saw (by type, host, port and user);
//     the list changed under the page = nothing is done
//   - a service that would be left on a deleted proxy is moved first, to where the page said
//     (another proxy by what it is, all the other proxies, WARP …); a service on "all proxies"
//     with no proxy left must be given a new way out too. A move that fails stops everything
//     before any proxy is deleted: no user is cut on the way
//   - the proxies are then deleted from the highest number down, so the numbers of the ones
//     still to delete never shift; the agent renumbers the routes of the ones that stay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type igPxMove struct {
	Svc    string      `json:"svc"`
	Via    string      `json:"via"`              // what is sent to the agent: proxy3, proxy, warp …
	Target *igProxyRow `json:"target,omitempty"` // a proxy that stays (by what it is)
	From   string      `json:"from"`             // the route it had
}

type igPxBulkPlan struct {
	Del   []*igProxyRow // highest number first
	Moves []igPxMove
	Left  int // proxies left after
}

// igPxAffected: the services the deletion would leave without a way out, and why.
// route proxyN with N deleted → "only"; route "proxy" with no proxy left → "pool".
func igPxAffected(info map[string]string, del map[int]bool, left int) map[string]string {
	out := map[string]string{}
	for _, g := range igServices {
		v := info[strings.ToLower(g)]
		if v == "proxy" && left == 0 {
			out[g] = "pool"
		} else if strings.HasPrefix(v, "proxy") && del[atoiOr(strings.TrimPrefix(v, "proxy"))] {
			out[g] = "only"
		}
	}
	return out
}

// igPxPlan works out what to do. moves: service -> "proxy" | "key:<proxy key>" | warp | warp6 | ipv6 | direct.
func igPxPlan(rows []*igProxyRow, info map[string]string, keys []string, moves map[string]string) (*igPxBulkPlan, error) {
	byKey := map[string]*igProxyRow{}
	for _, r := range rows {
		byKey[r.Key] = r
	}
	pl := &igPxBulkPlan{}
	del := map[int]bool{}
	for _, k := range keys {
		r := byKey[k]
		if r == nil {
			return nil, errors.New("that proxy is no longer on this server (the list changed) - reloaded")
		}
		if !del[r.N] {
			del[r.N] = true
			pl.Del = append(pl.Del, r)
		}
	}
	if len(pl.Del) == 0 {
		return nil, errors.New("nothing selected")
	}
	sort.Slice(pl.Del, func(i, j int) bool { return pl.Del[i].N > pl.Del[j].N })
	pl.Left = len(rows) - len(pl.Del)
	aff := igPxAffected(info, del, pl.Left)
	for _, g := range igServices {
		why, ok := aff[g]
		if !ok {
			continue
		}
		to := strings.TrimSpace(moves[g])
		if to == "" && why == "only" && pl.Left > 0 {
			to = "proxy" // what the agent does by itself; said in the dialog
		}
		from := info[strings.ToLower(g)]
		switch {
		case to == "":
			return nil, fmt.Errorf("%s would have no proxy left: choose where it goes", g)
		case strings.HasPrefix(to, "key:"):
			t := byKey[strings.TrimPrefix(to, "key:")]
			if t == nil || del[t.N] {
				return nil, fmt.Errorf("%s: the proxy it should move to is not staying", g)
			}
			pl.Moves = append(pl.Moves, igPxMove{Svc: g, Via: "proxy" + strconv.Itoa(t.N), Target: t, From: from})
		case to == "proxy":
			if pl.Left == 0 {
				return nil, fmt.Errorf("%s: no proxy is left for it", g)
			}
			// a service pinned to a deleted proxy goes to all the others when the agent deletes it
			pl.Moves = append(pl.Moves, igPxMove{Svc: g, Via: "proxy", From: from})
		case igVia.MatchString(to) && !strings.HasPrefix(to, "proxy"):
			pl.Moves = append(pl.Moves, igPxMove{Svc: g, Via: to, From: from})
		default:
			return nil, fmt.Errorf("%s: bad route %q", g, to)
		}
	}
	return pl, nil
}

func igPxSig(r *igProxyRow) string {
	u := r.user
	if u == "" {
		u = "-"
	}
	return r.Type + " " + r.Host + " " + r.Port + " " + u
}

// igPxBulkScript: check every line, move the services, then delete from the highest number down.
// Lines: "__M svc rc", "__D n rc" (rc "x" = the line changed meanwhile), the agent's own words between.
func igPxBulkScript(pl *igPxBulkPlan, tmo int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#igpx-bulk del=%d\nf=%s\n", len(pl.Del), igProxyFile)
	b.WriteString(`chk(){ local l t h p u; l=$(sed -n "${1}p" "$f"); read -r t h p u _ <<<"$l"; [ "$t $h $p $u" = "$2" ]; }
`)
	seen := map[int]bool{}
	check := func(r *igProxyRow) {
		if !seen[r.N] {
			seen[r.N] = true
			fmt.Fprintf(&b, "chk %d %s || { echo __CHANGED; echo __RC=0; exit 0; }\n", r.N, shq(igPxSig(r)))
		}
	}
	for _, r := range pl.Del {
		check(r)
	}
	for _, m := range pl.Moves {
		if m.Target != nil {
			check(m.Target)
		}
	}
	for _, m := range pl.Moves {
		if m.Via == "proxy" && strings.HasPrefix(m.From, "proxy") && m.From != "proxy" {
			continue // the agent's own "proxy del" moves it to all the other proxies
		}
		fmt.Fprintf(&b, "timeout %d igproxy route %s %s </dev/null 2>&1; x=$?; echo \"__M %s $x\"; [ $x = 0 ] || { echo __RC=$x; exit 0; }\n",
			tmo, shq(m.Svc), shq(m.Via), m.Svc)
	}
	for _, r := range pl.Del {
		fmt.Fprintf(&b, "chk %d %s || { echo \"__D %d x\"; echo __RC=0; exit 0; }\n", r.N, shq(igPxSig(r)), r.N)
		fmt.Fprintf(&b, "timeout %d igproxy proxy del %d </dev/null 2>&1; x=$?; echo \"__D %d $x\"; [ $x = 0 ] || { echo __RC=$x; exit 0; }\n", tmo, r.N, r.N)
	}
	b.WriteString("echo __RC=0\n")
	return b.String()
}

type igPxBulkOut struct {
	OK      bool     `json:"ok"`
	Deleted []string `json:"deleted"` // "HTTP 1.2.3.4:80"
	Left    []string `json:"left,omitempty"`
	Moved   []string `json:"moved,omitempty"` // "IG -> proxy3"
	Changed bool     `json:"changed,omitempty"`
	Msg     string   `json:"msg,omitempty"`
	Out     []string `json:"out,omitempty"`
}

func igPxName(r *igProxyRow) string {
	t := "HTTP"
	if r.Type == "socks5" {
		t = "SOCKS5"
	}
	return t + " " + r.Host + ":" + r.Port
}

func (a *App) igProxyBulkDel(ctx context.Context, x *Server, keys []string, moves map[string]string) (*igPxBulkOut, int, error) {
	rows, err := a.igProxies(ctx, x, false)
	if err != nil {
		return nil, 502, err
	}
	info := a.igInfo(ctx, x)
	if info["rc"] == "255" {
		return nil, 502, errors.New("no answer from the server")
	}
	pl, err := igPxPlan(rows, info, keys, moves)
	if err != nil {
		return nil, 409, err
	}
	const per = 150
	steps := len(pl.Del) + len(pl.Moves)
	rc, lines, err := a.igShell(ctx, x, igPxBulkScript(pl, per), time.Duration(30+(per+10)*steps)*time.Second)
	a.igForget(x.ID)
	res := &igPxBulkOut{}
	done := map[int]bool{}
	for _, l := range lines {
		f := strings.Fields(l)
		switch {
		case l == "__CHANGED":
			res.Changed = true
		case len(f) == 3 && f[0] == "__M" && f[2] == "0":
			for _, m := range pl.Moves {
				if m.Svc == f[1] {
					res.Moved = append(res.Moved, m.Svc+" -> "+m.Via)
				}
			}
		case len(f) == 3 && f[0] == "__D":
			if f[2] == "0" {
				done[atoiOr(f[1])] = true
			} else if f[2] == "x" {
				res.Changed = true
			}
		case strings.HasPrefix(l, "__"):
		default:
			if s := strings.TrimSpace(l); s != "" {
				res.Out = append(res.Out, s)
			}
		}
	}
	for _, r := range pl.Del {
		if done[r.N] {
			res.Deleted = append(res.Deleted, igPxName(r))
		} else {
			res.Left = append(res.Left, igPxName(r))
		}
	}
	res.OK = rc == 0 && !res.Changed && len(res.Left) == 0
	switch {
	case res.Changed && len(res.Deleted) == 0:
		res.Msg = "the proxy list changed on the server meanwhile - nothing was done, reloaded"
	case res.Changed:
		res.Msg = "the proxy list changed on the server meanwhile - stopped, reloaded"
	case rc == 255 && err != nil:
		res.Msg = err.Error()
	case rc != 0:
		res.Msg = igLastErr(strings.Join(res.Out, "\n"), rc)
	}
	return res, 200, nil
}

func (s *Server2) igProxyBulk(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, igStr(p["srv"]))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	if igStr(p["do"]) != "del" {
		httpErr(w, 400, "unknown action")
		return
	}
	var keys []string
	if l, ok := p["keys"].([]any); ok {
		for _, k := range l {
			if k := igStr(k); k != "" && len(keys) < 200 {
				keys = append(keys, k)
			}
		}
	}
	moves := map[string]string{}
	if m, ok := p["moves"].(map[string]any); ok {
		for k, v := range m {
			moves[strings.ToUpper(k)] = igStr(v)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	res, code, err := s.app.igProxyBulkDel(ctx, x, keys, moves)
	if err != nil {
		httpErr(w, code, err.Error())
		return
	}
	writeJSON(w, res)
}
