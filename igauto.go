package main

// IG Routing · Auto: the panel keeps each server's Instagram exit working by itself.
//
// Every few minutes each server's users' route is asked where Instagram places it (the
// country_code of instagram.com/accounts/login/ through the agent's users'-route relay 12370).
// When that is a no-music country (IR …) or nothing answers, twice in a row, the panel moves
// Instagram to the best exit that reads a music country: the route it should be on (WARP) if that
// works again, then a proxy of the server (European / the server's country first, music-tested
// first, Russia last), then the server's own IP, and when the server has none of those, a proxy
// copied from another server of the same owner. The route it left is kept as the one to go back
// to; it is tried again with a growing pause (30 min … 6 h) and taken back once it reads a music
// country again. A route changed by a person is followed, never fought.
//
// The agent has its own WARP -> proxy fallback for Instagram on warp6 (ig_fallback), but only
// with at least one WARP on the server: Ger-hertzener (Arshad's, new) had IG=warp6, no WARP (every
// new account read IR) and no proxy, so Instagram left through the server's own IP, IR, while
// the page said "healthy" (2026-11-13). While the agent's fallback is active the panel leaves
// that server alone.
//
// Only Instagram is moved. Google keeps its own guards (the agent's gem_watch, gemFix,
// gemhome.go: the hub's users' Google never leaves through 152.53.86.103); YouTube Music has no
// country signal. The page shows all three honestly.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	igAutoTick     = 2 * time.Minute  // the loop wakes this often
	igAutoEvery    = 10 * time.Minute // each server is checked this often (a bad one again at the next tick)
	igAutoBackMin  = 30 * time.Minute // the route it should be on is tried again after this …
	igAutoBackMax  = 6 * time.Hour    // … doubling up to this
	igAutoAlertGap = 6 * time.Hour    // "nothing works" at most this often per server
	igAutoLogMax   = 300
)

// IgAutoSvc is the automatic state of one service of one server.
type IgAutoSvc struct {
	Off   bool   `json:"off,omitempty"`   // the person turned the automatic repair off
	Auto  bool   `json:"auto,omitempty"`  // a person picked Auto (older domain services: Spotify …; igsvc.go)
	Pin   string `json:"pin,omitempty"`   // the exit the person pinned ("" = Auto)
	Want  string `json:"want,omitempty"`  // the route to be on: the pin, or the last route that worked
	Cur   string `json:"cur,omitempty"`   // the route the panel moved to while Want is broken ("" = none)
	Why   string `json:"why,omitempty"`   // why it moved, in a few words
	Since int64  `json:"since,omitempty"` // when it moved
	Next  int64  `json:"next,omitempty"`  // when Want is tried again
	Tries int    `json:"tries,omitempty"` // failed tries of Want since the move
	Alert int64  `json:"alert,omitempty"` // last "nothing works" alert
}

// IgAutoEvent is one line of the short history.
type IgAutoEvent struct {
	T    int64  `json:"t"`
	Srv  string `json:"srv"`
	Svc  string `json:"svc"`
	Kind string `json:"kind"` // fix | back | fail | info
	Msg  string `json:"msg"`
}

// the live result of the last probe of a server (memory only)
type igAutoLive struct {
	CC  string // Instagram's country on the users' route ("" = no answer)
	At  time.Time
	Bad int // bad probes in a row
	FB  string
}

var igAutoMem = struct {
	sync.Mutex
	live map[string]*igAutoLive
	busy map[string]bool
}{live: map[string]*igAutoLive{}, busy: map[string]bool{}}

// Instagram offers no music in these (the agent's IG_NOMUSIC)
var igNoMusicCC = map[string]bool{"IR": true, "CN": true, "KP": true, "SY": true, "CU": true}

func igNoMusic(cc string) bool { return igNoMusicCC[strings.ToUpper(strings.TrimSpace(cc))] }

var igEurope = map[string]bool{"DE": true, "NL": true, "FR": true, "GB": true, "FI": true, "SE": true, "AT": true, "CH": true, "BE": true,
	"PL": true, "IT": true, "ES": true, "DK": true, "NO": true, "CZ": true, "IE": true, "LU": true, "PT": true, "LT": true, "LV": true, "EE": true}

func igIsWarp(v string) bool { return strings.HasPrefix(v, "warp") }

// igWarpMissing: the services routed to WARP on a server that has no WARP ("IG,GOOGLE" …)
func igWarpMissing(S map[string]string) string {
	if S["warps"] != "0" {
		return ""
	}
	var out []string
	for _, k := range []string{"ig", "google", "ytm"} {
		if igIsWarp(S[k]) {
			out = append(out, strings.ToUpper(k))
		}
	}
	return strings.Join(out, ",")
}

// igNoExit: Instagram routed to WARP with no WARP and no proxy: it leaves through the server's own IP
func igNoExit(S map[string]string) string {
	if igIsWarp(S["ig"]) && S["warps"] == "0" && S["proxies"] == "0" {
		return "IG"
	}
	return ""
}

// ---- the probe on the server

// igAutoScript: L = Instagram's country on the users' route (3 tries), F = the agent's own fallback,
// R = Instagram's route. With scan: O = the server's own IP (relay 12371), P n host cc music = each
// proxy, W n cc = each WARP (its test port). Credentials stay on the server.
func igAutoScript(scan bool) string {
	s := `#igauto
R=/run/igproxy D=/etc/igproxy
grep -q "^VER=" /usr/local/bin/igproxy 2>/dev/null || { echo __RC=3; exit 0; }
cc(){ curl -s -m 10 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36" "$@" https://www.instagram.com/accounts/login/ 2>/dev/null | grep -oE '"country_code":"[A-Z]{2}"' | head -1 | cut -d'"' -f4; }
if ss -ltn 2>/dev/null | grep -q ':12370 '; then
  l=""; for i in 1 2 3; do l=$(cc -x socks5h://127.0.0.1:12370); [ -n "$l" ] && break; sleep 2; done
  echo "L ${l:--}"
else echo "L none"; fi
echo "F $(head -c 40 "$D/ig_fallback" 2>/dev/null)"
echo "R $(awk -F= '$1=="IG"{print $2}' "$D/routes" 2>/dev/null)"
`
	if scan {
		s += `d=$(mktemp -d)
ss -ltn 2>/dev/null | grep -q ':12371 ' && { echo "O $(cc -x socks5h://127.0.0.1:12371)" > "$d/o" & }
i=0
while read -r t h p u pw; do
  [ -z "$t" ] && continue; i=$((i+1)); s=socks5h; [ "$t" = http ] && s=http
  A=(-x "$s://$h:$p"); [ -n "$u" ] && [ "$u" != - ] && { [ "$pw" = - ] && pw=""; A+=(-U "$u:$pw"); }
  ( echo "P $i $h $(cc "${A[@]}") $(awk '{print $2}' "$R/pmus_$i" 2>/dev/null | head -c 12)" > "$d/p$i" ) &
done < <(cat "$D/proxies" 2>/dev/null)
i=0
while read -r k _; do
  [ -z "$k" ] && continue; i=$((i+1))
  ( echo "W $i $(cc -x socks5h://127.0.0.1:$((12350+i)))" > "$d/w$i" ) &
done < <(cat "$D/warps" 2>/dev/null)
wait; cat "$d"/* 2>/dev/null; rm -rf "$d"
`
	}
	return s + "echo __RC=0\n"
}

type igExitCC struct {
	Route string // proxyN | warpN | direct
	Host  string
	CC    string
	Music string // the agent's last music test of that proxy ("ok", "no …", "")
}

type igProbe struct {
	Live, FB, Route string
	Relay           bool
	Exits           []igExitCC
}

func igParseProbe(lines []string) igProbe {
	var p igProbe
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "L":
			if len(f) > 1 && f[1] != "none" {
				p.Relay = true
				if f[1] != "-" {
					p.Live = f[1]
				}
			}
		case "F":
			if len(f) > 1 {
				p.FB = f[1]
			}
		case "R":
			if len(f) > 1 {
				p.Route = f[1]
			}
		case "O":
			if len(f) > 1 {
				p.Exits = append(p.Exits, igExitCC{Route: "direct", CC: f[1]})
			}
		case "P":
			if len(f) >= 3 {
				e := igExitCC{Route: "proxy" + f[1], Host: f[2]}
				if len(f) > 3 && len(f[3]) == 2 {
					e.CC = f[3]
					if len(f) > 4 {
						e.Music = f[4]
					}
				} else if len(f) > 3 {
					e.Music = f[3]
				}
				p.Exits = append(p.Exits, e)
			}
		case "W":
			if len(f) > 2 {
				p.Exits = append(p.Exits, igExitCC{Route: "warp" + f[1], CC: f[2]})
			}
		}
	}
	return p
}

// igRank orders the exits that may carry Instagram: a music country only; music tested OK first,
// then the server's own country, then Europe, then the rest, Russia last (it passed real music
// tests, but a European exit first - the agent's order). Lower = better; -1 = not usable.
func igRank(e igExitCC, home string) int {
	cc := strings.ToUpper(e.CC)
	if cc == "" || igNoMusic(cc) {
		return -1
	}
	r := 40
	switch {
	case cc == "RU":
		r = 90
	case cc == strings.ToUpper(home):
		r = 10
	case igEurope[cc]:
		r = 20
	}
	if strings.HasPrefix(e.Music, "ok") {
		r -= 5
	}
	if e.Route == "direct" {
		r += 60 // every proxy first (but before Russia): the server's own IP is where the customers' Iranian traffic exits too
	}
	return r
}

// igCandidates: the routes to try for Instagram, best first (WARP = Want, when one of the server's
// WARPs reads a music country now).
func igCandidates(p igProbe, want, home string) []string {
	var out []string
	if igIsWarp(want) {
		for _, e := range p.Exits {
			if strings.HasPrefix(e.Route, "warp") && igRank(e, home) >= 0 {
				out = append(out, want)
				break
			}
		}
	}
	type c struct {
		r string
		k int
	}
	var cs []c
	for _, e := range p.Exits {
		if strings.HasPrefix(e.Route, "warp") {
			continue
		}
		if k := igRank(e, home); k >= 0 {
			cs = append(cs, c{e.Route, k})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].k < cs[j].k })
	for _, x := range cs {
		if x.r != p.Route {
			out = append(out, x.r)
		}
	}
	return out
}

// ---- state

func (a *App) igAutoGet(id string) IgAutoSvc {
	var s IgAutoSvc
	a.store.View(func(st *State) {
		if m := st.IgAuto[id]; m != nil && m["IG"] != nil {
			s = *m["IG"]
		}
	})
	return s
}

func (a *App) igAutoPut(id, svc string, fn func(s *IgAutoSvc)) {
	_ = a.store.Update(func(st *State) error {
		if st.IgAuto == nil {
			st.IgAuto = map[string]map[string]*IgAutoSvc{}
		}
		if st.IgAuto[id] == nil {
			st.IgAuto[id] = map[string]*IgAutoSvc{}
		}
		if st.IgAuto[id][svc] == nil {
			st.IgAuto[id][svc] = &IgAutoSvc{}
		}
		fn(st.IgAuto[id][svc])
		return nil
	})
}

func (a *App) igAutoLog(srv *Server, svc, kind, msg string) {
	_ = a.store.Update(func(st *State) error {
		st.IgAutoLog = append(st.IgAutoLog, IgAutoEvent{time.Now().Unix(), srv.ID, svc, kind, msg})
		if n := len(st.IgAutoLog); n > igAutoLogMax {
			st.IgAutoLog = append([]IgAutoEvent(nil), st.IgAutoLog[n-igAutoLogMax:]...)
		}
		return nil
	})
}

// igLiveCC: the panel's own fresher reading of Instagram's country (overrides the agent's
// 10-minute igcc on the page, so a fix shows at once)
func igLiveCC(id string) (string, bool) {
	igAutoMem.Lock()
	defer igAutoMem.Unlock()
	l := igAutoMem.live[id]
	if l == nil || l.CC == "" || time.Since(l.At) > 12*time.Minute {
		return "", false
	}
	return l.CC, true
}

// ---- the loop

func (a *App) igAutoLoop() {
	next := map[string]time.Time{}
	time.Sleep(90 * time.Second) // after a restart: let the page read the servers first
	for {
		var list []*Server
		a.store.View(func(st *State) {
			for _, x := range st.Servers {
				if x.Igproxy {
					list = append(list, x)
				}
			}
		})
		now := time.Now()
		for i, srv := range list {
			if t, ok := next[srv.ID]; ok && now.Before(t) {
				continue
			}
			// spread the servers over the 10 minutes
			next[srv.ID] = now.Add(igAutoEvery + time.Duration(i%5)*7*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			again := a.igAutoCheck(ctx, srv)
			cancel()
			if again {
				next[srv.ID] = time.Now().Add(igAutoTick)
			}
		}
		time.Sleep(igAutoTick)
	}
}

// igAutoCheck checks one server's Instagram and repairs it; true = look again at the next tick.
func (a *App) igAutoCheck(ctx context.Context, srv *Server) bool {
	igAutoMem.Lock()
	if igAutoMem.busy[srv.ID] {
		igAutoMem.Unlock()
		return false
	}
	igAutoMem.busy[srv.ID] = true
	igAutoMem.Unlock()
	defer func() { igAutoMem.Lock(); delete(igAutoMem.busy, srv.ID); igAutoMem.Unlock() }()

	inf := a.igInfo(ctx, srv)
	switch inf["state"] {
	case "OFFLINE", "NOAGENT", "SUDO", "PAUSED", "DOWN", "CHECKING", "":
		return false // the router itself is the problem: the other alerts cover it
	}
	if inf["ig"] == "" {
		return false
	}
	p, err := a.igAutoProbe(ctx, srv, false)
	if err != nil || !p.Relay {
		return false // an old agent without the users'-route relay: nothing to measure
	}
	route := inf["ig"]
	if p.Route != "" {
		route = p.Route
	}
	st := a.igAutoGet(srv.ID)
	if st.Off {
		return false
	}
	good := p.Live != "" && !igNoMusic(p.Live)

	// a route nobody here chose: a person (another page, by hand) or the agent's own fallback
	if (st.Cur != "" && route != st.Cur && route != st.Want) || (st.Cur == "" && st.Pin != "" && route != st.Pin && p.FB != route) {
		if p.FB != "" && p.FB == route {
			// the agent moved it (its WARP retries take over): keep our Want, drop our move
			a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) { s.Cur, s.Why, s.Tries, s.Next = "", "", 0, 0 })
		} else {
			a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) {
				if s.Pin != "" {
					s.Pin = route
				}
				s.Want, s.Cur, s.Why, s.Tries, s.Next = route, "", "", 0, 0
			})
			a.igAutoLog(srv, "IG", "info", "route changed by hand to "+igRouteWord(route)+" - followed")
		}
		st = a.igAutoGet(srv.ID)
	}

	if good {
		a.igAutoMark(srv.ID, p, 0)
		switch {
		case st.Cur == "" && (p.FB == "" || p.FB != route):
			if st.Want != route && st.Pin == "" {
				a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) { s.Want = route })
			}
		case st.Cur != "" && time.Now().Unix() >= st.Next:
			a.igAutoBack(ctx, srv, st)
		}
		return false
	}
	// bad: confirmed only the second time in a row (one probe can hit a hiccup)
	n := a.igAutoMark(srv.ID, p, 1)
	if n < 2 {
		return true
	}
	// (the agent's own fallback holding a no-music exit is repaired too)
	a.igAutoFix(ctx, srv, inf, route, p)
	return false
}

// igAutoMark records the live reading; bad=1 counts a bad one, 0 resets. Returns the bad count.
func (a *App) igAutoMark(id string, p igProbe, bad int) int {
	igAutoMem.Lock()
	defer igAutoMem.Unlock()
	l := igAutoMem.live[id]
	if l == nil {
		l = &igAutoLive{}
		igAutoMem.live[id] = l
	}
	l.CC, l.At, l.FB = p.Live, time.Now(), p.FB
	if bad == 0 {
		l.Bad = 0
	} else {
		l.Bad++
	}
	// the page's cached info follows the live reading at once
	a.ig.mu.Lock()
	if e, ok := a.ig.m[id]; ok && e.info != nil && p.Live != "" {
		m := make(map[string]string, len(e.info))
		for k, v := range e.info {
			m[k] = v
		}
		m["igcc"] = p.Live
		m["state"] = igStateOf(m, atoiOr(m["rc"]), "")
		a.ig.m[id] = igEntry{m, e.at}
	}
	a.ig.mu.Unlock()
	return l.Bad
}

func (a *App) igAutoProbe(ctx context.Context, srv *Server, scan bool) (igProbe, error) {
	tmo := 50 * time.Second
	if scan {
		tmo = 90 * time.Second
	}
	rc, lines, err := a.igShell(ctx, srv, igAutoScript(scan), tmo)
	if rc != 0 {
		if err == nil {
			err = fmt.Errorf("the server answered with code %d", rc)
		}
		return igProbe{}, err
	}
	return igParseProbe(lines), nil
}

// igAutoRoute sets Instagram's route and reads the users' route again: the live country ("" = no answer).
func (a *App) igAutoRoute(ctx context.Context, srv *Server, via string) (string, error) {
	rc, out := a.igRun(ctx, srv, []string{"route", "IG", via}, "", 180, nil)
	if rc != 0 {
		return "", fmt.Errorf("route IG %s: %s", via, clipTo(strings.TrimSpace(out), 160))
	}
	a.igForget(srv.ID)
	a.wpKick(srv.ID) // WARP's pool follows the route
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(5 * time.Second):
	}
	p, err := a.igAutoProbe(ctx, srv, false)
	if err != nil {
		return "", err
	}
	return p.Live, nil
}

func igRouteWord(v string) string {
	switch {
	case v == "warp6":
		return "WARP IPv6"
	case v == "warp":
		return "WARP"
	case v == "ipv6":
		return "IPv6"
	case v == "direct":
		return "own IP"
	case v == "proxy":
		return "proxies"
	case strings.HasPrefix(v, "proxy"):
		return "proxy " + strings.TrimPrefix(v, "proxy")
	}
	return v
}

func igWhyBad(live string) string {
	if live == "" {
		return "no answer"
	}
	return "Instagram sees " + live
}

// igAutoFix moves Instagram to the best exit that reads a music country now.
func (a *App) igAutoFix(ctx context.Context, srv *Server, inf map[string]string, route string, p0 igProbe) {
	st := a.igAutoGet(srv.ID)
	want := st.Want
	if want == "" || st.Cur == "" {
		want = route // the route it was on is the one to go back to
	}
	if st.Pin != "" {
		want = st.Pin
	}
	why := igWhyBad(p0.Live)
	if igIsWarp(route) && inf["warps"] == "0" {
		why = "no WARP on the server"
	}
	p, err := a.igAutoProbe(ctx, srv, true)
	if err != nil {
		return
	}
	cands := igCandidates(p, want, srv.Country)
	// none of the server's own: a proxy of another server of the same owner
	if len(cands) == 0 {
		if r := a.igBorrowProxy(ctx, srv); r != "" {
			cands = append(cands, r)
		}
	}
	for _, c := range cands {
		if ctx.Err() != nil {
			return
		}
		if c == route {
			continue
		}
		cc, err := a.igAutoRoute(ctx, srv, c)
		if err == nil && cc != "" && !igNoMusic(cc) {
			now := time.Now()
			back := c == want
			a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) {
				s.Want = want
				if back {
					s.Cur, s.Why, s.Since, s.Tries, s.Next = "", "", 0, 0, 0
				} else {
					s.Cur, s.Why, s.Since, s.Tries, s.Next = c, why, now.Unix(), 0, now.Add(igAutoBackMin).Unix()
				}
			})
			a.igAutoMark(srv.ID, igProbe{Live: cc, FB: p.FB}, 0)
			a.igAutoLog(srv, "IG", "fix", fmt.Sprintf("%s on %s (%s) -> %s (%s)", why, igRouteWord(route), orDash(p0.Live), igRouteWord(c), cc))
			return
		}
		if err != nil {
			a.igAutoLog(srv, "IG", "info", "tried "+igRouteWord(c)+": "+err.Error())
		} else {
			a.igAutoLog(srv, "IG", "info", "tried "+igRouteWord(c)+": "+igWhyBad(cc))
		}
	}
	// nothing works: put the route back and tell a person (at most every 6 h)
	if cur := a.igAutoCurRoute(ctx, srv); cur != route && route != "" {
		_, _ = a.igAutoRoute(ctx, srv, route)
	}
	a.igAutoLog(srv, "IG", "fail", fmt.Sprintf("%s on %s and no other exit reads a music country", why, igRouteWord(route)))
	if time.Since(time.Unix(st.Alert, 0)) > igAutoAlertGap {
		a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) { s.Alert = time.Now().Unix() })
		a.push(fmt.Sprintf("🛰 Instagram on %s: %s (route %s), and no WARP, proxy or own IP of the server reads a music country. Add a working proxy on the IG Routing page.", igLabel(srv), why, igRouteWord(route)))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *App) igAutoCurRoute(ctx context.Context, srv *Server) string {
	inf := a.igInfo(ctx, srv)
	return inf["ig"]
}

// igAutoBack tries the route it should be on again; it stays there only if it reads a music country.
func (a *App) igAutoBack(ctx context.Context, srv *Server, st IgAutoSvc) {
	want := st.Want
	if st.Pin != "" {
		want = st.Pin
	}
	if want == "" || want == st.Cur {
		a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) { s.Cur, s.Why, s.Tries, s.Next = "", "", 0, 0 })
		return
	}
	retry := func(why string) {
		d := igAutoBackMin << uint(st.Tries+1)
		if d > igAutoBackMax || d <= 0 {
			d = igAutoBackMax
		}
		a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) { s.Tries++; s.Next = time.Now().Add(d).Unix() })
		if st.Tries == 0 || st.Tries%4 == 3 { // not every try in the history
			a.igAutoLog(srv, "IG", "info", fmt.Sprintf("%s still not usable (%s) - stays on %s, next try in %s", igRouteWord(want), why, igRouteWord(st.Cur), d.Round(time.Minute)))
		}
	}
	// WARP: first a look at the WARPs without touching the users (a WARP in a music country?)
	if igIsWarp(want) {
		inf := a.igInfo(ctx, srv)
		if inf["warps"] == "0" {
			retry("no WARP on the server")
			return
		}
		p, err := a.igAutoProbe(ctx, srv, true)
		if err != nil {
			return
		}
		ok := false
		for _, e := range p.Exits {
			if strings.HasPrefix(e.Route, "warp") && igRank(e, srv.Country) >= 0 {
				ok = true
			}
		}
		if !ok {
			retry("no WARP reads a music country")
			return
		}
	}
	cc, err := a.igAutoRoute(ctx, srv, want)
	if err == nil && cc != "" && !igNoMusic(cc) {
		a.igAutoPut(srv.ID, "IG", func(s *IgAutoSvc) { s.Cur, s.Why, s.Since, s.Tries, s.Next = "", "", 0, 0, 0 })
		a.igAutoMark(srv.ID, igProbe{Live: cc}, 0)
		a.igAutoLog(srv, "IG", "back", fmt.Sprintf("%s works again (%s) - back from %s", igRouteWord(want), cc, igRouteWord(st.Cur)))
		return
	}
	// not yet: back to the exit that works
	why := igWhyBad(cc)
	if err != nil {
		why = err.Error()
	}
	if cc2, err2 := a.igAutoRoute(ctx, srv, st.Cur); err2 != nil || cc2 == "" || igNoMusic(cc2) {
		a.igAutoLog(srv, "IG", "info", "back on "+igRouteWord(st.Cur)+" after the try, but it reads "+orDash(cc2))
	}
	retry(why)
}

// igBorrowProxy copies one proxy from another server of the same owner that reads a music
// country from this server, and returns its route ("proxyN"), or "". Our own servers' relays
// are never copied (internal relays are off by the user's choice, 2026-11-10). The proxy line
// (with its password) only passes through the panel's memory.
func (a *App) igBorrowProxy(ctx context.Context, srv *Server) string {
	own := map[string]bool{}
	var donors []*Server
	a.store.View(func(st *State) {
		for _, x := range st.Servers {
			if x.IPv4 != "" {
				own[x.IPv4] = true
			}
			if x.Igproxy && x.ID != srv.ID && x.Owner == srv.Owner {
				donors = append(donors, x)
			}
		}
	})
	have := map[string]bool{}
	if rc, lines, _ := a.igShell(ctx, srv, "awk '{print $2\":\"$3}' /etc/igproxy/proxies 2>/dev/null; echo __RC=0", 20*time.Second); rc == 0 {
		for _, l := range lines {
			have[strings.TrimSpace(l)] = true
		}
	}
	seen := map[string]bool{}
	tried := 0
	for _, d := range donors {
		rc, lines, _ := a.igShell(ctx, d, "cat /etc/igproxy/proxies 2>/dev/null; echo __RC=0", 20*time.Second)
		if rc != 0 {
			continue
		}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) < 3 || (f[0] != "http" && f[0] != "socks5") || own[f[1]] {
				continue
			}
			k := f[1] + ":" + f[2]
			if have[k] || seen[k] || tried >= 3 {
				continue
			}
			seen[k] = true
			tried++
			if rc, out := a.igRun(ctx, srv, []string{"proxy", "add", "-"}, strings.Join(f, " ")+"\n", 120, nil); rc != 0 {
				a.igAutoLog(srv, "IG", "info", "could not add proxy "+k+" from "+d.Name+": "+clipTo(strings.TrimSpace(out), 120))
				continue
			}
			a.igForget(srv.ID)
			p, err := a.igAutoProbe(ctx, srv, true)
			if err != nil {
				return ""
			}
			for _, e := range p.Exits {
				if e.Host == f[1] && strings.HasPrefix(e.Route, "proxy") {
					if igRank(e, srv.Country) >= 0 {
						a.igAutoLog(srv, "IG", "info", fmt.Sprintf("copied proxy %s from %s (%s reads %s)", k, d.Name, e.Route, e.CC))
						return e.Route
					}
					// no good from here: take it out again
					a.igRun(ctx, srv, []string{"proxy", "del", strings.TrimPrefix(e.Route, "proxy")}, "", 120, nil)
					a.igForget(srv.ID)
				}
			}
		}
	}
	return ""
}

// ---- API

// igAutoView is what the page gets per server
type igAutoView struct {
	IG     *IgAutoSvc           `json:"ig,omitempty"`
	Pins   map[string]string    `json:"pins,omitempty"` // GOOGLE / YTM pins
	Live   string               `json:"live,omitempty"` // Instagram's country on the users' route, measured by the panel
	LiveAt int64                `json:"liveAt,omitempty"`
	Last   []IgAutoEvent        `json:"last,omitempty"` // the server's last events
	Warp   *WarpPool            `json:"warp,omitempty"` // the automatic WARP pool (warppool.go)
	Svc    map[string]igSvcView `json:"svc,omitempty"`  // every service: Auto / pinned, its last check (igsvc.go)
}

func (a *App) igAutoViewOf(id string) *igAutoView {
	v := &igAutoView{}
	a.store.View(func(st *State) {
		if m := st.IgAuto[id]; m != nil {
			if s := m["IG"]; s != nil {
				c := *s
				v.IG = &c
			}
			for _, k := range []string{"GOOGLE", "YTM"} {
				if s := m[k]; s != nil && s.Pin != "" {
					if v.Pins == nil {
						v.Pins = map[string]string{}
					}
					v.Pins[k] = s.Pin
				}
			}
		}
		if p := st.WarpPool[id]; p != nil {
			c := *p
			v.Warp = &c
		}
		for i := len(st.IgAutoLog) - 1; i >= 0 && len(v.Last) < 6; i-- {
			if st.IgAutoLog[i].Srv == id {
				v.Last = append(v.Last, st.IgAutoLog[i])
			}
		}
	})
	v.Svc = a.igSvcViewOf(id)
	igAutoMem.Lock()
	if l := igAutoMem.live[id]; l != nil && l.CC != "" {
		v.Live, v.LiveAt = l.CC, l.At.Unix()
	}
	igAutoMem.Unlock()
	return v
}

var igAutoSvcOK = map[string]bool{"IG": true, "GOOGLE": true, "YTM": true}
var igAutoVia = regexp.MustCompile(`^(proxy|proxy[0-9]{1,2}|warp|warp6|ipv6|direct)$`)

// POST /api/igproxy/auto {id, svc, mode: auto|pin|off, via}
// auto = the panel keeps it working (Instagram) / the agent's own guards (Google); pin = this exit
// (it still fails over while the pinned one is broken, and comes back); off = no automatic moves.
func (s *Server2) igAutoSet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct{ ID, Svc, Mode, Via string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, in.ID)
	if err == nil && in.Svc == "WARP" {
		// the WARP pool: auto (the panel sizes it) or by hand
		if in.Mode != "auto" && in.Mode != "off" {
			httpErr(w, 400, "mode is auto or off")
			return
		}
		s.app.wpPut(x.ID, func(p *WarpPool) {
			p.Off = in.Mode == "off"
			if !p.Off {
				p.Hold = 0
			}
		})
		s.app.igAutoLog(x, "WARP", "info", map[string]string{"auto": "WARP accounts: automatic", "off": "WARP accounts: by hand"}[in.Mode]+" (by "+orDash(user)+")")
		if in.Mode == "auto" {
			s.app.wpKick(x.ID)
		}
		writeJSON(w, s.app.igAutoViewOf(x.ID))
		return
	}
	if err == nil && !igAutoSvcOK[in.Svc] {
		err = errors.New("unknown service")
	}
	if err == nil && in.Mode == "pin" && !igAutoVia.MatchString(in.Via) {
		err = errors.New("unknown exit")
	}
	if err == nil && in.Mode == "pin" && gemHomeRouteBad(x, in.Svc, in.Via) {
		err = errors.New(gemHomeRefusal)
	}
	if err == nil && in.Mode != "auto" && in.Mode != "pin" && in.Mode != "off" {
		err = errors.New("mode is auto, pin or off")
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if in.Mode == "pin" {
		ctx, cancel := context.WithTimeout(r.Context(), 200*time.Second)
		defer cancel()
		if rc, out := s.app.igRun(ctx, x, []string{"route", in.Svc, in.Via}, "", 180, nil); rc != 0 {
			httpErr(w, 502, "route "+in.Svc+" "+in.Via+": "+clipTo(strings.TrimSpace(out), 200))
			return
		}
		s.app.igForget(x.ID)
		s.app.wpKick(x.ID)
	}
	s.app.igAutoPut(x.ID, in.Svc, func(a *IgAutoSvc) {
		switch in.Mode {
		case "pin":
			a.Off, a.Pin, a.Want, a.Cur, a.Why, a.Tries, a.Next = false, in.Via, in.Via, "", "", 0, 0
		case "auto":
			a.Off, a.Pin = false, ""
		case "off":
			a.Off = true
		}
	})
	word := map[string]string{"auto": "Auto", "off": "automatic repair off", "pin": "pinned to " + igRouteWord(in.Via)}[in.Mode]
	s.app.igAutoLog(x, in.Svc, "info", word+" (by "+orDash(user)+")")
	if in.Svc == "IG" && in.Mode != "off" {
		go func() { // look at once (a pin to a dead exit fails over within minutes)
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()
			if s.app.igAutoCheck(ctx, x) {
				time.Sleep(igAutoTick)
				s.app.igAutoCheck(ctx, x)
			}
		}()
	}
	writeJSON(w, s.app.igAutoViewOf(x.ID))
}

// GET /api/igproxy/auto/log?id= : the automatic events (one server, or every visible one)
func (s *Server2) igAutoLogGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	id := r.URL.Query().Get("id")
	ok := map[string]string{}
	for _, x := range s.igServersOf(user, admin, "") {
		ok[x.ID] = x.Name
	}
	type ev struct {
		IgAutoEvent
		Name string `json:"name"`
	}
	out := []ev{}
	s.app.store.View(func(st *State) {
		for i := len(st.IgAutoLog) - 1; i >= 0 && len(out) < 100; i-- {
			e := st.IgAutoLog[i]
			if n, vis := ok[e.Srv]; vis && (id == "" || id == e.Srv) {
				out = append(out, ev{e, n})
			}
		}
	})
	writeJSON(w, out)
}
