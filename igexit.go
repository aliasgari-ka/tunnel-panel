package main

// IG Routing · automatic exits for Google · Gemini and YouTube Music.
//
// Each server's users' route (the agent's relay 12370: the rules the users get) is read every
// 10 minutes: for Gemini the country Google places it in (the keyless app's OneGoogle domain,
// og.qtm) and whether Google answers at all (403 = this IP is refused); for YouTube Music the
// "not available in your region" page. When the service's current exit fails twice in a row,
// the panel tries the other exits of the server in a fixed order and keeps the first one that
// passes the same check on the users' route:
//
//  1. the server's own IPv4, then its own IPv6
//  2. WARP over IPv4
//  3. WARP IPv6 — on the exit Google already used, a fresh WARP IP (the agent's "google rotate":
//     the accounts themselves stay with the WARP pool, warppool.go)
//  4. each configured outbound / proxy
//  5. a relay through another of our servers (same owner) whose own IP passes
//
// The route it left is the one to go back to (Want). It is tried again after 30 min, doubling to
// 6 h, and taken back only when it passes twice in a row; a fail soon after a move back makes
// the next try later (Tries is kept until the exit has held for 6 h), so it does not flap.
//
// A pinned exit (a person picked one on the page) is read like the others, so the page shows
// what the users really get on it, but never moved; "off" is not read. A route somebody
// changed outside the panel is followed as the new Want. The panel host's users' Google never
// leaves through its own IP (gemhome.go: the Google test account's exit), and no server relays
// through it either.
//
// Why not the signed-in browser check (gbrowser): the test account lives on the panel host's own
// IP alone, which the users never get, and the signed-out app has stopped saying where Google
// places an exit (2026-11-14: Russia's WARPs and Turkey looked the same). Google's own country
// for the IP is the signal both the page and the agent's gdom use. On warp6 the reading also asks
// whether IPv6 really passes through the WARPs: a WARP whose IPv6 is dead falls back to Cloudflare's
// shared IPv4, where the keyless page reads fine but signed-in users are refused.
//
// Instagram has its own ladder (igauto.go); the newer services theirs (igsvc.go).

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	igExEvery    = 10 * time.Minute
	igExTick     = 2 * time.Minute
	igExBadTimes = 2
	igExBackMin  = 30 * time.Minute
	igExBackMax  = 6 * time.Hour
	igExHeld     = 6 * time.Hour // a move back that held this long forgets the earlier tries
	igExSettle   = 5 * time.Second
	igExProxyMax = 4 // single outbounds tried per fix
	igExRelayMax = 3 // other servers tried as a relay per fix
)

// the services this file moves
var igExSvcs = []string{"GOOGLE", "YTM"}

// Google offers no Gemini in these (the page's IG_GBAD)
var igExNoGemini = map[string]bool{"ir": true, "ru": true, "cn": true, "by": true, "cu": true, "sy": true, "kp": true}

var (
	igExDomRe   = regexp.MustCompile(`^(?:co|com)\.([a-z]{2})$`)
	igExAddedRe = regexp.MustCompile(`proxy ([0-9]+) added`)
)

// igExRead is one reading of a service on one exit.
type igExRead struct {
	Code string // http code ("000" = no connection)
	Dom  string // Gemini: Google's domain for the exit ("de", "com", "com.tr"); YTM: YouTube's GL
	Flag string // "region" = the service's own "not available here" page
	// V6: on warp6 only, whether IPv6 really passes through the WARPs that carry the service
	// ("ok", "no"; "" = not on warp6 / not measured). A WARP whose IPv6 is dead still answers over
	// Cloudflare's shared IPv4: the keyless page reads fine there, a signed-in Gemini does not
	// (Ger-hertzener, 2026-11-14: "WARP IPv6" ✓, users refused).
	V6 string
}

// igExDomCC: Google's domain as a country code ("com.tr" -> TR, "co.uk" -> GB, "com" -> "").
func igExDomCC(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if m := igExDomRe.FindStringSubmatch(d); m != nil {
		d = m[1]
	}
	if d == "uk" {
		return "GB"
	}
	if len(d) == 2 {
		return strings.ToUpper(d)
	}
	return ""
}

// igExVerdict: "ok", "bad" or "" (no verdict: the check itself did not get through) and why.
func igExVerdict(svc string, r *igExRead) (string, string) {
	if r == nil {
		return "", ""
	}
	code := r.Code
	if code == "" || code == "000" {
		return "bad", "no answer"
	}
	if r.V6 == "no" {
		return "bad", "WARP IPv6 passes no IPv6"
	}
	switch svc {
	case "GOOGLE":
		if code == "403" {
			return "bad", "Google refuses the IP (403)"
		}
		if code == "429" {
			return "bad", "Google asks for a captcha"
		}
		if r.Flag == "region" {
			return "bad", "Gemini not offered there"
		}
		d := strings.ToLower(r.Dom)
		cc := igExDomCC(d)
		if igExNoGemini[strings.ToLower(cc)] {
			return "bad", "Gemini not offered in " + cc
		}
		if strings.HasPrefix(code, "5") || d == "" || d == "-" {
			return "", "" // Google answered without its country: no verdict
		}
		return "ok", ""
	case "YTM":
		if r.Flag == "region" {
			return "bad", "YouTube Music not offered there"
		}
		if strings.HasPrefix(code, "5") {
			return "", ""
		}
		if code == "403" {
			return "bad", "YouTube refuses the IP (403)"
		}
		return "ok", ""
	}
	return "", ""
}

// igExScript reads the services through socks port 127.0.0.1:port of the server
// (12370 = the users' route, 12371 = the server's own IP). One line "X <SVC> <code> <dom> <flag> <v6>".
// On the users' route a service on warp6 also gets v6: IPv6 to an IPv6 address through each WARP
// test port of the WARPs that carry it (gb = Google's own, wb = the rest; config.json).
func igExScript(svcs []string, port int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `#igexit
grep -q "^VER=" /usr/local/bin/igproxy 2>/dev/null || { echo __RC=3; exit 0; }
ss -ltn 2>/dev/null | grep -q ':%d ' || { echo NORELAY; echo __RC=0; exit 0; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
X="-x socks5h://127.0.0.1:%d"
f=$(mktemp)
g(){ local c d fl=- i
  for i in 1 2; do
    c=$(curl -s -m 15 -A "$UA" $X -H 'Accept-Language: en-US,en;q=0.9' -o "$f" -w '%%{http_code}' https://gemini.google.com/app 2>/dev/null)
    [ "${c:-000}" != 000 ] && break; sleep 2
  done
  d=$(grep -oE 'og[.]qtm[^"]*","[a-z.]{2,8}"' "$f" | head -1 | sed -E 's/.*"([a-z.]+)"$/\1/')
  grep -qsi "not supported in your country\|isn.t currently supported\|not available in your country\|not available in your region" "$f" && fl=region
  echo "X GOOGLE ${c:-000} ${d:--} $fl $(v6 GOOGLE)"; }
y(){ local r c d fl=- i
  for i in 1 2; do
    r=$(curl -s -m 15 -A "$UA" $X -H 'Accept-Language: en-US,en;q=0.9' -o "$f" -w '%%{http_code} %%{redirect_url}' https://music.youtube.com/ 2>/dev/null); c=${r%%%% *}
    [ "${c:-000}" != 000 ] && break; sleep 2
  done
  case "${r#* }" in *unavailable-in-region*|*not-available*) fl=region;; esac
  grep -qsi "unavailable-in-region\|not available in your country\|isn.t available in your country" "$f" && fl=region
  d=$(grep -oE '"GL":"[A-Z]{2}"' "$f" | head -1 | cut -d'"' -f4)
  echo "X YTM ${c:-000} ${d:--} $fl $(v6 YTM)"; }
`, port, port)
	if port == gemRelayPort {
		b.WriteString(igExV6Sh)
	} else {
		b.WriteString("v6(){ echo -; }\n")
	}
	for _, s := range svcs {
		switch s {
		case "GOOGLE":
			b.WriteString("g\n")
		case "YTM":
			b.WriteString("y\n")
		}
	}
	b.WriteString("rm -f \"$f\"\necho __RC=0\n")
	return b.String()
}

// igExV6Sh: v6 <SVC> -> ok | no | - (not on warp6, or no WARP test port found). Every WARP that may
// carry the service must pass: the balancer can pick any of them. A failed one is asked again once
// (a tunnel that just came up).
const igExV6Sh = `v6(){
  [ "$(awk -F= -v s="$1" '$1==s{print $2}' /etc/igproxy/routes 2>/dev/null)" = warp6 ] || { echo -; return; }
  local b=wb p n=0 ok=0 i; [ "$1" = GOOGLE ] && b=gb
  for p in $(python3 -c 'import json,sys
c=json.load(open("/etc/igproxy/config.json")); r=c.get("routing",{})
sel=[x for B in r.get("balancers",[]) if B.get("tag")==sys.argv[1] for x in B.get("selector",[])]
ins={x["outboundTag"]:x["inboundTag"][0] for x in r.get("rules",[]) if x.get("outboundTag") and len(x.get("inboundTag") or [])==1 and str(x["inboundTag"][0]).startswith("wtest")}
port={i.get("tag"):i.get("port") for i in c.get("inbounds",[])}
for o in c.get("outbounds",[]):
  t=o.get("tag","")
  if t.startswith("warp") and any(t.startswith(s) for s in sel) and ins.get(t) in port: print(port[ins[t]])' "$b" 2>/dev/null); do
    n=$((n+1))
    for i in 1 2; do
      curl -s -m 10 -x "socks5://127.0.0.1:$p" 'https://[2606:4700:4700::1111]/cdn-cgi/trace' 2>/dev/null | grep -q '^ip=.*:' && { ok=$((ok+1)); break; }
      sleep 2
    done
  done
  [ "$n" = 0 ] && { echo -; return; }
  [ "$ok" = "$n" ] && echo ok || echo no; }
`

// igExParse reads the script's lines; false = the relay is not there (an old agent).
func igExParse(lines []string) (map[string]*igExRead, bool) {
	out := map[string]*igExRead{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "NORELAY" {
			return nil, false
		}
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != "X" {
			continue
		}
		r := &igExRead{Code: f[2], Dom: f[3]}
		if r.Dom == "-" {
			r.Dom = ""
		}
		if len(f) > 4 && f[4] == "region" {
			r.Flag = "region"
		}
		if len(f) > 5 && (f[5] == "ok" || f[5] == "no") {
			r.V6 = f[5]
		}
		out[f[1]] = r
	}
	return out, true
}

// igExLadder: the exits to try for svc on this server, in order, leaving out the failing one
// (route). A WARP route that failed comes back as a fresh WARP IP ("warp6+") for Google.
func igExLadder(svc string, srv *Server, inf map[string]string, route string) []string {
	home := gemIsHome(srv)
	warps := atoiOr(inf["warps"]) > 0
	var out []string
	add := func(v string) {
		if v == route && !(svc == "GOOGLE" && igIsWarp(v)) {
			return
		}
		if v == route {
			v += "+" // the same WARP route, on a fresh WARP IP
		}
		if !contains(out, v) {
			out = append(out, v)
		}
	}
	if !home {
		add("direct")
	}
	if strings.TrimSpace(srv.IPv6) != "" {
		add("ipv6")
	}
	if warps {
		add("warp")
		add("warp6")
	}
	hub := gemHomeHost()
	rel := igRelays(inf)
	for n := 1; n <= atoiOr(inf["proxies"]) && n <= igExProxyMax; n++ {
		if r, ok := rel[n]; ok && r[0] == hub {
			continue // a relay through the panel host's own IP: never
		}
		add("proxy" + strconv.Itoa(n))
	}
	out = append(out, "relay")
	return out
}

// igExBackAfter: the pause before the preferred exit is tried again, after tries failed tries.
func igExBackAfter(tries int) time.Duration {
	d := igExBackMin << uint(min(tries, 8))
	if d > igExBackMax || d <= 0 {
		d = igExBackMax
	}
	return d
}

// ---- live state (memory only)

type igExLive struct {
	Read igExRead
	OK   string
	Why  string
	At   time.Time
	Bad  int
}

var igExMem = struct {
	sync.Mutex
	live map[string]map[string]*igExLive
}{live: map[string]map[string]*igExLive{}}

func igExMark(id, svc string, r *igExRead, v, why string) int {
	igExMem.Lock()
	defer igExMem.Unlock()
	m := igExMem.live[id]
	if m == nil {
		m = map[string]*igExLive{}
		igExMem.live[id] = m
	}
	l := m[svc]
	if l == nil {
		l = &igExLive{}
		m[svc] = l
	}
	if r != nil {
		l.Read = *r
	}
	l.OK, l.Why, l.At = v, why, time.Now()
	switch v {
	case "ok":
		l.Bad = 0
	case "bad":
		l.Bad++
	}
	return l.Bad
}

// igExIsAuto: the panel may move this service of this server (not pinned, not off).
func igExIsAuto(rec *IgAutoSvc) bool {
	return rec == nil || (rec.Pin == "" && !rec.Off)
}

// ---- the loop

func (a *App) igExitLoop() {
	next := map[string]time.Time{}
	time.Sleep(4 * time.Minute) // after a restart: after the page, igauto and igsvc
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
			next[srv.ID] = now.Add(igExEvery + time.Duration(i%5)*11*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
			if a.igExCheck(ctx, srv) {
				next[srv.ID] = time.Now().Add(igExTick)
			}
			cancel()
		}
		time.Sleep(igExTick)
	}
}

// igExRun reads svcs through the server's socks port; nil = no reading.
func (a *App) igExRun(ctx context.Context, srv *Server, svcs []string, port int) map[string]*igExRead {
	rc, lines, err := a.igShell(ctx, srv, igExScript(svcs, port), 80*time.Second)
	if err != nil || rc != 0 {
		return nil
	}
	m, ok := igExParse(lines)
	if !ok {
		return nil
	}
	return m
}

// igExCheck reads one server's Google and YouTube Music and moves the ones that fail; true = look again soon.
func (a *App) igExCheck(ctx context.Context, srv *Server) bool {
	// one at a time with igsvc on a server: both change routes
	igSvcMem.Lock()
	if igSvcMem.busy[srv.ID] {
		igSvcMem.Unlock()
		return true
	}
	igSvcMem.busy[srv.ID] = true
	igSvcMem.Unlock()
	defer func() { igSvcMem.Lock(); delete(igSvcMem.busy, srv.ID); igSvcMem.Unlock() }()

	inf := a.igInfo(ctx, srv)
	switch inf["state"] {
	case "OFFLINE", "NOAGENT", "SUDO", "PAUSED", "DOWN", "CHECKING", "":
		return false
	}
	recs := a.igSvcRecs(srv.ID)
	var svcs []string
	for _, k := range igExSvcs {
		route := inf[strings.ToLower(k)]
		// a pinned exit is read too (the page shows what the users get on it), never moved
		if route == "" || (recs[k] != nil && recs[k].Off) {
			continue
		}
		if gemIsHome(srv) && route == "direct" {
			continue // the guard (gemhome.go) moves it off the test account's IP
		}
		svcs = append(svcs, k)
	}
	if len(svcs) == 0 {
		return false
	}
	read := a.igExRun(ctx, srv, svcs, gemRelayPort)
	if read == nil {
		return false
	}
	again := false
	now := time.Now()
	for _, k := range svcs {
		route := inf[strings.ToLower(k)]
		rec := recs[k]
		if !igExIsAuto(rec) {
			v, why := igExVerdict(k, read[k])
			igExMark(srv.ID, k, read[k], v, why)
			continue
		}
		// a route nobody here chose: followed
		if rec != nil && rec.Cur != "" && route != rec.Cur && route != rec.Want {
			a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Want, s.Cur, s.Why, s.Tries, s.Next = route, "", "", 0, 0 })
			a.igAutoLog(srv, k, "info", fmt.Sprintf("%s: route changed outside the panel to %s - followed", igSvcName(k), igRouteWord(route)))
			rec = nil
		}
		if rec == nil || rec.Cur == "" {
			if rec == nil || rec.Want != route {
				a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Want = route })
			}
		}
		r := read[k]
		v, why := igExVerdict(k, r)
		bad := igExMark(srv.ID, k, r, v, why)
		switch v {
		case "ok":
			if rec != nil && rec.Cur != "" && now.Unix() >= rec.Next {
				a.igExBack(ctx, srv, k, *rec)
			}
		case "bad":
			if bad < igExBadTimes {
				again = true
				continue
			}
			a.igExFix(ctx, srv, k, route, why)
			inf = a.igInfo(ctx, srv) // proxies may have been added
		}
	}
	return again
}

// igExSet puts svc on via ("warp6+" = warp6 on a fresh WARP IP) and reads the users' route.
func (a *App) igExSet(ctx context.Context, srv *Server, svc, via string) (string, *igExRead, error) {
	fresh := strings.HasSuffix(via, "+")
	via = strings.TrimSuffix(via, "+")
	if gemHomeRouteBad(srv, svc, via) || (gemIsHome(srv) && via == "direct") {
		return "", nil, fmt.Errorf("not on the panel host's own IP")
	}
	if err := a.igSvcRoute(ctx, srv, map[string]string{svc: via}); err != nil {
		return "", nil, err
	}
	if fresh && svc == "GOOGLE" {
		if rc, out := a.igRun(ctx, srv, []string{"google", "rotate"}, "", 110, nil); rc != 0 {
			return "", nil, fmt.Errorf("google rotate: %s", clipTo(agentLine(srv, out), 120))
		}
		a.igForget(srv.ID)
	}
	a.wpKick(srv.ID)
	select {
	case <-ctx.Done():
		return "", nil, ctx.Err()
	case <-time.After(igExSettle):
	}
	m := a.igExRun(ctx, srv, []string{svc}, gemRelayPort)
	if m == nil {
		return "", nil, fmt.Errorf("no reading")
	}
	v, _ := igExVerdict(svc, m[svc])
	return v, m[svc], nil
}

func igExWhere(svc string, r *igExRead) string {
	if r == nil {
		return ""
	}
	if svc == "GOOGLE" {
		if cc := igExDomCC(r.Dom); cc != "" {
			return cc
		}
		if r.Dom != "" {
			return "google." + r.Dom
		}
		return ""
	}
	return r.Dom
}

func igExWord(v string) string {
	if v == "relay" {
		return "a relay"
	}
	if strings.HasSuffix(v, "+") {
		return igRouteWord(strings.TrimSuffix(v, "+")) + " (fresh IP)"
	}
	return igRouteWord(v)
}

// igExFix tries the ladder and keeps the first exit that passes.
func (a *App) igExFix(ctx context.Context, srv *Server, svc, route, why string) {
	recs := a.igSvcRecs(srv.ID)
	rec := recs[svc]
	want := route
	if rec != nil && rec.Cur != "" && rec.Want != "" {
		want = rec.Want // the current fallback failed too: the preferred one stays the goal
	}
	inf := a.igInfo(ctx, srv)
	name := igSvcName(svc)
	var tried []string
	for _, c := range igExLadder(svc, srv, inf, route) {
		if ctx.Err() != nil {
			return
		}
		via := c
		var added int
		if c == "relay" {
			via, added = a.igExRelay(ctx, srv, svc)
			if via == "" {
				continue
			}
		}
		v, r, err := a.igExSet(ctx, srv, svc, via)
		if err == nil && v == "ok" {
			now := time.Now()
			keep := strings.TrimSuffix(via, "+")
			back := keep == want
			a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) {
				if s.Back > 0 && now.Sub(time.Unix(s.Back, 0)) > igExHeld {
					s.Tries = 0
				}
				s.Want = want
				if back {
					s.Cur, s.Why, s.Since, s.Next = "", "", 0, 0
					return
				}
				s.Cur, s.Why, s.Since = keep, igRouteWord(route)+": "+why, now.Unix()
				s.Next = now.Add(igExBackAfter(s.Tries)).Unix()
			})
			igExMark(srv.ID, svc, r, "ok", "")
			where := igExWhere(svc, r)
			if where != "" {
				where = ", " + where
			}
			word := igExWord(via)
			if c == "relay" {
				word = igProxyName(a.igInfo(ctx, srv), keep, a.igServerByIP)
			}
			a.igAutoLog(srv, svc, "fix", fmt.Sprintf("%s on %s: %s -> %s%s", name, igRouteWord(route), why, word, where))
			a.igExPatchInfo(srv.ID, svc, keep, r)
			a.push(fmt.Sprintf("🔀 %s: %s %s → %s%s (auto)", igLabel(srv), name, igRouteWord(route)+" failed ("+why+")", word, where))
			return
		}
		if added > 0 { // the relay did not pass: take it out again
			a.igRun(ctx, srv, []string{"proxy", "del", strconv.Itoa(added)}, "", 120, nil)
			a.igForget(srv.ID)
		}
		w := "no reading"
		if err != nil {
			w = clipTo(err.Error(), 80)
		} else if _, y := igExVerdict(svc, r); y != "" {
			w = y
		}
		tried = append(tried, igExWord(c)+" ("+w+")")
	}
	// nothing passed: back where it was, and tell a person at most every 6 h
	if cur := a.igInfo(ctx, srv)[strings.ToLower(svc)]; cur != route {
		_ = a.igSvcRoute(ctx, srv, map[string]string{svc: route})
	}
	a.igAutoLog(srv, svc, "fail", fmt.Sprintf("%s on %s: %s; nothing else passed: %s", name, igRouteWord(route), why, strings.Join(tried, ", ")))
	if rec == nil || time.Since(time.Unix(rec.Alert, 0)) > igAutoAlertGap {
		a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) { s.Alert = time.Now().Unix() })
		a.push(fmt.Sprintf("🔀⚠️ %s: %s fails on %s (%s) and no other exit passes — add an outbound on the IG Routing page.", igLabel(srv), name, igRouteWord(route), why))
	}
}

// igExBack tries the preferred exit again; it is kept only when it passes twice.
func (a *App) igExBack(ctx context.Context, srv *Server, svc string, rec IgAutoSvc) {
	name := igSvcName(svc)
	v, r, err := a.igExSet(ctx, srv, svc, rec.Want)
	if err == nil && v == "ok" {
		time.Sleep(20 * time.Second)
		m := a.igExRun(ctx, srv, []string{svc}, gemRelayPort)
		if m != nil {
			v, _ = igExVerdict(svc, m[svc])
			r = m[svc]
		} else {
			v = ""
		}
	}
	if err == nil && v == "ok" {
		now := time.Now()
		a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) { s.Cur, s.Why, s.Since, s.Next, s.Back = "", "", 0, 0, now.Unix() })
		igExMark(srv.ID, svc, r, "ok", "")
		a.igExPatchInfo(srv.ID, svc, rec.Want, r)
		where := igExWhere(svc, r)
		if where != "" {
			where = ", " + where
		}
		a.igAutoLog(srv, svc, "back", fmt.Sprintf("%s: %s passes again%s - back from %s", name, igRouteWord(rec.Want), where, igRouteWord(rec.Cur)))
		a.push(fmt.Sprintf("🔀 %s: %s back on %s%s (it passes again; was on %s)", igLabel(srv), name, igRouteWord(rec.Want), where, igRouteWord(rec.Cur)))
		return
	}
	_ = a.igSvcRoute(ctx, srv, map[string]string{svc: rec.Cur})
	d := igExBackAfter(rec.Tries + 1)
	a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) { s.Tries++; s.Next = time.Now().Add(d).Unix() })
	if rec.Tries == 0 || rec.Tries%4 == 3 {
		w := "no reading"
		if err != nil {
			w = clipTo(err.Error(), 80)
		} else if _, y := igExVerdict(svc, r); y != "" {
			w = y
		}
		a.igAutoLog(srv, svc, "info", fmt.Sprintf("%s: %s still fails (%s) - stays on %s, next try in %s", name, igRouteWord(rec.Want), w, igRouteWord(rec.Cur), d.Round(time.Minute)))
	}
}

// igExRelay finds another of our servers (same owner, never the panel host) whose own IP passes
// svc, and makes it a proxy of srv. It returns that route ("proxyN") and N when it was added now.
func (a *App) igExRelay(ctx context.Context, srv *Server, svc string) (string, int) {
	hub := gemHomeHost()
	var donors []*Server
	a.store.View(func(st *State) {
		for _, x := range st.Servers {
			if x.Igproxy && x.ID != srv.ID && x.Owner == srv.Owner && x.IPv4 != "" && x.IPv4 != srv.IPv4 && x.IPv4 != hub {
				donors = append(donors, x)
			}
		}
	})
	// the server's own country first, then Europe, then the rest
	rank := func(x *Server) int {
		switch {
		case strings.EqualFold(x.Country, srv.Country):
			return 0
		case igEurope[strings.ToUpper(x.Country)]:
			return 1
		}
		return 2
	}
	for i := 1; i < len(donors); i++ {
		for j := i; j > 0 && rank(donors[j]) < rank(donors[j-1]); j-- {
			donors[j], donors[j-1] = donors[j-1], donors[j]
		}
	}
	seen := map[string]bool{}
	tried := 0
	for _, d := range donors {
		if seen[d.IPv4] || tried >= igExRelayMax || ctx.Err() != nil {
			continue
		}
		seen[d.IPv4] = true
		m := a.igExRun(ctx, d, []string{svc}, gemRelayPort+1)
		if m == nil {
			continue
		}
		if v, _ := igExVerdict(svc, m[svc]); v != "ok" {
			continue
		}
		tried++
		inf := a.igInfo(ctx, srv)
		for n, r := range igRelays(inf) {
			if r[0] == d.IPv4 && r[1] == strconv.Itoa(gemRelayPort+1) {
				return "proxy" + strconv.Itoa(n), 0 // already one of its proxies
			}
		}
		line := fmt.Sprintf("socks5 %s %d - -\n", d.IPv4, gemRelayPort+1)
		rc, out := a.igRun(ctx, srv, []string{"proxy", "add", "-"}, line, 120, nil)
		a.igForget(srv.ID)
		mm := igExAddedRe.FindStringSubmatch(out)
		if rc != 0 || mm == nil {
			a.igAutoLog(srv, svc, "info", "could not add "+d.Name+"'s own IP as a relay: "+clipTo(agentLine(srv, out), 120))
			continue
		}
		n, _ := strconv.Atoi(mm[1])
		a.igAutoLog(srv, svc, "info", fmt.Sprintf("%s passes on %s's own IP: added it as proxy %d (relay)", igSvcName(svc), d.Name, n))
		return "proxy" + mm[1], n
	}
	return "", 0
}

// igExPatchInfo: the page's cached info follows a move at once.
func (a *App) igExPatchInfo(id, svc, route string, r *igExRead) {
	a.ig.mu.Lock()
	defer a.ig.mu.Unlock()
	e, ok := a.ig.m[id]
	if !ok || e.info == nil {
		return
	}
	m := make(map[string]string, len(e.info))
	for k, v := range e.info {
		m[k] = v
	}
	m[strings.ToLower(svc)] = route
	if svc == "GOOGLE" && r != nil && r.Dom != "" {
		m["gdom"] = r.Dom
	}
	a.ig.m[id] = igEntry{m, e.at}
}

// igExViewOf: the page's view of GOOGLE / YTM (auto-picked exit and why, the last reading).
type igExView struct {
	Mode  string `json:"mode"`           // auto | pin | off
	Want  string `json:"want,omitempty"` // the preferred exit
	Cur   string `json:"cur,omitempty"`  // the exit the panel picked while Want fails
	Why   string `json:"why,omitempty"`
	Next  int64  `json:"next,omitempty"` // when Want is tried again
	OK    string `json:"ok,omitempty"`   // the last reading: ok | bad
	Bad   string `json:"bad,omitempty"`  // why it read bad
	Where string `json:"where,omitempty"`
	At    int64  `json:"at,omitempty"`
}

func (a *App) igExViewOf(id string, recs map[string]*IgAutoSvc) map[string]igExView {
	out := map[string]igExView{}
	for _, k := range igExSvcs {
		rec := recs[k]
		v := igExView{Mode: "auto"}
		if rec != nil {
			switch {
			case rec.Off:
				v.Mode = "off"
			case rec.Pin != "":
				v.Mode = "pin"
			default:
				v.Want, v.Cur, v.Why, v.Next = rec.Want, rec.Cur, rec.Why, rec.Next
			}
		}
		igExMem.Lock()
		if l := igExMem.live[id][k]; l != nil && time.Since(l.At) < 25*time.Minute {
			v.OK, v.Bad, v.At = l.OK, l.Why, l.At.Unix()
			v.Where = igExWhere(k, &l.Read)
		}
		igExMem.Unlock()
		out[k] = v
	}
	return out
}
