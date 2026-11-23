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
// IP alone, which the users never get. Google's own country for the IP (the page's domain) is the
// signal both the page and the agent's gdom use - but it cannot tell "google.com because the IP
// is American" from "google.com because Google places it in Iran". The signed-out app can: it
// prints the place ("Tehran Province, Iran / From your IP address"). It had stopped printing it on
// 2026-11-14 and prints it again since 2026-11-17, so the reading asks the test browser too
// (igExPlace, at most every 30 min per server and after every move): a place decides - a country
// without Gemini fails, any other passes. No place is a verdict too, while the app is known to
// print places (one seen on some exit in the last 6 h): Google places that exit nowhere and refuses
// Gemini to accounts there - xe108's own IPv6 went from "Tehran Province, Iran" to no place at
// all, the keyless page still read google.com, and the ladder took Google back to it (2026-11-18).
// Only when no exit anywhere gets a place (2026-11-14..16) does the keyless reading stand alone. On warp6 the reading also asks
// whether IPv6 really passes through the WARPs: a WARP whose IPv6 is dead falls back to Cloudflare's
// shared IPv4, where the keyless page reads fine but signed-in users are refused.
// The same shared exit shows on IPv4 WARP ("warp") and on a warp6 that slips to it: Google places
// it in no country (google.com) although the server stands in Germany or Turkey. On a WARP route
// of a server outside the US that reading is a fail (Ger-hertzener 2026-11-15: Google on WARP read
// google.com, users signed in got no Gemini; its own IP read google.de and works).
//
// A reading that never comes (the users' route cannot be read) or never decides (Google answers
// without a country) is not "checking" for ever: it is shown as such, and three undecided
// readings in a row (30 min) count as a fail, so the ladder moves the service.
//
// Google Colab rides on Google's route (the agent's Google list has research.google.com and
// colab.* since 2026-11-15) and refuses many IPs Gemini accepts: Google answers 403 or 404 on
// colab.research.google.com there (usa, usa-kharej, xe107-germany's own IPs, 2026-11-15). The
// Google reading also fetches Colab and an exit where it is refused fails, so the ladder moves
// Google to one where both open. An older agent still sends Colab out of the server's own IP:
// Colab is not read there ("-"), it would say nothing about Google's exit.
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
	igExUnkTimes = 3 // undecided readings in a row that count as a fail
	igExNoRead   = 25 * time.Minute
	// igExFlapMax: Want failed again within igExHeld of a move back this many times in a row:
	// the exit that kept working becomes Want and the panel stops moving the users back and forth
	// (2026-11-16..18: nl, هلند1, فنلاند1, ترکیه and xe107 went back to WARP IPv6 or a proxy and
	// off it again within 1-3 h, every move a Gemini cut for the users)
	igExFlapMax = 3
)

// igExStrong: a reading good enough to move the users back onto the preferred exit. For Google
// that is a place from the test browser, or a country in Google's domain: a bare google.com
// with no place passed the backs of 11-18 (xe108, خارج اوتباند, xe107, xe101) and the same exits
// failed again within the hour.
func igExStrong(svc string, r *igExRead) bool {
	if svc != "GOOGLE" {
		return true
	}
	return r != nil && (r.Place != "" || igExDomCC(r.Dom) != "")
}

// igExStarted: readings live in memory; before this much time has passed since the start the
// card may still say "checking", after it a missing reading is shown as missing.
var igExStarted = time.Now()

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
	// Route: the service's route on the agent when it was read (users' route only); Home: the
	// server's own country (from the panel)
	Route string
	Home  string
	// Colab: Google Colab's http code on the same route ("" = not read: an agent whose Google
	// list does not carry Colab)
	Colab string
	// Place: where the signed-out Gemini app says Google places the users' exit ("Nuremberg,
	// Germany"; "" = the test browser gave no place). It decides when it is there.
	Place string
	// NoPlace: the app opened and named no place, while it does name one on other exits these
	// hours: Google serves no Gemini to accounts on this exit.
	NoPlace bool
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
		if r.Colab == "403" || r.Colab == "404" {
			return "bad", "Google Colab refuses the IP (" + r.Colab + ")"
		}
		if r.Flag == "region" {
			return "bad", "Gemini not offered there"
		}
		if r.Place != "" { // what a browser is told: the truth for signed-in users
			if gemPlaceBad(r.Place) {
				return "bad", "Google places the users in " + r.Place + ": no Gemini there"
			}
			return "ok", ""
		}
		if r.NoPlace {
			return "bad", "Google places the users nowhere on this exit: signed-in Gemini is refused"
		}
		d := strings.ToLower(r.Dom)
		cc := igExDomCC(d)
		if igExNoGemini[strings.ToLower(cc)] {
			return "bad", "Gemini not offered in " + cc
		}
		if strings.HasPrefix(code, "5") || d == "" || d == "-" {
			return "", "" // Google answered without its country: no verdict
		}
		if home := strings.ToUpper(strings.TrimSpace(r.Home)); cc == "" && igIsWarp(r.Route) && home != "" && home != "US" {
			return "bad", "Google places this WARP in no country (google." + d + "), not " + home + ": signed-in Gemini is refused"
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
  grep -qsi "not supported in your country\|isn.\{1,6\}t currently supported\|not available in your country\|not available in your region" "$f" && fl=region
  echo "X GOOGLE ${c:-000} ${d:--} $fl $(v6 GOOGLE) $(rt GOOGLE) $(cb)"; }
cb(){ local c i  # Colab: only where the agent sends it on Google's route
  grep -q 'domain:research[.]google[.]com' /usr/local/bin/igproxy 2>/dev/null || { echo -; return; }
  for i in 1 2; do
    c=$(curl -s -m 15 -A "$UA" $X -H 'Accept-Language: en-US,en;q=0.9' -o /dev/null -w '%%{http_code}' https://colab.research.google.com/ 2>/dev/null)
    [ "${c:-000}" != 000 ] && break; sleep 2
  done
  echo "${c:-000}"; }
y(){ local r c d fl=- i
  for i in 1 2; do
    r=$(curl -s -m 15 -A "$UA" $X -H 'Accept-Language: en-US,en;q=0.9' -o "$f" -w '%%{http_code} %%{redirect_url}' https://music.youtube.com/ 2>/dev/null); c=${r%%%% *}
    [ "${c:-000}" != 000 ] && break; sleep 2
  done
  case "${r#* }" in *unavailable-in-region*|*not-available*) fl=region;; esac
  grep -qsi "unavailable-in-region\|not available in your country\|isn.\{1,6\}t available in your country" "$f" && fl=region
  d=$(grep -oE '"GL":"[A-Z]{2}"' "$f" | head -1 | cut -d'"' -f4)
  echo "X YTM ${c:-000} ${d:--} $fl $(v6 YTM) $(rt YTM)"; }
`, port, port)
	if port == gemRelayPort {
		b.WriteString(igExV6Sh)
		b.WriteString("rt(){ local r; r=$(awk -F= -v s=\"$1\" '$1==s{v=$2} END{print v}' /etc/igproxy/routes 2>/dev/null); echo \"${r:--}\"; }\n")
	} else {
		b.WriteString("v6(){ echo -; }\nrt(){ echo -; }\n")
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
		if len(f) > 6 && f[6] != "-" {
			r.Route = f[6]
		}
		if len(f) > 7 && f[7] != "-" && f[7] != "000" {
			r.Colab = f[7]
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
	Unk  int // undecided readings in a row
	// a ladder that found no passing exit is not climbed again at once: every try moves the route
	// through all the exits, and most moves restart the server's router (its users are cut)
	FixFails int
	FixNext  time.Time
	// StrayNext: the next time a server found on its failing preferred exit may be put back on the
	// exit the panel had picked (igExStray); a restore that did not pass waits igExBackMin
	StrayNext time.Time
}

// igExStray: the record says the users are on Cur (picked by the panel because Want fails), but
// the server routes the service through Want. A try back that could not return, an agent update
// or a change on the server in the same minute leave it so; usa-kharej sat on WARP IPv6 on
// 2026-11-23 03:03 with proxy 7 (France, passing) in its record, and the ladder that ran from
// there found nothing and left it there.
func igExStray(rec *IgAutoSvc, route string) bool {
	return rec != nil && rec.Cur != "" && rec.Cur != rec.Want && route == rec.Want
}

// igExStrayMay: may the restore be tried now? It notes the try (the next one waits igExBackMin).
func igExStrayMay(id, svc string, now time.Time) bool {
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
	if now.Before(l.StrayNext) {
		return false
	}
	l.StrayNext = now.Add(igExBackMin)
	return true
}

// igExFixReset forgets the ladder's back-off: the route was changed by a person or by the server,
// so what failed before says nothing about the exits to try from here.
func igExFixReset(id, svc string) {
	igExMem.Lock()
	defer igExMem.Unlock()
	if l := igExMem.live[id][svc]; l != nil {
		l.FixFails, l.FixNext, l.StrayNext = 0, time.Time{}, time.Time{}
	}
}

// igExFixing: a bad reading that the panel is still dealing with by itself - the ladder has not
// been climbed yet, or its back-off is over. False = it found nothing: a person is needed.
func igExFixing(id, svc string, now time.Time) bool {
	igExMem.Lock()
	defer igExMem.Unlock()
	l := igExMem.live[id][svc]
	return l != nil && l.OK == "bad" && !now.Before(l.FixNext) && l.FixFails == 0
}

// igExFixWait: may the ladder be tried now? ok=false -> not before the returned time.
func igExFixWait(id, svc string, now time.Time) (bool, time.Time) {
	igExMem.Lock()
	defer igExMem.Unlock()
	if l := igExMem.live[id][svc]; l != nil && now.Before(l.FixNext) {
		return false, l.FixNext
	}
	return true, time.Time{}
}

// igExFixDone notes how a ladder try ended: found = an exit passed (the count starts anew);
// else the next try waits 30 min, 1 h, 2 h … 6 h.
func igExFixDone(id, svc string, found bool, now time.Time) {
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
	if found {
		l.FixFails, l.FixNext = 0, time.Time{}
		return
	}
	l.FixNext = now.Add(igExBackAfter(l.FixFails))
	l.FixFails++
}

var igExMem = struct {
	sync.Mutex
	live map[string]map[string]*igExLive
}{live: map[string]map[string]*igExLive{}}

func igExMark(id, svc string, r *igExRead, v, why string) int {
	n, _, _ := igExMarkV(id, svc, r, v, why)
	return n
}

// igExMarkV keeps one reading: v ok | bad | "" (undecided) | none (no reading at all). The
// igExUnkTimes-th undecided reading in a row becomes a fail; it returns the fails in a row and
// the verdict as kept.
func igExMarkV(id, svc string, r *igExRead, v, why string) (int, string, string) {
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
	switch v {
	case "":
		l.Unk++
		if l.Unk >= igExUnkTimes {
			v, why = "bad", "Google gives no clear answer on this exit (30 min)"
		}
	case "none":
	default:
		l.Unk = 0
	}
	l.OK, l.Why, l.At = v, why, time.Now()
	switch v {
	case "ok":
		l.Bad = 0
	case "bad":
		l.Bad++
	}
	return l.Bad, v, why
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
		a.store.View(func(st *State) { list = igDrivers(st.Servers) }) // one entry per machine (igtwin.go)
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
	for _, r := range m {
		r.Home = srv.Country
		if port != gemRelayPort {
			r.Route = ""
		}
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
		for _, k := range svcs {
			igExMark(srv.ID, k, nil, "none", "the users' route could not be read")
		}
		return false
	}
	again := false
	now := time.Now()
	for _, k := range svcs {
		route := inf[strings.ToLower(k)]
		rec := recs[k]
		if !igExIsAuto(rec) {
			if k == "GOOGLE" {
				a.igExPlace(ctx, srv, read[k], false) // a pinned exit is never moved, but the card says the truth
			}
			v, why := igExVerdict(k, read[k])
			igExMark(srv.ID, k, read[k], v, why)
			continue
		}
		// a route nobody here chose: followed
		if rec != nil && rec.Cur != "" && route != rec.Cur && route != rec.Want {
			a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Want, s.Cur, s.Why, s.Tries, s.Next = route, "", "", 0, 0 })
			a.igAutoLog(srv, k, "info", fmt.Sprintf("%s: route changed outside the panel to %s - followed", igSvcName(k), igRouteWord(route)))
			rec = nil
			igExFixReset(srv.ID, k)
		}
		if rec == nil || rec.Cur == "" {
			if rec == nil || rec.Want != route {
				a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Want = route })
				igExFixReset(srv.ID, k) // a new exit to start from: the old back-off does not apply
			}
		}
		r := read[k]
		if k == "GOOGLE" {
			a.igExPlace(ctx, srv, r, false)
		}
		v, why := igExVerdict(k, r)
		bad, v, why := igExMarkV(srv.ID, k, r, v, why)
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
			// left on the failing preferred exit although the panel had picked another: back on
			// that one first (one move), before any ladder and whatever the ladder's back-off says
			if igExStray(rec, route) && igExStrayMay(srv.ID, k, now) && a.igExRestore(ctx, srv, k, *rec, why) {
				continue
			}
			if ok, _ := igExFixWait(srv.ID, k, now); !ok {
				continue // the ladder found nothing a while ago: not climbed again yet
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
	if svc == "GOOGLE" {
		a.igExPlace(ctx, srv, m[svc], true) // the exit just changed: ask the browser now
	}
	v, _ := igExVerdict(svc, m[svc])
	return v, m[svc], nil
}

// ---- where Google places the users' exit (the test browser)

const igExPlaceEvery = 30 * time.Minute

// igExPlaceProbe opens the signed-out Gemini app through a socks proxy (a variable for the tests).
var igExPlaceProbe = gemProbe

type igExPlaceT struct {
	Place, Route string
	Refused      bool // the app's own refusal (its words, Google's 403 page)
	Silent       bool // the app opened, waited, and named no place
	At           time.Time
}

// igExPlaceTrust: "no place" counts as a refusal only while a place was seen on some exit this
// recently - the proof that the app prints places these hours.
const igExPlaceTrust = 6 * time.Hour

var igExPlaceMem = struct {
	sync.Mutex
	m    map[string]igExPlaceT
	seen time.Time  // the last time any exit got a place
	busy sync.Mutex // one probe at a time: one test browser
}{m: map[string]igExPlaceT{}}

// igExPlace adds to a Google reading of the users' route what the test browser is told there:
// r.Place, or Flag "region" when the app itself refuses. A reading is reused for igExPlaceEvery
// while the route is the same; fresh asks now. No answer (browser down, relay not reachable)
// changes nothing: the keyless reading stands.
func (a *App) igExPlace(ctx context.Context, srv *Server, r *igExRead, fresh bool) {
	if r == nil || srv.IPv4 == "" || r.Code == "" || r.Code == "000" {
		return
	}
	igExPlaceMem.Lock()
	c, ok := igExPlaceMem.m[srv.ID]
	igExPlaceMem.Unlock()
	if !ok || fresh || c.Route != r.Route || time.Since(c.At) > igExPlaceEvery {
		igExPlaceMem.busy.Lock()
		pctx, cancel := context.WithTimeout(ctx, 70*time.Second)
		v, p, err := igExPlaceProbe(pctx, fmt.Sprintf("socks5://%s:%d", srv.IPv4, gemRelayPort))
		cancel()
		igExPlaceMem.busy.Unlock()
		c = igExPlaceT{Route: r.Route, At: time.Now()}
		if err == nil {
			c.Place = gemPlace(p)
			c.Refused = c.Place == "" && v == "refused" && gemVerdict(p) == "refused"
			// the app itself, open, input box there, and no place after the probe's wait
			c.Silent = c.Place == "" && v == "refused" && !c.Refused && p.Input && strings.HasPrefix(p.URL, gemURL)
		}
		igExPlaceMem.Lock()
		igExPlaceMem.m[srv.ID] = c
		if c.Place != "" {
			igExPlaceMem.seen = c.At
		}
		igExPlaceMem.Unlock()
	}
	r.Place = c.Place
	if c.Refused && r.Flag == "" {
		r.Flag = "region"
	}
	if c.Silent {
		igExPlaceMem.Lock()
		r.NoPlace = !igExPlaceMem.seen.IsZero() && time.Since(igExPlaceMem.seen) < igExPlaceTrust
		igExPlaceMem.Unlock()
	}
}

func igExWhere(svc string, r *igExRead) string {
	if r == nil {
		return ""
	}
	if svc == "GOOGLE" {
		if r.Place != "" {
			return r.Place
		}
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
			adopted := false
			a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) {
				if s.Back > 0 && now.Sub(time.Unix(s.Back, 0)) > igExHeld {
					s.Tries, s.Flaps = 0, 0
				}
				s.Want = want
				if back {
					s.Cur, s.Why, s.Since, s.Next = "", "", 0, 0
					return
				}
				if igExFlap(rec, route, now) {
					s.Flaps++
					s.Tries++ // the next try back waits longer
				}
				if s.Flaps >= igExFlapMax {
					s.Want, s.Cur, s.Why, s.Since, s.Next, s.Tries, s.Flaps = keep, "", "", 0, 0, 0, 0
					adopted = true
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
			if adopted {
				a.igAutoLog(srv, svc, "info", fmt.Sprintf("%s: %s failed again soon after each move back (%d times): %s is kept as the exit, no more moves back", name, igRouteWord(route), igExFlapMax, word))
			}
			a.igExPatchInfo(srv.ID, svc, keep, r)
			a.push(fmt.Sprintf("🔀 %s: %s %s → %s%s (auto)", igLabel(srv), name, igRouteWord(route)+" failed ("+why+")", word, where))
			igExFixDone(srv.ID, svc, true, time.Now())
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
	igExFixDone(srv.ID, svc, false, time.Now())
	if cur := a.igInfo(ctx, srv)[strings.ToLower(svc)]; cur != route {
		_ = a.igSvcRoute(ctx, srv, map[string]string{svc: route})
	}
	a.igAutoLog(srv, svc, "fail", fmt.Sprintf("%s on %s: %s; nothing else passed: %s", name, igRouteWord(route), why, strings.Join(tried, ", ")))
	if rec == nil || time.Since(time.Unix(rec.Alert, 0)) > igAutoAlertGap {
		a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) { s.Alert = time.Now().Unix() })
		a.push(fmt.Sprintf("🔀⚠️ %s: %s fails on %s (%s) and no other exit passes — add an outbound on the IG Routing page.", igLabel(srv), name, igRouteWord(route), why))
	}
}

// igExRestore puts a stray service (igExStray) back on the exit the panel had picked; true = it
// passes there again.
func (a *App) igExRestore(ctx context.Context, srv *Server, svc string, rec IgAutoSvc, why string) bool {
	v, r, err := a.igExSet(ctx, srv, svc, rec.Cur)
	if err != nil || v != "ok" {
		return false
	}
	igExMark(srv.ID, svc, r, "ok", "")
	a.igExPatchInfo(srv.ID, svc, rec.Cur, r)
	where := igExWhere(svc, r)
	if where != "" {
		where = ", " + where
	}
	a.igAutoLog(srv, svc, "fix", fmt.Sprintf("%s was left on %s (%s) - back on %s%s", igSvcName(svc), igRouteWord(rec.Want), why, igRouteWord(rec.Cur), where))
	igExFixDone(srv.ID, svc, true, time.Now())
	return true
}

// igExFlap: the preferred exit fails within igExHeld of the last move back onto it.
func igExFlap(rec *IgAutoSvc, route string, now time.Time) bool {
	return rec != nil && rec.Cur == "" && rec.Back > 0 && route == rec.Want && now.Sub(time.Unix(rec.Back, 0)) <= igExHeld
}

// igExBack tries the preferred exit again; it is kept only when it passes twice, with a country.
func (a *App) igExBack(ctx context.Context, srv *Server, svc string, rec IgAutoSvc) {
	name := igSvcName(svc)
	v, r, err := a.igExSet(ctx, srv, svc, rec.Want)
	weak := err == nil && v == "ok" && !igExStrong(svc, r)
	if weak {
		v = ""
	}
	if err == nil && v == "ok" {
		time.Sleep(20 * time.Second)
		m := a.igExRun(ctx, srv, []string{svc}, gemRelayPort)
		if m != nil {
			if svc == "GOOGLE" {
				a.igExPlace(ctx, srv, m[svc], false) // asked a moment ago, in igExSet
			}
			v, _ = igExVerdict(svc, m[svc])
			r = m[svc]
			if v == "ok" && !igExStrong(svc, r) {
				v, weak = "", true
			}
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
	if e := a.igSvcRoute(ctx, srv, map[string]string{svc: rec.Cur}); e != nil { // must not stay on the failing exit
		time.Sleep(igExSettle)
		if e = a.igSvcRoute(ctx, srv, map[string]string{svc: rec.Cur}); e != nil {
			a.igAutoLog(srv, svc, "info", fmt.Sprintf("%s: could not go back to %s after the try on %s (%s) - the next check puts it back", name, igRouteWord(rec.Cur), igRouteWord(rec.Want), clipTo(e.Error(), 80)))
		}
	}
	d := igExBackAfter(rec.Tries + 1)
	a.igAutoPut(srv.ID, svc, func(s *IgAutoSvc) { s.Tries++; s.Next = time.Now().Add(d).Unix() })
	if rec.Tries == 0 || rec.Tries%4 == 3 {
		w := "no reading"
		if err != nil {
			w = clipTo(err.Error(), 80)
		} else if weak {
			w = "Google names no country there (" + igExWhere(svc, r) + ")"
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
	Since int64  `json:"since,omitempty"` // when the panel moved it to Cur
	Next  int64  `json:"next,omitempty"`  // when Want is tried again
	OK    string `json:"ok,omitempty"`    // the last reading: ok | bad
	Bad   string `json:"bad,omitempty"`  // why it read bad
	Where string `json:"where,omitempty"`
	At    int64  `json:"at,omitempty"`
	// Fixing: it reads bad and the panel is still trying the other exits by itself (nothing to do
	// for a person yet); false on a bad reading = no exit passed
	Fixing bool `json:"fixing,omitempty"`
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
				v.Want, v.Cur, v.Why, v.Since, v.Next = rec.Want, rec.Cur, rec.Why, rec.Since, rec.Next
			}
		}
		igExMem.Lock()
		if l := igExMem.live[id][k]; l != nil && time.Since(l.At) < igExNoRead {
			v.OK, v.Bad, v.At = l.OK, l.Why, l.At.Unix()
			v.Where = igExWhere(k, &l.Read)
			if v.OK == "" {
				v.Bad = "Google answered without saying where it places this exit"
			}
		} else if v.Mode != "off" && time.Since(igExStarted) >= igExNoRead {
			v.OK, v.Bad = "none", "not read for 25 min"
			if l != nil {
				v.At = l.At.Unix()
			}
		}
		igExMem.Unlock()
		v.Fixing = v.Mode == "auto" && v.OK == "bad" && igExFixing(id, k, time.Now())
		out[k] = v
	}
	return out
}
