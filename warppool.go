package main

// IG Routing · WARP pool: the panel keeps each server's WARP accounts at what the server needs,
// by itself. Nobody adds or removes a WARP by hand any more (it is still possible, in the ⋯ menu).
//
// What a server needs follows from its routes and its own load:
//   - nothing on WARP (and Instagram not waiting to go back to it) → no account;
//   - Instagram (or another non-Google service) on WARP → the WARPs that carry it + 1 spare. On
//     warp6 every account leaves from its own IPv6, so one carries Instagram (the agent's pool keeps
//     one exit IP); on warp (IPv4, BALANCE) they share Cloudflare's exit, and the 24 h peak of user
//     connections decides: one WARP per 2500 connections / 5 min (measured on 9 servers);
//   - Google on WARP → its own WARPs (the agent's gwarps, 2) on top.
//
// The panel does not register accounts itself: it sets the agent's "minwarps" to that number and
// turns the agent's own load sizing off (warpauto). The agent makes missing accounts within ~2 min,
// at most 3 per round, waits 30 min after a failed round, and stops for 6 h when two new accounts
// in a row read a no-music country (igcc_stop) - so Cloudflare is never flooded and a server
// whose WARPs all read IR does not loop: Instagram stays on a proxy (igauto.go moves it) and the
// page says so.
//
// The panel tests the standbys (accounts out of the pool because their exit differs) on their own
// with a temporary Xray, like the agent's warp_try - connectivity, exit, Instagram's country (= the
// music signal without a test account) - and removes what is not needed: dead accounts, accounts
// whose exit reads a no-music country, and accounts beyond the need. Removing restarts the router
// for a few seconds (the agent rebuilds its config), so a surplus is removed only at night (03-06
// server time), all in one restart; when good accounts are missing, broken ones go at once so the
// agent can make new ones. Google's own WARPs, the WARPs carrying users and accounts younger than
// 2 h are never removed. A hand add / delete holds the trims for 24 h; "Manage by hand" stops the
// pool for that server.
//
// Routes are never changed here: the hub's users' Google never leaving through 152.53.86.103
// (gemhome.go), the Google test account at home, and the NOTRACK rules stay as they are.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	wpTick      = 2 * time.Minute
	wpEvery     = 15 * time.Minute // each server is looked at this often (sooner after a route change)
	wpTestEvery = 6 * time.Hour    // a standby is tested again after this
	wpTestMax   = 3                // standbys tested per round (each ~5-15 s, one at a time on the server)
	wpTrimGap   = 6 * time.Hour    // the router is restarted for a trim at most this often
	wpHoldHand  = 24 * time.Hour   // a hand add / delete: no trim, no size change for this long
	wpYoung     = 2 * time.Hour    // an account this new is never removed
	wpConnPer   = 2500             // user connections / 5 min one WARP keeps its speed with
	wpCarryMax  = 8
	wpNightFrom = 3 // server hour: surplus accounts are removed from …
	wpNightTo   = 6 // … to
)

// WarpPool is the automatic WARP pool of one server (State.WarpPool).
type WarpPool struct {
	Off    bool   `json:"off,omitempty"`    // the person manages this server's WARPs by hand
	Hold   int64  `json:"hold,omitempty"`   // a hand add / delete: no trims or size changes before this
	Used   bool   `json:"used"`             // a service is on WARP (or Instagram waits to go back to it)
	Need   int    `json:"need"`             // accounts the server needs (carry + spare + Google's own)
	Carry  int    `json:"carry"`            // carrying Instagram / the other services
	Spare  int    `json:"spare"`            //
	G      int    `json:"g"`                // Google's own
	Have   int    `json:"have"`             // accounts on the server
	Good   int    `json:"good"`             // working ones (in use, or a standby that passed its test)
	Bad    int    `json:"bad"`              // broken / no-music ones waiting to be removed
	Extra  int    `json:"extra"`            // good ones beyond the need, removed at night
	Untest int    `json:"untest,omitempty"` // standbys not tested yet
	NoExit string `json:"noExit,omitempty"` // WARP gives only this no-music country here: Instagram stays on a proxy
	Note   string `json:"note,omitempty"`   // what the panel does now
	Short  bool   `json:"short,omitempty"`  // fewer good accounts than needed: the agent makes new ones
	Wait   int    `json:"wait,omitempty"`   // seconds until the agent's next sign-up (NoExit: its 6 h pause)
	Trim   int64  `json:"trim,omitempty"`   // last trim
	At     int64  `json:"at,omitempty"`     // last look
}

var wpMem = struct {
	sync.Mutex
	kick map[string]bool
	busy map[string]bool
}{kick: map[string]bool{}, busy: map[string]bool{}}

// wpKick: look at this server at the next tick (a route moved to / away from WARP)
func (a *App) wpKick(id string) {
	wpMem.Lock()
	wpMem.kick[id] = true
	wpMem.Unlock()
}

func (a *App) wpGet(id string) WarpPool {
	var p WarpPool
	a.store.View(func(st *State) {
		if x := st.WarpPool[id]; x != nil {
			p = *x
		}
	})
	return p
}

func (a *App) wpPut(id string, fn func(p *WarpPool)) {
	_ = a.store.Update(func(st *State) error {
		if st.WarpPool == nil {
			st.WarpPool = map[string]*WarpPool{}
		}
		if st.WarpPool[id] == nil {
			st.WarpPool[id] = &WarpPool{}
		}
		fn(st.WarpPool[id])
		return nil
	})
}

// wpHold: a person added or removed a WARP by hand: leave the pool's size alone for a day
func (a *App) wpHold(id string) {
	a.wpPut(id, func(p *WarpPool) { p.Hold = time.Now().Add(wpHoldHand).Unix() })
}

// ---- what a server needs

// wpNeed: carry + spare WARPs for Instagram and the other non-Google services, and Google's own.
// igWant is the route Instagram waits to go back to (igauto's Want while it sits on another exit).
func wpNeed(inf map[string]string, igWant string) (carry, spare, g int, used bool) {
	igOn := igIsWarp(inf["ig"]) || igIsWarp(igWant)
	other := false
	for _, k := range igServices {
		k = strings.ToLower(k)
		if k != "ig" && k != "google" && igIsWarp(inf[k]) {
			other = true
		}
	}
	gOn := igIsWarp(inf["google"])
	if !igOn && !other && !gOn {
		return 0, 0, 0, false
	}
	if gOn {
		g = 2 // the agent's gwarps default
		if n := len(igGwList(inf["gw"])); n > 0 && igAtoi(inf["warps"], 0) > n+1 {
			g = n // a server with its own gwarps setting (with n+1 accounts or fewer the agent cuts the set)
		}
	}
	if !igOn && !other {
		return 1, 0, g, true // only Google: the agent keeps at least one other account beside Google's
	}
	carry = 1
	if inf["ig"] == "warp" && inf["mode"] == "BALANCE" {
		// IPv4: the pool shares one exit IP, so more WARPs carry more connections
		peak := igAtoi(inf["wpeak"], 0)
		carry = int(math.Ceil(float64(peak) / wpConnPer))
		carry = max(1, min(carry, wpCarryMax))
	}
	return carry, 1, g, true
}

func igGwList(s string) []int {
	var out []int
	for _, x := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// ---- the plan for one server

// wpRank scores one account: 100 carries users, 60 works (failover spare), 50 a standby that
// passed its test, 20 not tested yet, 15 the agent gives it a new account now, 10 being repaired,
// below that broken (removed when good ones are missing, or at night).
func wpRank(w IgWarp, d IgWarps, bal, igOn bool, now int64) int {
	fresh := w.TestAt > 0 && now-w.TestAt < int64(wpTestEvery/time.Second)
	s := 0
	switch w.State {
	case "ok":
		if bal || d.Active == w.N || d.Active == 0 {
			s = 100
		} else {
			s = 60
		}
	case "out":
		switch w.Why {
		case "ip":
			switch {
			case !fresh:
				s = 20
			case w.Test == "ok":
				s = 50
			case w.Test == "no":
				s = 5
			default:
				s = 2
			}
		case "ipnew":
			s = 15
		case "music":
			s = 5
		default:
			s = 3
		}
	case "repair":
		s = 10
	default:
		s = 3
	}
	if w.Old && s < 100 {
		s -= 1 // an account from before auto keys: the first to go among equals
	}
	if !igOn && s == 5 && w.Why != "music" {
		s = 50 // a no-music country only matters while Instagram is on WARP
	}
	return s
}

type wpPlanT struct {
	Test   []IgWarp // standbys to test now
	Bad    []IgWarp // broken / no-music: removed when good ones are missing (or at night)
	Extra  []IgWarp // good ones beyond the need: removed at night
	Good   int
	Untest int
}

// wpPlan sorts a server's accounts into keep / test / remove. keepN = the non-Google need.
func wpPlan(d IgWarps, gw []int, keepN int, bal, igOn bool, now int64) wpPlanT {
	var p wpPlanT
	isG := map[int]bool{}
	for _, n := range gw {
		isG[n] = true
	}
	type c struct {
		w IgWarp
		s int
	}
	var cs []c
	for _, w := range d.Warps {
		if isG[w.N] {
			continue
		}
		cs = append(cs, c{w, wpRank(w, d, bal, igOn, now)})
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].s != cs[j].s {
			return cs[i].s > cs[j].s
		}
		return cs[i].w.N < cs[j].w.N
	})
	kept := 0
	for _, x := range cs {
		young := x.w.Age > 0 && time.Duration(x.w.Age)*time.Second < wpYoung
		switch {
		case x.s >= 50:
			p.Good++
			if x.s >= 100 || kept < keepN {
				kept++
			} else if !young {
				p.Extra = append(p.Extra, x.w)
			}
		case x.s == 20:
			p.Untest++
			if len(p.Test) < wpTestMax {
				p.Test = append(p.Test, x.w)
			}
			kept++ // not judged before its test
		case x.s >= 10:
			kept++ // the agent works on it
		default:
			if !young {
				p.Bad = append(p.Bad, x.w)
			}
		}
	}
	return p
}

// ---- the loop

func (a *App) wpLoop() {
	next := map[string]time.Time{}
	time.Sleep(4 * time.Minute) // after a restart: igauto and the page read the servers first
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
			wpMem.Lock()
			k := wpMem.kick[srv.ID]
			delete(wpMem.kick, srv.ID)
			wpMem.Unlock()
			if t, ok := next[srv.ID]; ok && now.Before(t) && !k {
				continue
			}
			next[srv.ID] = now.Add(wpEvery + time.Duration(i%7)*11*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			a.wpCheck(ctx, srv)
			cancel()
		}
		time.Sleep(wpTick)
	}
}

func wpIsNight(h int) bool { return h >= wpNightFrom && h < wpNightTo }

// wpCheck looks at one server's WARPs and sizes them.
func (a *App) wpCheck(ctx context.Context, srv *Server) {
	wpMem.Lock()
	if wpMem.busy[srv.ID] {
		wpMem.Unlock()
		return
	}
	wpMem.busy[srv.ID] = true
	wpMem.Unlock()
	defer func() { wpMem.Lock(); delete(wpMem.busy, srv.ID); wpMem.Unlock() }()

	pool := a.wpGet(srv.ID)
	if pool.Off {
		return
	}
	inf := a.igInfo(ctx, srv)
	switch inf["state"] {
	case "OFFLINE", "NOAGENT", "SUDO", "PAUSED", "DOWN", "CHECKING", "":
		return
	}
	if inf["ig"] == "" {
		return
	}
	ig := a.igAutoGet(srv.ID)
	igWant := ""
	if ig.Cur != "" && !ig.Off {
		igWant = ig.Want // Instagram sits on another exit and goes back to Want
	}
	carry, spare, g, used := wpNeed(inf, igWant)
	d, err := a.igWarps(ctx, srv)
	if err != nil {
		return
	}
	now := time.Now()
	igOn := igIsWarp(inf["ig"]) || igIsWarp(igWant)
	bal := inf["mode"] == "BALANCE"
	gw := igGwList(inf["gw"])
	hold := pool.Hold > now.Unix()

	plan := wpPlan(d, gw, carry+spare, bal, igOn, now.Unix())
	// test the standbys nobody has looked at (their result stays on the server, in /run/igproxy)
	if len(plan.Test) > 0 && used {
		if res := a.wpTest(ctx, srv, plan.Test); len(res) > 0 {
			for i := range d.Warps {
				if r, ok := res[d.Warps[i].N]; ok {
					d.Warps[i].setTest(r)
				}
			}
			plan = wpPlan(d, gw, carry+spare, bal, igOn, now.Unix())
		}
	}

	gOK := 0
	for _, w := range d.Warps {
		for _, n := range gw {
			if w.N == n && w.State == "ok" {
				gOK++
			}
		}
	}
	np := WarpPool{Off: pool.Off, Hold: pool.Hold, Trim: pool.Trim, Used: used, Carry: carry, Spare: spare, G: g,
		Need: carry + spare + g, Have: len(d.Warps), Good: plan.Good + gOK, Bad: len(plan.Bad), Untest: plan.Untest, At: now.Unix()}
	if !used {
		np.Need, np.Good = 0, 0
		for _, w := range d.Warps {
			if w.State == "ok" {
				np.Good++
			}
		}
	}
	// WARP gives only a no-music country here (the agent stopped making accounts): say so, add nothing
	if igOn && d.CCStop > 0 && plan.Good == 0 {
		np.NoExit = orStr(d.RejCC, "IR")
	}
	if !igOn && used {
		np.NoExit = ""
	}

	// 1. the size: the agent makes the missing accounts itself (rate-limited), never more
	minw := 0
	if used {
		minw = carry + spare
	}
	var notes []string
	if !hold {
		if inf["minw"] != strconv.Itoa(minw) {
			if rc, out := a.igRun(ctx, srv, []string{"set", "minwarps", strconv.Itoa(minw)}, "", 60, nil); rc == 0 {
				a.igAutoLog(srv, "WARP", "info", fmt.Sprintf("WARP accounts kept: %s → %d%s", orDash(inf["minw"]), minw, wpWhy(carry, spare, g, used, inf)))
				a.igForget(srv.ID)
			} else {
				a.igAutoLog(srv, "WARP", "fail", "could not set the WARP count: "+clipTo(strings.TrimSpace(out), 120))
			}
		}
		if inf["wauto"] == "ON" {
			_, _ = a.igRun(ctx, srv, []string{"set", "warpauto", "off"}, "", 60, nil) // the panel sizes the pool now
		}
	}

	// 2. what goes: broken ones at once when good ones are missing (so the agent can make new ones),
	// the rest - and every surplus - at night, all in one router restart
	good := plan.Good
	short := used && good < carry+spare
	var trim []IgWarp
	night := wpIsNight(d.Hour)
	switch {
	case hold:
	case !used:
		if night {
			for _, w := range d.Warps {
				if !(w.Age > 0 && time.Duration(w.Age)*time.Second < wpYoung) {
					trim = append(trim, w)
				}
			}
		}
	case short && np.NoExit == "":
		trim = plan.Bad
	case night:
		trim = append(append(trim, plan.Bad...), plan.Extra...)
	}
	np.Extra = len(plan.Extra)
	if !used {
		np.Extra = len(d.Warps)
	}
	if len(trim) > 0 && now.Sub(time.Unix(pool.Trim, 0)) < wpTrimGap {
		trim = nil
	}
	if len(trim) > 0 {
		if ok, said := a.wpTrim(ctx, srv, trim); ok {
			np.Trim = now.Unix()
			np.Have -= len(trim)
			a.igAutoLog(srv, "WARP", "fix", fmt.Sprintf("removed %d WARP account%s (%s) - %d left", len(trim), plural(int64(len(trim))), wpWhyTrim(trim, used, short), np.Have))
			a.igForget(srv.ID)
			switch {
			case !used || !short:
				np.Bad, np.Extra = 0, 0
			default:
				np.Bad = 0 // only the broken ones went: the surplus waits for the night
			}
		} else if said != "" {
			a.igAutoLog(srv, "WARP", "fail", "removing WARP accounts failed: "+clipTo(said, 160))
		}
	}

	np.Short = short && np.Have < np.Need
	np.Wait = d.FNext
	if np.NoExit != "" {
		np.Wait = d.CCStop
	}
	// 3. the line the page shows (in English for the log and the AI; the page builds its own)
	switch {
	case hold:
		notes = append(notes, "changed by hand - the panel leaves the count alone until "+time.Unix(pool.Hold, 0).Format("Jan 2 15:04"))
	case !used && np.Have > 0:
		notes = append(notes, "no service on WARP - the accounts are removed tonight")
	case np.NoExit != "":
		notes = append(notes, fmt.Sprintf("every new WARP reads %s (no music) here - Instagram stays on its other exit, WARP is tried again in %s", np.NoExit, wpDur(d.CCStop)))
	case short && np.Have < np.Need:
		if d.FNext > 0 {
			notes = append(notes, "making new accounts - next try in "+wpDur(d.FNext))
		} else {
			notes = append(notes, "making new accounts")
		}
	case plan.Untest > 0:
		notes = append(notes, "testing the standbys")
	}
	if !hold && used && np.Extra+np.Bad > 0 && len(trim) == 0 {
		notes = append(notes, fmt.Sprintf("%d not needed - removed tonight (03-06, the router restarts for a few seconds)", np.Extra+np.Bad))
	}
	np.Note = strings.Join(notes, " · ")
	a.wpPut(srv.ID, func(p *WarpPool) {
		off, hd := p.Off, p.Hold
		*p = np
		p.Off, p.Hold = off, hd
	})
}

func wpWhy(carry, spare, g int, used bool, inf map[string]string) string {
	if !used {
		return " (no service on WARP)"
	}
	var b []string
	if carry > 0 {
		w := "for Instagram"
		if !igIsWarp(inf["ig"]) {
			w = "for the services on WARP"
		}
		if inf["ig"] == "warp" && inf["mode"] == "BALANCE" {
			w += fmt.Sprintf(", 24 h peak %s connections / 5 min", orDash(inf["wpeak"]))
		}
		b = append(b, fmt.Sprintf("%d %s", carry, w))
	}
	if spare > 0 {
		b = append(b, fmt.Sprintf("%d spare", spare))
	}
	if g > 0 {
		b = append(b, fmt.Sprintf("+ %d of Google's own", g))
	}
	return " (" + strings.Join(b, ", ") + ")"
}

func wpWhyTrim(ws []IgWarp, used, short bool) string {
	if !used {
		return "no service on WARP"
	}
	bad, no, extra := 0, 0, 0
	for _, w := range ws {
		switch {
		case w.Test == "no" || w.Why == "music":
			no++
		case w.State == "ok" || w.Test == "ok":
			extra++
		default:
			bad++
		}
	}
	var b []string
	if no > 0 {
		b = append(b, fmt.Sprintf("%d in a no-music country", no))
	}
	if bad > 0 {
		b = append(b, fmt.Sprintf("%d not working", bad))
	}
	if extra > 0 {
		b = append(b, fmt.Sprintf("%d not needed", extra))
	}
	return strings.Join(b, ", ")
}

func wpDur(sec int) string {
	switch {
	case sec <= 0:
		return "a moment"
	case sec < 5400:
		return fmt.Sprintf("%d min", (sec+59)/60)
	default:
		return fmt.Sprintf("%d h", (sec+1799)/3600)
	}
}

// ---- on the server

// setTest reads "<ok|no|down> <ip> <cc> <loc> <epoch>" (wtest_<id>, written by wpTestScript)
func (w *IgWarp) setTest(s string) {
	f := strings.Fields(s)
	if len(f) < 5 {
		return
	}
	dash := func(x string) string {
		if x == "-" || x == "?" {
			return ""
		}
		return x
	}
	w.Test, w.TestIP, w.TestCC, w.TestLoc = f[0], dash(f[1]), dash(f[2]), dash(f[3])
	w.TestAt, _ = strconv.ParseInt(f[4], 10, 64)
}

// wpTestScript tests standbys one by one with a temporary Xray on the agent's test port (12399,
// under the agent's own lock, so it never runs beside the agent's warp_try): the account as the
// router would use it (warp6 = its own IPv6, warp-via = through the forward), the exit Cloudflare
// sees, and the country Instagram places it in. The key stays in a 0600 file and is removed.
// TESTS = "n:id …"; prints "T n <ok|no|down> <ip> <cc> <loc> <epoch>".
const wpTestScript = `#wptest
D=${WPD:-/etc/igproxy} R=${WPR:-/run/igproxy} B=/usr/local/bin/igproxy X=${WPD:-/etc/igproxy}/xray
P=$(grep -m1 '^WARP_PUB=' "$B" | cut -d'"' -f2); M=$(grep -m1 -oE '^SOMARK=[0-9]+' "$B" | cut -d= -f2)
NM=$(grep -m1 '^IG_NOMUSIC=' "$B" | cut -d'"' -f2); [ -n "$NM" ] || NM="IR CN KP SY CU"
[ -x "$X" ] && [ -n "$P" ] && [ -s "$D/warps" ] || { echo "T none"; exit 0; }
r=$(awk -F= '$1=="IG"{v=$2} END{print v}' "$D/routes" 2>/dev/null); igw=0; case "$r" in warp|warp6) igw=1;; esac
via=($(tr -s ' \n' '\n\n' 2>/dev/null < "$D/warp_via" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$'))
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
exec 7>"$R/warp_try.lock"
for t in $TESTS; do
  n=${t%%:*}; want=${t#*:}
  read -r k a e id < <(sed -n "${n}p" "$D/warps")
  [ -n "$k" ] && [ "$(tr -cd 'A-Za-z0-9' <<<"$id")" = "$want" ] || { echo "T $n gone"; continue; }
  [ ${#via[@]} -gt 0 ] && [ ! -e "$D/kwg" ] && e=${via[$(( (n - 1) % ${#via[@]} ))]}
  a6=""; [ "$r" = warp6 ] && [ "$id" != none ] && a6=$(grep '^Address' "$D/warp-acc/$id/wgcf-profile.conf" 2>/dev/null | grep -oE '[0-9a-fA-F]*:[0-9a-fA-F:]+/[0-9]+' | head -1)
  adr="\"$a\""; aip='"0.0.0.0/0"'; ds=ForceIPv4; [ -n "$a6" ] && { adr="$adr,\"$a6\""; aip="$aip,\"::/0\""; ds=ForceIPv6v4; }
  flock -w 120 7 || { echo "T $n busy"; continue; }
  c=$(umask 077; mktemp --suffix=.json)
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":12399,"protocol":"socks","settings":{"udp":false}}],"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"%s","address":[%s],"peers":[{"publicKey":"%s","endpoint":"%s","keepAlive":25,"allowedIPs":[%s]}],"mtu":1280,"noKernelTun":true,"domainStrategy":"%s"},"streamSettings":{"sockopt":{"mark":%s}}}]}' \
    "$k" "$adr" "$P" "$e" "$aip" "$ds" "${M:-255}" > "$c"
  "$X" run -c "$c" >/dev/null 2>&1 & pid=$!
  sleep 3; res=down ip=- loc=- cc=-
  if kill -0 $pid 2>/dev/null; then
    for j in 1 2; do tr=$(curl -s -m 8 -x socks5h://127.0.0.1:12399 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null); grep -qE '^warp=(on|plus)' <<<"$tr" && break; tr=""; done
    if [ -n "$tr" ]; then
      res=ok; ip=$(sed -n 's/^ip=//p' <<<"$tr"); loc=$(sed -n 's/^loc=//p' <<<"$tr")
      if [ $igw = 1 ]; then
        for j in 1 2; do cc=$(curl -s -m 15 -L --compressed -A "$UA" -H 'Accept-Language: en-US' -x socks5h://127.0.0.1:12399 https://www.instagram.com/accounts/login/ 2>/dev/null | grep -oE '"country_code":"[A-Z]{2}"' | head -1 | cut -d'"' -f4); [ -n "$cc" ] && break; done
        [ -n "$cc" ] || cc=-
        [[ " $NM " == *" $cc "* ]] && res=no
      fi
    fi
  fi
  kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -f "$c"; flock -u 7
  tk=$id; [ "$id" = none ] && tk=n$n
  echo "$res ${ip:--} ${cc:--} ${loc:--} $(date +%s)" > "$R/wtest_$tk"
  echo "T $n $res ${ip:--} ${cc:--} ${loc:--} $(date +%s)"
done
`

// wpTest runs wpTestScript for these standbys; result per WARP number.
func (a *App) wpTest(ctx context.Context, srv *Server, ws []IgWarp) map[int]string {
	h, err := a.igHost(ctx, srv)
	if err != nil {
		return nil
	}
	var b strings.Builder
	for _, w := range ws {
		fmt.Fprintf(&b, "%d:%s ", w.N, wpSafeID(w.ID))
	}
	out, _ := h.Run(ctx, "TESTS="+shq(strings.TrimSpace(b.String()))+"\n"+wpTestScript, nil)
	res := map[int]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) >= 7 && f[0] == "T" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				res[n] = strings.Join(f[2:], " ")
			}
		}
	}
	return res
}

func wpSafeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "none"
	}
	return b.String()
}

// wpTrimScript removes several WARP accounts in one go under the agent's own lock (no agent job
// writes the list meanwhile): each number must still hold the same account, the per-number state
// files of the ones that stay move with their new numbers, then ONE "igproxy apply" (the router
// restarts once, a few seconds). TRIM = "n:id …". Prints "X ok <before> <after>" or "X <why>".
const wpTrimScript = `#wptrim
D=${WPD:-/etc/igproxy} R=${WPR:-/run/igproxy} IGP=${WPIGP:-/usr/local/bin/igproxy}
[ -s "$D/warps" ] || { echo "X none"; exit 0; }
exec 6>"$R/slowlock"; flock -w 300 6 || { echo "X busy"; exit 0; }
N=$(grep -c . "$D/warps"); del=" "
for t in $TRIM; do n=${t%%:*}; want=${t#*:}
  id=$(sed -n "${n}p" "$D/warps" | awk '{print $4}')
  [ -n "$id" ] && [ "$(tr -cd 'A-Za-z0-9' <<<"$id")" = "$want" ] || { echo "X changed $n"; exit 0; }
  del="$del$n "
done
[ "$del" = " " ] && { echo "X none"; exit 0; }
cp -p "$D/warps" "$R/warps.before-trim"
declare -A map; j=0
for i in $(seq 1 "$N"); do if [[ "$del" == *" $i "* ]]; then map[$i]=0; else j=$((j+1)); map[$i]=$j; fi; done
ids=$(awk -v d="$del" 'index(d, " " NR " ") {print $4}' "$D/warps")
awk -v d="$del" 'index(d, " " NR " ") == 0' "$D/warps" > "$D/warps.tmp" && chmod 600 "$D/warps.tmp" && mv -f "$D/warps.tmp" "$D/warps" || { echo "X write"; exit 0; }
cd "$R" || exit 0
for f in wout wsel wfail wnew wmeas wqc wgem gleft gcc gdown kc_next kc_fail kwg_ep wipflip; do
  tmp=$(mktemp -d "$R/.trim.XXXX")
  for i in $(seq 1 "$N"); do
    [ -e "${f}_$i" ] || continue
    m=${map[$i]}; if [ "$m" != 0 ]; then mv -f "${f}_$i" "$tmp/${f}_$m"; else rm -f "${f}_$i"; fi
  done
  for x in "$tmp"/*; do [ -e "$x" ] && mv -f "$x" "$R/"; done; rmdir "$tmp"
done
for f in warp_active gwarp_active; do v=$(cat "$f" 2>/dev/null)
  [ -n "$v" ] || continue; m=${map[$v]:-0}; if [ "$m" != 0 ]; then echo "$m" > "$f"; else rm -f "$f"; fi
done
rm -f "$R"/wtest_n* "$R/last_sel"
for id in $ids; do [ -n "$id" ] && [ "$id" != none ] && [[ "$id" =~ ^[A-Za-z0-9]+$ ]] && { rm -rf "$D/warp-acc/$id"; rm -f "$R/wtest_$id"; }; done
IGPX_SLOW=1 timeout 170 "$IGP" apply >/dev/null 2>&1
echo "X ok $N $j $(systemctl is-active igproxy-xray)"
`

// wpTrim removes these accounts (one router restart). ok = done; said = why not.
func (a *App) wpTrim(ctx context.Context, srv *Server, ws []IgWarp) (bool, string) {
	h, err := a.igHost(ctx, srv)
	if err != nil {
		return false, err.Error()
	}
	var b strings.Builder
	for _, w := range ws {
		fmt.Fprintf(&b, "%d:%s ", w.N, wpSafeID(w.ID))
	}
	out, err := h.Run(ctx, "TRIM="+shq(strings.TrimSpace(b.String()))+"\n"+wpTrimScript, nil)
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "X ok") {
			return true, ""
		}
		if strings.HasPrefix(l, "X ") {
			if l == "X none" || strings.HasPrefix(l, "X changed") || l == "X busy" {
				return false, "" // the list changed meanwhile / the agent is busy: next round
			}
			return false, l
		}
	}
	if err != nil {
		return false, err.Error()
	}
	return false, "no answer"
}
