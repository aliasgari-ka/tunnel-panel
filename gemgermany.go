package main

// Each server's Google goes out in the server's own country: a customer who buys a US
// server wants Gemini's US features (Germany lacked some, e.g. video editing). Its own IP
// when Google places that in the country, else one of its WARPs that Google places there.
// Each choice must first pass the Gemini check in the test browser.

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gemGoogleDom: Google's OneGoogle domain for a country ("US" -> "com", "GB" -> "co.uk").
var gemGoogleDom = map[string]string{"us": "com", "gb": "co.uk", "uk": "co.uk", "jp": "co.jp", "kr": "co.kr", "in": "co.in",
	"za": "co.za", "nz": "co.nz", "au": "com.au", "br": "com.br", "tr": "com.tr", "hk": "com.hk", "sg": "com.sg"}

// gemWantDom: the Google country a server's users should get — the server's own country
// ("" when its country is unknown: then it is left alone).
func gemWantDom(srv *Server) string {
	cc := strings.ToLower(srv.Country)
	if d, ok := gemGoogleDom[cc]; ok {
		return d
	}
	return cc
}

// gemDomIs: Google's domain d is the country want stands for. Many countries' domain is
// "com.<cc>" or "co.<cc>" (com.cy, co.il, com.ua…), which the map above doesn't list: without
// this a server in such a country looked misplaced every round.
func gemDomIs(d, want string) bool {
	return d == want || (want != "" && !strings.Contains(want, ".") && (d == "com."+want || d == "co."+want))
}

var gemDomRe = regexp.MustCompile(`og[.]qtm[^"]*","([a-z.]{2,8})"`)

// gemDom: the Google country of a socks exit ("ip:port"), from the keyless Gemini page.
func gemDom(ctx context.Context, socks string) string {
	_, b, err := gemSocksGet(ctx, socks, gemURL, true)
	if err != nil {
		return ""
	}
	if m := gemDomRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

type gemDomAt struct {
	dom string
	at  time.Time
}

var gemOwnDom = struct {
	sync.Mutex
	m map[string]gemDomAt
}{m: map[string]gemDomAt{}}

// gemOwnDomOf: Google's country for the server's own IP (its relay port 12371), cached.
func gemOwnDomOf(ctx context.Context, srv *Server) string {
	gemOwnDom.Lock()
	c, ok := gemOwnDom.m[srv.ID]
	gemOwnDom.Unlock()
	if ok && time.Since(c.at) < gemServerEvery {
		return c.dom
	}
	d := gemDom(ctx, srv.IPv4+":12371")
	if d == "" {
		return d // a failed check is not kept for hours
	}
	gemOwnDom.Lock()
	gemOwnDom.m[srv.ID] = gemDomAt{d, time.Now()}
	gemOwnDom.Unlock()
	return d
}

func (a *App) igServerByIP(ip string) *Server {
	var r *Server
	a.store.View(func(s *State) {
		for _, x := range s.Servers {
			if x.Igproxy && x.IPv4 == ip {
				r = x
			}
		}
	})
	return r
}

// igRelays parses the agent's prelay= ("N:host:port,…": its socks proxies to our relays).
func igRelays(inf map[string]string) map[int][2]string {
	out := map[int][2]string{}
	for _, x := range strings.Split(inf["prelay"], ",") {
		f := strings.Split(x, ":")
		if n, err := strconv.Atoi(f[0]); err == nil && len(f) == 3 {
			out[n] = [2]string{f[1], f[2]}
		}
	}
	return out
}

// igProxyName: "proxy4 (internal: XE105 own IP)" for a proxy that is one of our servers.
func igProxyName(inf map[string]string, route string, byIP func(string) *Server) string {
	n, err := strconv.Atoi(strings.TrimPrefix(route, "proxy"))
	if !strings.HasPrefix(route, "proxy") || err != nil {
		return route
	}
	r, ok := igRelays(inf)[n]
	if !ok {
		return route
	}
	name := r[0]
	if s := byIP(r[0]); s != nil {
		name = s.Name
	}
	if r[1] == "12371" {
		return route + " (internal: " + name + " own IP)"
	}
	p, _ := strconv.Atoi(r[1])
	return fmt.Sprintf("%s (internal: %s WARP %d)", route, name, p-12371)
}

const (
	gemFixVisits = 6               // browser checks per gemFix at most (without the account)
	gemSettle    = 5 * time.Second // after a route change, before the users' route is checked
)

// gemNoBrowser starts gemFix's answer when the check could not run at all (gemLoop retries
// such a server next round instead of after gemServerEvery).
const gemNoBrowser = "the Google test browser did not answer"

var gemRouteRe = regexp.MustCompile(`^(proxy[0-9]*|warp6?|ipv6|direct)$`)

// gemFix moves a server's Google to an exit in its own country that the browser check
// passes: its own IP, else one of its WARPs (pinned as a WARP). Another server is never used:
// the internal relay proxies it once added broke Gemini and are no longer made.
func (a *App) gemFix(srv *Server, inf map[string]string) string {
	want := gemWantDom(srv)
	if want == "" {
		return "the server's country is unknown — set it on the Servers page"
	}
	if !gemRouteRe.MatchString(inf["google"]) { // nothing known to put it back to
		return "Google's current route is unknown (agent too old?) — not moved"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	type cand struct {
		port, what string
		warp       int // 0 = the server's own IP (route "direct"), else that WARP
	}
	var cands []cand
	if inf["google"] != "direct" && gemDomIs(gemOwnDomOf(ctx, srv), want) {
		cands = append(cands, cand{"12371", "its own IP", 0})
	}
	for n := 1; n <= 8; n++ {
		port := strconv.Itoa(12371 + n)
		if gemDomIs(gemDom(ctx, srv.IPv4+":"+port), want) {
			cands = append(cands, cand{port, fmt.Sprintf("its WARP %d", n), n})
		}
	}
	prev := inf["google"]
	signedIn, usersFail := 0, 0
	for _, c := range cands {
		if signedIn >= gemFixVisits {
			break
		}
		signedIn++
		pc, pcancel := context.WithTimeout(ctx, 2*time.Minute)
		v, _, perr := gemProbe(pc, "socks5://"+srv.IPv4+":"+c.port)
		pcancel()
		if perr != nil && v == "" {
			// the check never ran (test browser or its tunnel down): not a verdict on the exits
			return gemNoBrowser + ": " + clipTo(perr.Error(), 100)
		}
		if v == "signedout" {
			return "the Gemini test account is signed out — log in again (IG Routing → 🔑 Google test browser), then Google is moved on the next round"
		}
		if v != "ok" {
			continue
		}
		// a WARP is used as a WARP (Google's route on WARP, pinned to that one) — never as a
		// proxy to the relay: internal proxies are no longer made (Gemini broke on them)
		via := "direct"
		if c.warp > 0 {
			if via = prev; via != "warp" && via != "warp6" {
				via = "warp"
			}
		}
		if via != prev {
			if rc, out := a.igRun(ctx, srv, []string{"route", "GOOGLE", via}, "", 180, nil); rc != 0 {
				return "could not move Google to " + c.what + ": " + clipTo(agentLine(srv, out), 100)
			}
		}
		if c.warp > 0 {
			if rc, out := a.igRun(ctx, srv, []string{"google", "use", strconv.Itoa(c.warp)}, "", 120, nil); rc != 0 {
				log.Printf("gemini fix %s: pinning Google to %s: %s", srv.Name, c.what, agentLine(srv, out))
			}
		}
		a.igForget(srv.ID)
		// the exit passed in the test browser, but the users' route must reach it too: check the
		// users' relay a few times
		d := ""
		for i := 0; i < 3 && !gemDomIs(d, want); i++ {
			time.Sleep(gemSettle)
			d = gemDom(ctx, srv.IPv4+":"+strconv.Itoa(gemRelayPort))
		}
		if gemDomIs(d, want) {
			return "Google moved to " + c.what + " — ." + want + ", Gemini opens there"
		}
		usersFail++
		if c.warp > 0 && via == prev {
			// the route stayed, but Google is pinned to this WARP now: let the agent pick its
			// WARP again instead of leaving it on one the users' route doesn't get through
			bc, bcancel := context.WithTimeout(context.Background(), 2*time.Minute)
			if rc, out := a.igRun(bc, srv, []string{"google", "rotate"}, "", 110, nil); rc != 0 {
				log.Printf("gemini fix %s: unpinning Google from %s: %s", srv.Name, c.what, agentLine(srv, out))
			}
			bcancel()
			a.igForget(srv.ID)
		}
		if via != prev {
			// put it back, with a context of its own: the round's may be spent by now
			bc, bcancel := context.WithTimeout(context.Background(), 4*time.Minute)
			rc, out := a.igRun(bc, srv, []string{"route", "GOOGLE", prev}, "", 180, nil)
			bcancel()
			a.igForget(srv.ID)
			if rc != 0 {
				return fmt.Sprintf("moved Google to %s, but the users' route gets %q there, and putting it back to %s failed: %s — check it by hand", c.what, d, prev, clipTo(agentLine(srv, out), 100))
			}
		}
		log.Printf("gemini fix %s: %s works in the test browser, but the users' route gets %q there -> left on %s", srv.Name, c.what, d, prev)
	}
	if len(cands) == 0 {
		return "no exit that Google places in ." + want + " — move it by hand"
	}
	if usersFail > 0 {
		return fmt.Sprintf("%d exit(s) opened Gemini, but the users' route did not reach them — left on %s", usersFail, prev)
	}
	return fmt.Sprintf("no .%s exit opens Gemini (%d tried) — left as is", want, signedIn)
}
