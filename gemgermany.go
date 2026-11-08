package main

// Each server's Google goes out in the server's own country: a customer who buys a US
// server wants Gemini's US features (Germany lacked some, e.g. video editing). Its own IP
// when Google places that in the country, else one of its WARPs that Google places there,
// else the own IP of another of our servers in that country (through the agent's relay, an
// "internal" proxy). Each choice must first pass the signed-in Gemini check.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
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

var gemDomRe = regexp.MustCompile(`og[.]qtm[^"]*","([a-z.]{2,8})"`)

// gemDom: the Google country of a socks exit ("ip:port"), from the keyless Gemini page.
func gemDom(ctx context.Context, socks string) string {
	d, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return ""
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return ""
	}
	tr := &http.Transport{DialContext: cd.DialContext, TLSHandshakeTimeout: 15 * time.Second}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", gemURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
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
	gemFixVisits = 3               // signed-in checks per gemFix at most
	gemSettle    = 5 * time.Second // after a route change, before the users' route is checked
)

var gemRouteRe = regexp.MustCompile(`^(proxy[0-9]*|warp6?|ipv6|direct)$`)

// gemFix moves a server's Google to an exit in its own country that the signed-in check
// passes: its own IP, else one of its WARPs, else the own IP of another of our servers there
// (an internal relay proxy, added when missing; spread by id so each server keeps its choice).
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
		ip, port, what string
		own            bool // the server's own IP: route "direct"
	}
	var cands []cand
	if inf["google"] != "direct" && gemOwnDomOf(ctx, srv) == want {
		cands = append(cands, cand{srv.IPv4, "12371", "its own IP", true})
	}
	for n := 1; n <= 8; n++ {
		port := strconv.Itoa(12371 + n)
		if gemDom(ctx, srv.IPv4+":"+port) == want {
			cands = append(cands, cand{srv.IPv4, port, fmt.Sprintf("its WARP %d", n), false})
		}
	}
	var others []*Server
	a.store.View(func(s *State) {
		for _, x := range s.Servers {
			if x.Igproxy && x.Owner == "" && x.ID != srv.ID && x.IPv4 != "" && x.IPv4 != srv.IPv4 {
				others = append(others, x)
			}
		}
	})
	sort.Slice(others, func(i, j int) bool {
		hi, hj := sha1.Sum([]byte(srv.ID+others[i].ID)), sha1.Sum([]byte(srv.ID+others[j].ID))
		return bytes.Compare(hi[:], hj[:]) < 0
	})
	for _, x := range others {
		if gemOwnDomOf(ctx, x) == want {
			cands = append(cands, cand{x.IPv4, "12371", x.Name + " own IP", false})
		}
	}
	find := func(inf map[string]string, ip, port string) string {
		for n, r := range igRelays(inf) {
			if r[0] == ip && r[1] == port {
				return "proxy" + strconv.Itoa(n)
			}
		}
		return ""
	}
	prev := inf["google"]
	signedIn, usersFail := 0, 0
	for _, c := range cands {
		if signedIn >= gemFixVisits { // the test account is signed out when seen too often
			break
		}
		signedIn++
		pc, pcancel := context.WithTimeout(ctx, 2*time.Minute)
		v, _, _ := gemProbe(pc, "socks5://"+c.ip+":"+c.port)
		pcancel()
		if v == "signedout" {
			return "the Gemini test account is signed out — log in again (IG Routing → 🔑 Google test browser), then Google is moved on the next round"
		}
		if v != "ok" {
			continue
		}
		via, what, added := "direct", c.what, false
		if !c.own {
			if via = find(inf, c.ip, c.port); via == "" { // not in its list yet: add it (the agent tests it first)
				if rc, out := a.igRun(ctx, srv, []string{"proxy", "add", "-"}, "socks5 "+c.ip+" "+c.port+" - -", 120, nil); rc != 0 {
					log.Printf("gemini fix %s: adding %s: %s", srv.Name, c.what, agentLine(srv, out))
					continue
				}
				a.igForget(srv.ID)
				if via = find(a.igInfo(ctx, srv), c.ip, c.port); via == "" {
					continue
				}
				added = true
			}
			what = via + " (internal: " + c.what + ")"
		}
		if rc, out := a.igRun(ctx, srv, []string{"route", "GOOGLE", via}, "", 180, nil); rc != 0 {
			return "could not move Google to " + what + ": " + clipTo(agentLine(srv, out), 100)
		}
		a.igForget(srv.ID)
		// the exit passed in the test browser, but the users' route must reach it too (a server's
		// own WARP relayed through its own IP did not): check the users' relay a few times
		d := ""
		for i := 0; i < 3 && d != want; i++ {
			time.Sleep(gemSettle)
			d = gemDom(ctx, srv.IPv4+":"+strconv.Itoa(gemRelayPort))
		}
		if d == want {
			return "Google moved to " + what + " — ." + want + ", signed-in Gemini works there"
		}
		usersFail++
		// put it back, with a context of its own: the round's may be spent by now
		bc, bcancel := context.WithTimeout(context.Background(), 4*time.Minute)
		rc, out := a.igRun(bc, srv, []string{"route", "GOOGLE", prev}, "", 180, nil)
		if rc == 0 && added { // the relay proxy added for this try goes too
			if n := strings.TrimPrefix(find(a.igInfo(bc, srv), c.ip, c.port), "proxy"); n != "" {
				a.igRun(bc, srv, []string{"proxy", "del", n}, "", 120, nil)
			}
		}
		bcancel()
		a.igForget(srv.ID)
		if rc != 0 {
			return fmt.Sprintf("moved Google to %s, but the users' route gets %q there, and putting it back to %s failed: %s — check it by hand", what, d, prev, clipTo(agentLine(srv, out), 100))
		}
		log.Printf("gemini fix %s: %s works in the test browser, but the users' route gets %q there -> put back to %s", srv.Name, what, d, prev)
	}
	if len(cands) == 0 {
		return "no exit that Google places in ." + want + " — move it by hand"
	}
	if usersFail > 0 {
		return fmt.Sprintf("%d exit(s) opened Gemini signed in, but the users' route did not reach them — left on %s", usersFail, prev)
	}
	return fmt.Sprintf("no .%s exit opens Gemini signed in (%d tried) — left as is", want, signedIn)
}
