package main

// Google's country for an exit (the keyless Gemini page's OneGoogle domain) and the helpers
// around it. The exit itself is picked by igexit.go.

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

var gemRouteRe = regexp.MustCompile(`^(proxy[0-9]*|warp6?|ipv6|direct)$`)
