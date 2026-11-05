package main

// One Google country for everyone. Users move between our servers (failover, a new
// subscription), and a Google account that hops countries looks suspicious to Google. So
// every server's Google goes out in Germany, where most of our servers are: its own IP when
// Google places that in Germany, else the own IP of one of our German servers through the
// agent's relay (an "internal" proxy).

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

// gemWantDom: the Google country every server's users get (OneGoogle domain).
const gemWantDom = "de"

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

// gemFix moves a server's Google to a German exit that the signed-in check passes: its own IP
// when Google places that in Germany, else the own IP of one of our German servers (an
// internal relay proxy, added when missing). Each server keeps the same choice (spread by id).
func (a *App) gemFix(srv *Server, inf map[string]string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var cands []*Server
	if inf["google"] != "direct" && gemOwnDomOf(ctx, srv) == gemWantDom {
		cands = append(cands, srv)
	}
	var others []*Server
	a.store.View(func(s *State) {
		for _, x := range s.Servers {
			if x.Igproxy && x.Owner == "" && x.ID != srv.ID && x.IPv4 != "" {
				others = append(others, x)
			}
		}
	})
	sort.Slice(others, func(i, j int) bool {
		hi, hj := sha1.Sum([]byte(srv.ID+others[i].ID)), sha1.Sum([]byte(srv.ID+others[j].ID))
		return bytes.Compare(hi[:], hj[:]) < 0
	})
	for _, x := range others {
		if gemOwnDomOf(ctx, x) == gemWantDom {
			cands = append(cands, x)
		}
	}
	find := func(inf map[string]string, ip string) string {
		for n, r := range igRelays(inf) {
			if r[0] == ip && r[1] == "12371" {
				return "proxy" + strconv.Itoa(n)
			}
		}
		return ""
	}
	for _, c := range cands {
		pc, pcancel := context.WithTimeout(ctx, 2*time.Minute)
		v, _, _ := gemProbe(pc, "socks5://"+c.IPv4+":12371")
		pcancel()
		if v != "ok" {
			continue
		}
		via, what := "direct", "its own IP"
		if c != srv {
			if via = find(inf, c.IPv4); via == "" { // not in its list yet: add it (the agent tests it first)
				if rc, out := a.igRun(ctx, srv, []string{"proxy", "add", "-"}, "socks5 "+c.IPv4+" 12371 - -", 120, nil); rc != 0 {
					log.Printf("gemini fix %s: adding %s: %s", srv.Name, c.Name, lastLineOf(out))
					continue
				}
				a.igForget(srv.ID)
				if via = find(a.igInfo(ctx, srv), c.IPv4); via == "" {
					continue
				}
			}
			what = via + " (internal: " + c.Name + " own IP)"
		}
		if rc, out := a.igRun(ctx, srv, []string{"route", "GOOGLE", via}, "", 180, nil); rc != 0 {
			return "could not move Google to " + what + ": " + clipTo(lastLineOf(out), 100)
		}
		a.igForget(srv.ID)
		return "Google moved to " + what + " — Germany, signed-in Gemini works there"
	}
	if len(cands) == 0 {
		return "no German exit found — move it by hand"
	}
	return fmt.Sprintf("no German exit opens Gemini signed in (%d tried) — left as is", len(cands))
}

// gemRelaySync gives every agent the IPv4 list of all our agent servers: they may use each
// other's relays, so a new server works with the others without a new agent script.
func (a *App) gemRelaySync(list []*Server, sent map[string]string) {
	ips := make([]string, 0, len(list))
	for _, s := range list {
		ips = append(ips, s.IPv4)
	}
	sort.Strings(ips)
	want := strings.Join(ips, "\n")
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, s := range list {
		mu.Lock()
		done := sent[s.ID] == want
		mu.Unlock()
		if done {
			continue
		}
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if rc, out := a.igRun(ctx, s, []string{"relay-allow", "-"}, want+"\n", 60, nil); rc != 0 {
				log.Printf("relay allow-list %s: %s", s.Name, lastLineOf(out)) // an older agent: next round again
				return
			}
			mu.Lock()
			sent[s.ID] = want
			mu.Unlock()
		}(s)
	}
	wg.Wait()
}
