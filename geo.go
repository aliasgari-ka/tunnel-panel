package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// geo is a best-effort IP → country lookup. The panel (on the foreign server) asks public
// endpoints once per IP and caches the answer; the server's own Country/CountryIP in the
// state is the lasting cache. Only the IP goes out — no name, account or anything else.
// Iran servers never do this lookup — only the panel host does.
//
// Several free sources, tried in order: one that is down, rate-limited (ip-api allows 45 a
// minute) or blocked from the panel's network no longer leaves every server without a flag.
var geo = struct {
	sync.Mutex
	cache  map[string]geoInfo
	failed map[string]time.Time // ip -> when a failed lookup may be tried again
	client *http.Client
}{cache: map[string]geoInfo{}, failed: map[string]time.Time{}, client: &http.Client{Timeout: 6 * time.Second}}

// geoRetry: a failed lookup (every source down, rate limit) is tried again after this, not never.
var geoRetry = 10 * time.Minute

type geoInfo struct {
	Country string // ISO alpha-2, upper case
	City    string
}

// geoSource: one public endpoint. parse gets the body and returns the country code and city.
type geoSource struct {
	name  string
	url   func(ip string) string
	parse func(b []byte) (string, string)
}

var geoSources = []geoSource{
	{"ipwho.is", func(ip string) string { return "https://ipwho.is/" + ip + "?fields=success,country_code,city" },
		func(b []byte) (string, string) {
			var o struct {
				Success     bool   `json:"success"`
				CountryCode string `json:"country_code"`
				City        string `json:"city"`
			}
			if json.Unmarshal(b, &o) != nil || !o.Success {
				return "", ""
			}
			return o.CountryCode, o.City
		}},
	{"ip-api.com", func(ip string) string {
		return "http://ip-api.com/json/" + ip + "?fields=status,countryCode,city" // free tier is http only
	}, func(b []byte) (string, string) {
		var o struct {
			Status      string `json:"status"`
			CountryCode string `json:"countryCode"`
			City        string `json:"city"`
		}
		if json.Unmarshal(b, &o) != nil || o.Status != "success" {
			return "", ""
		}
		return o.CountryCode, o.City
	}},
	{"country.is", func(ip string) string { return "https://api.country.is/" + ip },
		func(b []byte) (string, string) {
			var o struct {
				Country string `json:"country"`
			}
			if json.Unmarshal(b, &o) != nil {
				return "", ""
			}
			return o.Country, ""
		}},
	{"ipapi.co", func(ip string) string { return "https://ipapi.co/" + ip + "/json/" },
		func(b []byte) (string, string) {
			var o struct {
				CountryCode string `json:"country_code"`
				City        string `json:"city"`
				Error       bool   `json:"error"`
			}
			if json.Unmarshal(b, &o) != nil || o.Error {
				return "", ""
			}
			return o.CountryCode, o.City
		}},
}

// normCC: a valid ISO alpha-2 code in upper case, else "". "UK" is GB.
func normCC(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	if cc == "UK" {
		return "GB"
	}
	return cc
}

// geoAddr: the public IP of a host (IP or name), "" for private, loopback or unresolvable.
func geoAddr(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

// lookupGeo resolves a host (IP or name) to a country code. Private/invalid addresses return "".
func lookupGeo(ctx context.Context, host string) geoInfo {
	key := geoAddr(host)
	if key == "" {
		return geoInfo{}
	}
	geo.Lock()
	if g, ok := geo.cache[key]; ok {
		geo.Unlock()
		return g
	}
	if time.Now().Before(geo.failed[key]) {
		geo.Unlock()
		return geoInfo{}
	}
	geo.Unlock()

	g := queryGeo(ctx, key)
	geo.Lock()
	if g.Country != "" {
		geo.cache[key] = g
		delete(geo.failed, key)
	} else {
		geo.failed[key] = time.Now().Add(geoRetry)
	}
	geo.Unlock()
	return g
}

// queryGeo asks the sources in turn and keeps the first valid answer.
func queryGeo(ctx context.Context, ip string) geoInfo {
	for _, src := range geoSources {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.url(ip), nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "tunnel-panel")
		resp, err := geo.client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if cc, city := src.parse(b); normCC(cc) != "" {
			return geoInfo{Country: normCC(cc), City: city}
		}
	}
	return geoInfo{}
}

// serverGeoAddr: the address a server's country is looked up from.
func serverGeoAddr(srv *Server) string {
	for _, h := range []string{srv.IPv4, srv.IPv6, srv.SSHHost} {
		if h != "" {
			return h
		}
	}
	return ""
}

// geoDue: the server's country should be (re)detected — not set by hand, and unknown or
// found for another address than the server has now.
func geoDue(srv *Server) bool {
	if srv.CountryManual {
		return false
	}
	return srv.Country == "" || srv.CountryIP != serverGeoAddr(srv)
}

// annotateGeo fills a server's country/city from its public address, best-effort. A country
// set by hand (CountryManual) is never replaced.
func (a *App) annotateGeo(srv *Server) {
	if !geoDue(srv) {
		return
	}
	addr := serverGeoAddr(srv)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	g := lookupGeo(ctx, addr)
	if g.Country == "" {
		return
	}
	_ = a.store.Update(func(st *State) error {
		if x := a.store.serverLocked(st, srv.ID); x != nil && !x.CountryManual && serverGeoAddr(x) == addr {
			x.Country, x.City, x.CountryIP = g.Country, g.City, addr
		}
		return nil
	})
}

// geoBackfill: every server whose country is missing (or found for an old address) gets
// it — at start and then every 30 minutes, one server at a time. Countries that were in the
// state before CountryIP existed are kept as they are (they may have been typed by hand).
func (a *App) geoBackfill() {
	time.Sleep(20 * time.Second)
	for {
		var due []*Server
		a.store.Update(func(st *State) error {
			for _, s := range st.Servers {
				if s.Country != "" && s.CountryIP == "" && !s.CountryManual {
					s.Country = normCC(s.Country)
					s.CountryIP = serverGeoAddr(s) // older state: trust the country it has
				}
				if geoDue(s) {
					c := *s
					due = append(due, &c)
				}
			}
			return nil
		})
		for _, s := range due {
			a.annotateGeo(s)
			if x := a.store.Server(s.ID); x != nil && x.Country == "" {
				log.Printf("geo: no country found for server %s yet (every source failed)", s.Name)
			}
			time.Sleep(2 * time.Second)
		}
		time.Sleep(30 * time.Minute)
	}
}
