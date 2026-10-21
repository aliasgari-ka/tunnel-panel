package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// geo is a best-effort IP → country lookup. The panel (on the foreign server) queries a
// public endpoint once per IP and caches the result; failures are non-fatal and the UI
// simply shows no flag. Iran servers never do this lookup — only the panel host does.
var geo = struct {
	sync.Mutex
	cache  map[string]geoInfo
	client *http.Client
}{cache: map[string]geoInfo{}, client: &http.Client{Timeout: 6 * time.Second}}

type geoInfo struct {
	Country string // ISO alpha-2
	City    string
}

// lookupGeo resolves a host (IP or name) to a country code. Private/invalid addresses return "".
func lookupGeo(ctx context.Context, host string) geoInfo {
	host = strings.Trim(host, "[]")
	if host == "" {
		return geoInfo{}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return geoInfo{}
	}
	key := ip.String()
	geo.Lock()
	if g, ok := geo.cache[key]; ok {
		geo.Unlock()
		return g
	}
	geo.Unlock()

	g := queryGeo(ctx, key)
	geo.Lock()
	geo.cache[key] = g
	geo.Unlock()
	return g
}

func queryGeo(ctx context.Context, ip string) geoInfo {
	// ip-api.com: free, no key, returns countryCode. http (their free tier is http-only).
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,countryCode,city", nil)
	resp, err := geo.client.Do(req)
	if err != nil {
		return geoInfo{}
	}
	defer resp.Body.Close()
	var out struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || out.Status != "success" {
		return geoInfo{}
	}
	return geoInfo{Country: out.CountryCode, City: out.City}
}

// annotateGeo fills a server's country/city from its public address, once, best-effort.
func (a *App) annotateGeo(srv *Server) {
	if srv.Country != "" {
		return
	}
	addr := srv.IPv4
	if addr == "" {
		addr = srv.IPv6
	}
	if addr == "" {
		addr = srv.SSHHost
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	g := lookupGeo(ctx, addr)
	if g.Country != "" {
		_ = a.store.Update(func(st *State) error {
			if x := a.store.serverLocked(st, srv.ID); x != nil && x.Country == "" {
				x.Country, x.City = g.Country, g.City
			}
			return nil
		})
	}
}
