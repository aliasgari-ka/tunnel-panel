package main

// IG Routing · My sites: a site is the whole site. Whatever the person types (a URL, www., a path,
// a port, capitals, an IDN) becomes the registrable domain (public suffix list: example.co.uk) and
// the agent's "domain:" rule, which is that domain AND every subdomain. The panel also opens the
// site once from the panel host and offers the other domains it loads (its CDN, API, media,
// login) pre-checked, so the site works fully on the chosen exit; shared CDNs and libraries
// (Cloudflare, jsDelivr, analytics …) and every Google domain are left out (Google has its own
// route; on the panel host its users' Google never leaves through the host's own IP: gemhome.go).
// The page shows one card per site with all its domains; deleting a site removes them all in one
// reload (the agent's "custom delm", a live routing swap).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// platforms whose customers share one registrable domain: keep the customer's own host
var igSharedHost = []string{"cloudfront.net", "akamaized.net", "akamaihd.net", "akamai.net", "edgekey.net", "edgesuite.net",
	"azureedge.net", "azurefd.net", "blob.core.windows.net", "fastly.net", "fastlylb.net", "b-cdn.net", "amazonaws.com",
	"r2.dev", "r2.cloudflarestorage.com", "vercel.app", "netlify.app", "herokuapp.com", "appspot.com", "web.app",
	"firebaseapp.com", "pages.dev", "workers.dev", "github.io", "gitlab.io", "wpengine.com", "kxcdn.com", "cdn77.org",
	"bunnycdn.com", "imgix.net", "cloudinary.com", "digitaloceanspaces.com", "backblazeb2.com"}

// shared libraries, analytics and generic CDNs: routing them would move other sites too
var igSiteGeneric = map[string]bool{"cloudflare.com": true, "cloudflareinsights.com": true, "jsdelivr.net": true, "unpkg.com": true,
	"jquery.com": true, "bootstrapcdn.com": true, "fontawesome.com": true, "w3.org": true, "schema.org": true, "ogp.me": true,
	"gravatar.com": true, "wp.com": true, "wordpress.org": true, "wordpress.com": true, "sentry.io": true, "sentry-cdn.com": true,
	"hotjar.com": true, "hotjar.io": true, "segment.com": true, "segment.io": true, "mixpanel.com": true, "amplitude.com": true,
	"intercom.io": true, "intercomcdn.com": true, "zendesk.com": true, "zdassets.com": true, "hcaptcha.com": true, "cookielaw.org": true,
	"onetrust.com": true, "cookiebot.com": true, "newrelic.com": true, "nr-data.net": true, "datadoghq.com": true,
	"browser-intake-datadoghq.com": true, "yandex.ru": true, "yandex.net": true, "clarity.ms": true, "bing.com": true,
	"microsoft.com": true, "apple.com": true, "mozilla.org": true, "facebook.net": true, "facebook.com": true, "twitter.com": true,
	"x.com": true, "t.co": true, "linkedin.com": true, "licdn.com": true, "instagram.com": true, "vimeo.com": true, "polyfill.io": true,
	"typekit.net": true, "adobe.com": true, "adobedtm.com": true, "example.com": true, "github.com": true, "githubusercontent.com": true,
	"cdnjs.com": true, "jsdelivr.com": true, "stripe.com": true, "paypal.com": true, "tiktok.com": true, "pinterest.com": true,
	"reddit.com": true, "whatsapp.com": true, "telegram.org": true, "t.me": true, "addtoany.com": true, "sharethis.com": true,
	"criteo.com": true, "criteo.net": true, "taboola.com": true, "outbrain.com": true, "amazon-adsystem.com": true, "adnxs.com": true,
	"rubiconproject.com": true, "pubmatic.com": true, "openx.net": true, "quantserve.com": true, "scorecardresearch.com": true,
	"chartbeat.com": true, "chartbeat.net": true, "optimizely.com": true, "launchdarkly.com": true, "statsig.com": true,
	"googleoptimize.com": true, "unsplash.com": true, "creativecommons.org": true, "wikipedia.org": true, "wikimedia.org": true,
	"json-schema.org": true, "react.dev": true, "reactjs.org": true, "iptc.org": true, "aboutads.info": true, "youradchoices.ca": true,
	"youronlinechoices.com": true, "youronlinechoices.eu": true, "dotmetrics.net": true, "amazon.com": true, "tinyurl.com": true, "opera.com": true,
	"firefox.com": true, "apollo.dev": true, "commonmark.org": true, "npms.io": true, "yarnpkg.com": true, "gettyimages.com": true, "relay.dev": true}

// Google's own domains: never offered, never added on the panel host with a direct route
var igGoogleDom = map[string]bool{"googleapis.com": true, "gstatic.com": true, "googleusercontent.com": true, "ggpht.com": true,
	"googlevideo.com": true, "youtube.com": true, "ytimg.com": true, "youtu.be": true, "doubleclick.net": true, "googlesyndication.com": true,
	"googletagmanager.com": true, "googletagservices.com": true, "google-analytics.com": true, "googleadservices.com": true,
	"recaptcha.net": true, "withgoogle.com": true, "gvt1.com": true, "gvt2.com": true, "goo.gl": true, "g.co": true,
	"firebaseio.com": true, "googleblog.com": true, "blogger.com": true, "blogspot.com": true, "gmail.com": true, "android.com": true,
	"chrome.com": true, "chromium.org": true, "goog": true, "google": true}

func igIsGoogle(d string) bool {
	d = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(d, "domain:"), "full:"))
	for x := d; x != ""; { // fonts.googleapis.com: googleapis.com is itself a public suffix
		if igGoogleDom[x] {
			return true
		}
		i := strings.Index(x, ".")
		if i < 0 {
			break
		}
		x = x[i+1:]
	}
	if e, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		d = e
	}
	// google.com, google.de, google.co.uk …
	return strings.HasPrefix(d, "google.") && !strings.Contains(strings.TrimPrefix(d, "google."), "google")
}

// igHostKey: the domain a host is routed by — its registrable domain, or the host itself on a shared platform
func igHostKey(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	for _, p := range igSharedHost {
		if strings.HasSuffix(h, "."+p) {
			// the customer's own name directly under the platform (d123.cloudfront.net, app.vercel.app)
			rest := strings.TrimSuffix(h, "."+p)
			if i := strings.LastIndex(rest, "."); i >= 0 {
				rest = rest[i+1:]
			}
			return rest + "." + p, nil
		}
		if h == p {
			return "", errors.New(h + " is a shared platform: add the site's own host on it (e.g. abc." + p + ")")
		}
	}
	e, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return "", errors.New(h + " is not a site (a public suffix)")
	}
	return e, nil
}

var igHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// igSiteNorm turns what a person typed into the site's domain ("https://www.Sub.Example.co.uk:8443/x" -> example.co.uk)
func igSiteNorm(in string) (string, error) {
	s := strings.TrimSpace(in)
	for _, p := range []string{"domain:", "full:"} {
		s = strings.TrimPrefix(s, p)
	}
	if s == "" {
		return "", errors.New("type a site, e.g. example.com")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("not a site: %q", in)
	}
	h := strings.Trim(strings.ToLower(u.Hostname()), ".")
	h = strings.TrimPrefix(h, "*.")
	if net.ParseIP(h) != nil {
		return "", errors.New("an IP address is not a site: type its domain name")
	}
	if a, err := idna.Lookup.ToASCII(h); err == nil {
		h = a
	} else {
		return "", fmt.Errorf("not a valid domain name: %q", h)
	}
	if !igHostRe.MatchString(h) {
		return "", fmt.Errorf("not a valid domain name: %q", h)
	}
	return igHostKey(h)
}

// ---- finding the domains a site loads

var igHostInText = regexp.MustCompile(`(?i)(?:https?:)?\\?/\\?/([a-z0-9][a-z0-9.-]*\.[a-z][a-z0-9-]{1,30})(?::\d+)?`)
var igAssetRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"'<>\s]+\.(?:js|css)(?:\?[^"'<>\s]*)?)["']`)

// a client that only talks to public addresses (the address is checked after DNS, at connect time)
var igSiteClient = func() *http.Client {
	d := &net.Dialer{Timeout: 8 * time.Second, Control: func(_, addr string, _ syscall.RawConn) error {
		host, _, _ := net.SplitHostPort(addr)
		ip := net.ParseIP(host)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
			(ip.To4() != nil && (ip.To4()[0] == 100 && ip.To4()[1]&0xc0 == 64 || ip.To4()[0] == 0)) {
			return errors.New("not a public address")
		}
		return nil
	}}
	tr := &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxIdleConns: 4}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
			return errors.New("stop")
		}
		return nil
	}}
}()

func igFetch(ctx context.Context, u string, max int64) (string, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := igSiteClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	return string(b), resp.Request.URL, nil
}

type igRelated struct {
	D    string `json:"d"`    // the domain (all its subdomains)
	N    int    `json:"n"`    // how often the site refers to it
	Hit  string `json:"hit"`  // one host seen, e.g. static.example-cdn.net
	Sure bool   `json:"sure"` // the page loads it (or it carries the site's name): pre-checked
}

// igSiteFind opens the site (and a few of its scripts / styles) and lists the other domains it loads.
func igSiteFind(ctx context.Context, site string) ([]igRelated, int, error) {
	var page string
	var base *url.URL
	var err error
	for _, u := range []string{"https://" + site + "/", "https://www." + site + "/", "http://" + site + "/"} {
		if page, base, err = igFetch(ctx, u, 3<<20); err == nil && page != "" {
			break
		}
	}
	if page == "" {
		if err == nil {
			err = errors.New("empty page")
		}
		return nil, 0, fmt.Errorf("could not open %s from the panel host: %v", site, err)
	}
	var css, js []string
	// up to 8 scripts / styles of the site itself or its CDN (their API hosts are often only there)
	var assets []string
	for _, m := range igAssetRe.FindAllStringSubmatch(page, 40) {
		if r, e := base.Parse(strings.ReplaceAll(m[1], "&amp;", "&")); e == nil && (r.Scheme == "https" || r.Scheme == "http") {
			assets = append(assets, r.String())
		}
	}
	if len(assets) > 8 {
		assets = assets[:8]
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range assets {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			if t, _, e := igFetch(ctx, a, 4<<20); e == nil {
				mu.Lock()
				if strings.Contains(strings.ToLower(strings.SplitN(a, "?", 2)[0]), ".css") {
					css = append(css, t)
				} else {
					js = append(js, t)
				}
				mu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	label := strings.SplitN(site, ".", 2)[0]
	count, hit, sure := map[string]int{}, map[string]string{}, map[string]bool{}
	left := map[string]bool{}
	add := func(h string, strong bool) {
		h = strings.ToLower(strings.Trim(h, "."))
		if !igHostRe.MatchString(h) || igFakeTLD(h) {
			return
		}
		k, e := igHostKey(h)
		if e != nil || k == site {
			return
		}
		own := len(label) >= 4 && strings.Contains(k, label)
		if igIsGoogle(k) || (igSiteGeneric[k] && !own) {
			left[k] = true
			return
		}
		count[k]++
		if strong || own {
			sure[k] = true
		}
		if hit[k] == "" {
			hit[k] = h
		}
	}
	if bk, e := igHostKey(base.Hostname()); e == nil && bk != site { // the site redirected to another domain
		add(base.Hostname(), true)
	}
	// what the page itself loads: scripts, styles, images, frames, preconnect / preload, CSS url()
	for _, t := range append([]string{page}, css...) {
		for _, tag := range igResTag.FindAllString(t, 3000) {
			low := strings.ToLower(tag)
			if strings.HasPrefix(low, "<link") && !igLinkRel.MatchString(low) {
				continue
			}
			for _, m := range igHostInText.FindAllStringSubmatch(tag, 50) {
				add(m[1], true)
			}
		}
		for _, m := range igCSSURL.FindAllStringSubmatch(t, 3000) {
			add(m[1], true)
		}
	}
	// scripts: hosts with the site's name are its own (API …); others only as "maybe"
	for _, t := range js {
		for _, m := range igJSURL.FindAllStringSubmatch(t, 4000) {
			add(m[1], false)
		}
	}
	var out []igRelated
	for k, n := range count {
		out = append(out, igRelated{k, n, hit[k], sure[k]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sure != out[j].Sure {
			return out[i].Sure
		}
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].D < out[j].D
	})
	var keep []igRelated
	maybe := 0
	for _, r := range out {
		if !r.Sure {
			if maybe >= 8 {
				continue
			}
			maybe++
		}
		keep = append(keep, r)
		if len(keep) >= 25 {
			break
		}
	}
	return keep, len(left), nil
}

// tags that load something, the rel= of a <link> that loads, CSS url(), a full URL in a script
var (
	igResTag  = regexp.MustCompile(`(?is)<(?:script|link|img|iframe|source|video|audio|embed|meta|object)\b[^>]*>`)
	igLinkRel = regexp.MustCompile(`rel\s*=\s*["']?[^"'>]*(preconnect|dns-prefetch|preload|stylesheet|icon|modulepreload|manifest)`)
	igCSSURL  = regexp.MustCompile(`(?i)url\(\s*["']?(?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z][a-z0-9-]{1,30})`)
	igJSURL   = regexp.MustCompile("(?i)[\"'`]https?:\\\\?/\\\\?/([a-z0-9][a-z0-9.-]*\\.[a-z][a-z0-9-]{1,30})")
)

// igFakeTLD: names that are not real hosts (file names, reserved / private names)
func igFakeTLD(h string) bool {
	i := strings.LastIndex(h, ".")
	switch h[i+1:] {
	case "js", "css", "json", "png", "jpg", "svg", "gif", "webp", "html", "php", "invalid", "test", "example", "localhost", "local", "internal", "android", "map", "ts", "md":
		return true
	}
	return false
}

// ---- the agent's list grouped into sites

type igSiteDom struct {
	D       string   `json:"d"`                 // the domain
	Rule    string   `json:"rule"`              // the agent's rule (domain:x)
	Route   string   `json:"route"`             // "" = the "my sites" route
	Also    []string `json:"also,omitempty"`    // services whose own list covers it too (My sites wins)
	Covered string   `json:"covered,omitempty"` // another of my sites already covers it
}

type igSiteCard struct {
	Site  string      `json:"site"`
	Route string      `json:"route"`
	Doms  []igSiteDom `json:"doms"`
}

var igSvcListCache = struct {
	sync.Mutex
	m map[string]igSvcListEntry
}{m: map[string]igSvcListEntry{}}

type igSvcListEntry struct {
	at    time.Time
	lists map[string][]string
}

// igSvcLists: each service's domain list on this server (the agent's "svclists"; cached 30 min)
func (a *App) igSvcLists(ctx context.Context, srv *Server) map[string][]string {
	igSvcListCache.Lock()
	e, ok := igSvcListCache.m[srv.ID]
	igSvcListCache.Unlock()
	if ok && time.Since(e.at) < 30*time.Minute {
		return e.lists
	}
	rc, out := a.igRun(ctx, srv, []string{"svclists"}, "", 30, nil)
	m := map[string][]string{}
	if rc == 0 {
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) > 1 && contains(igServices, f[0]) {
				m[f[0]] = append(m[f[0]], f[1:]...)
			}
		}
		igSvcListCache.Lock()
		igSvcListCache.m[srv.ID] = igSvcListEntry{time.Now(), m}
		igSvcListCache.Unlock()
	}
	return m
}

// igDomCovers: does rule-domain a cover b (b == a or a subdomain of a)?
func igDomCovers(a, b string) bool { return a == b || strings.HasSuffix(b, "."+a) }

// igSiteCards groups the agent's "my sites" lines ("domain:x [route]") into sites.
func igSiteCards(raw string, rel map[string]string, lists map[string][]string) []igSiteCard {
	type line struct{ rule, d, route string }
	var ls []line
	for _, l := range strings.Split(raw, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		d := f[0]
		for _, p := range []string{"domain:", "full:"} {
			d = strings.TrimPrefix(d, p)
		}
		r := ""
		if len(f) > 1 {
			r = f[1]
		}
		ls = append(ls, line{f[0], d, r})
	}
	by := map[string]*igSiteCard{}
	var order []string
	for _, l := range ls {
		site := rel[l.d]
		if site == "" {
			if k, err := igHostKey(l.d); err == nil && !strings.Contains(l.rule, "regexp:") && !strings.Contains(l.rule, "keyword:") {
				site = k
			} else {
				site = l.d
			}
		}
		c := by[site]
		if c == nil {
			c = &igSiteCard{Site: site}
			by[site] = c
			order = append(order, site)
		}
		sd := igSiteDom{D: l.d, Rule: l.rule, Route: l.route}
		if strings.HasPrefix(l.rule, "domain:") || strings.HasPrefix(l.rule, "full:") {
			for svc, list := range lists {
				for _, e := range list {
					x := strings.TrimPrefix(strings.TrimPrefix(e, "domain:"), "full:")
					if x != e && (igDomCovers(x, l.d) || igDomCovers(l.d, x)) {
						sd.Also = append(sd.Also, svc)
						break
					}
				}
			}
			sort.Strings(sd.Also)
			for _, o := range ls {
				if o.d != l.d && strings.HasPrefix(o.rule, "domain:") && igDomCovers(o.d, l.d) {
					sd.Covered = o.d
					break
				}
			}
		}
		c.Doms = append(c.Doms, sd)
	}
	out := make([]igSiteCard, 0, len(order))
	for _, k := range order {
		c := by[k]
		c.Route = c.Doms[0].Route
		for _, d := range c.Doms {
			if d.D == c.Site {
				c.Route = d.Route
			}
		}
		out = append(out, *c)
	}
	return out
}

// ---- API

// igInfoMem: the server's last info the panel read (no SSH; empty when none)
func (a *App) igInfoMem(id string) map[string]string {
	a.ig.mu.Lock()
	defer a.ig.mu.Unlock()
	if e, ok := a.ig.m[id]; ok && e.info != nil {
		return e.info
	}
	return map[string]string{}
}

func (a *App) igSiteRel(id string) map[string]string {
	out := map[string]string{}
	a.store.View(func(st *State) {
		for k, v := range st.IgSites[id] {
			out[k] = v
		}
	})
	return out
}

// GET /api/igproxy/sites?id= : the server's sites as cards
func (s *Server2) igSitesGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	x, err := s.igServer(user, admin, r.URL.Query().Get("id"))
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	rc, out := s.app.igRun(ctx, x, []string{"custom", "raw"}, "", 30, nil)
	if rc != 0 { // an older agent: no "custom raw"
		rc2, lines, err := s.app.igShell(ctx, x, "cat /etc/igproxy/custom 2>/dev/null; echo __RC=0", 30*time.Second)
		if err != nil || rc2 != 0 {
			httpErr(w, 502, "could not read the sites: "+clipTo(strings.TrimSpace(out), 160))
			return
		}
		out = strings.Join(lines, "\n")
	}
	writeJSON(w, map[string]any{"sites": igSiteCards(out, s.app.igSiteRel(x.ID), s.app.igSvcLists(ctx, x)), "home": gemIsHome(x)})
}

// POST /api/igproxy/sites/find {site}: the site's domain and the other domains it loads
func (s *Server2) igSitesFind(w http.ResponseWriter, r *http.Request) {
	var in struct{ Site string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	site, err := igSiteNorm(in.Site)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	res := map[string]any{"site": site, "google": igIsGoogle(site)}
	if igIsGoogle(site) {
		res["related"] = []igRelated{}
		writeJSON(w, res)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	rel, left, err := igSiteFind(ctx, site)
	if err != nil {
		res["err"] = err.Error()
		rel = []igRelated{}
	}
	res["related"], res["left"] = rel, left
	writeJSON(w, res)
}

var igSiteRoute = regexp.MustCompile(`^(|proxy|proxy[1-9][0-9]*|warp|direct)$`)

// POST /api/igproxy/sites/add {srv: id|"all", view, site, route, domains:[...]}: the site with all its
// subdomains and the chosen related domains, one reload per server
func (s *Server2) igSitesAdd(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct {
		Srv, View, Site, Route string
		Domains                []string
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	site, err := igSiteNorm(in.Site)
	if err == nil && !igSiteRoute.MatchString(in.Route) {
		err = errors.New("bad route")
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	doms := []string{site}
	for _, d := range in.Domains {
		k, err := igSiteNorm(d)
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		if !contains(doms, k) {
			doms = append(doms, k)
		}
	}
	if len(doms) > 40 {
		httpErr(w, 400, "too many domains (40 at most)")
		return
	}
	var list []*Server
	if in.Srv == "all" {
		list = s.igServersOf(user, admin, in.View)
	} else if x, err := s.igServer(user, admin, in.Srv); err == nil {
		list = []*Server{x}
	} else {
		httpErr(w, 400, err.Error())
		return
	}
	type res struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
		Msg  string `json:"msg"`
	}
	out := make([]res, len(list))
	var wg sync.WaitGroup
	for i, x := range list {
		wg.Add(1)
		go func(i int, x *Server) {
			defer wg.Done()
			out[i].Name = x.Name
			ds := doms
			// the panel host: its users' Google never leaves through its own IP (gemhome.go)
			if gemIsHome(x) && (in.Route == "direct" || (in.Route == "" && s.app.igInfoMem(x.ID)["custom"] == "direct")) {
				var keep []string
				for _, d := range ds {
					if !igIsGoogle(d) {
						keep = append(keep, d)
					}
				}
				if len(keep) < len(ds) {
					out[i].Msg = "Google domains left out here (the test account's IP) · "
				}
				ds = keep
			}
			if len(ds) == 0 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			route := in.Route
			if route == "" {
				route = "-"
			}
			rc, said := s.app.igRun(ctx, x, append([]string{"custom", "addm", route}, ds...), "", 150, nil)
			if rc != 0 && strings.Contains(said, "usage: custom") { // an older agent: one by one
				rc = 0
				for _, d := range ds {
					args := []string{"custom", "add", d}
					if in.Route != "" {
						args = append(args, in.Route)
					}
					if r2, o := s.app.igRun(ctx, x, args, "", 120, nil); r2 != 0 {
						rc, said = r2, o
					}
				}
			}
			s.app.igForget(x.ID)
			if rc != 0 {
				out[i].Msg += clipTo(lastLineOf(said), 160)
				return
			}
			out[i].OK = true
			out[i].Msg += fmt.Sprintf("%s + %d related domains", site, len(ds)-1)
			_ = s.app.store.Update(func(st *State) error {
				if st.IgSites == nil {
					st.IgSites = map[string]map[string]string{}
				}
				if st.IgSites[x.ID] == nil {
					st.IgSites[x.ID] = map[string]string{}
				}
				for _, d := range ds {
					if d != site {
						st.IgSites[x.ID][d] = site
					}
				}
				return nil
			})
		}(i, x)
	}
	wg.Wait()
	writeJSON(w, map[string]any{"site": site, "results": out})
}

// POST /api/igproxy/sites/del {id, site}: every domain of the site, one reload
func (s *Server2) igSitesDel(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct{ ID, Site string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, in.ID)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	rc, out := s.app.igRun(ctx, x, []string{"custom", "raw"}, "", 30, nil)
	if rc != 0 {
		httpErr(w, 502, "could not read the sites: "+clipTo(strings.TrimSpace(out), 160))
		return
	}
	var rules []string
	for _, c := range igSiteCards(out, s.app.igSiteRel(x.ID), nil) {
		if c.Site == in.Site {
			for _, d := range c.Doms {
				rules = append(rules, d.Rule)
			}
		}
	}
	if len(rules) == 0 {
		httpErr(w, 400, "no such site here (reload the page)")
		return
	}
	if rc, said := s.app.igRun(ctx, x, append([]string{"custom", "delm"}, rules...), "", 150, nil); rc != 0 {
		httpErr(w, 502, clipTo(lastLineOf(said), 200))
		return
	}
	s.app.igForget(x.ID)
	_ = s.app.store.Update(func(st *State) error {
		for d, site := range st.IgSites[x.ID] {
			if site == in.Site {
				delete(st.IgSites[x.ID], d)
			}
		}
		return nil
	})
	writeJSON(w, map[string]any{"removed": len(rules)})
}
