package main

// "Run checks" of IG Routing's Tests tab: the light checks of one server in one go, as a list the
// page can show (✓ / ✗ per service and per exit) instead of a log to read. One request per
// service through the users'-route relay (127.0.0.1:12370, the agent's RELAY_BASE-1: it follows
// the users' routes) and one Cloudflare trace per exit (a few hundred bytes each); the proxies
// are tested by the Proxies tab's own test. Nothing is changed on the server. The last result
// of each server is kept (in memory) so the tab shows it with its time when opened again.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const igHealthScript = `#ighealth
R=/run/igproxy D=/etc/igproxy
grep -q "^VER=" /usr/local/bin/igproxy 2>/dev/null || { echo __RC=3; exit 0; }
now=$(date +%s); d=$(mktemp -d)
ex(){ # ex <key> <standby reason> <curl args> : one Cloudflare trace through that exit
  local k=$1 w=$2 o t; shift 2
  o=$(curl -s -m 8 "$@" -w '\n__T %{http_code} %{time_starttransfer}' https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
  t=$(sed -n 's/^__T //p' <<<"$o"); t=${t:-000 0}
  # IPv6: this host's own HTTPS over IPv6 can be firewalled while the router's IPv6 exit works -> DNS over IPv6 (the agent's own test)
  [ "$k" = ipv6 ] && [ "${t%% *}" != 200 ] && dig -6 +short +time=3 +tries=1 @2606:4700:4700::1111 one.one.one.one A 2>/dev/null | grep -qE '^[0-9.]+$' && t="dns 0"
  printf 'E\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "${t%% *}" "$(awk '{printf "%d", $2*1000}' <<<"$t")" \
    "$(sed -n 's/^ip=//p' <<<"$o")" "$(sed -n 's/^loc=//p' <<<"$o")" "$w"
}
sv(){ # sv <key> <url> : that service through the users' routes
  printf 'S\t%s\t%s\n' "$1" "$(curl -s -m 12 -x socks5h://127.0.0.1:12370 -o /dev/null -w '%{http_code}\t%{time_total}\t%{redirect_url}' "$2" 2>/dev/null)"
}
ex direct "" -4 > "$d/e0" &
[ "$(cat "$D/has_v6" 2>/dev/null)" = 1 ] && { ex ipv6 "" -6 > "$d/e6" & }
i=0
[ -s "$D/warps" ] && while read -r k _; do
  [ -z "$k" ] && continue; i=$((i+1)); ex "warp$i" "$(awk 'NR==1{print $1}' "$R/wout_$i" 2>/dev/null | head -c 20)" -x "socks5h://127.0.0.1:$((12350+i))" > "$d/w$i" &
done < "$D/warps"
if ss -ltn 2>/dev/null | grep -q ':12370 '; then
  sv IG https://i.instagram.com/ > "$d/s1" &
  sv GOOGLE https://www.google.com/generate_204 > "$d/s2" &
  sv GEMINI https://gemini.google.com/app > "$d/s3" &
else printf 'S\tRELAY\tnone\n' > "$d/s0"; fi
wait; cat "$d"/* 2>/dev/null; rm -rf "$d"
for f in gem igp; do [ -s "$R/${f}_state" ] && read -r a b _ < "$R/${f}_state" && printf 'A\t%s\t%s\t%s\n' "$f" "$a" "$((now - ${b:-$now}))"; done
[ -s "$R/panel_state" ] && printf 'A\tpanel\t%s\n' "$(head -c 300 "$R/panel_state" | tr '\t\n' '  ')"
echo __RC=0
`

// IgHCheck is one line of the result: a service (through the users' routes) or an exit.
type IgHCheck struct {
	K    string `json:"k"`              // IG GOOGLE GEMINI | direct ipv6 warpN proxyN
	OK   bool   `json:"ok"`             // works
	Warn bool   `json:"warn,omitempty"` // works, but with a catch (Why says which)
	Idle bool   `json:"idle,omitempty"` // a WARP on standby (Why = the agent's reason: ip | ipnew | music | down)
	MS   int    `json:"ms,omitempty"`
	IP   string `json:"ip,omitempty"`
	Loc  string `json:"loc,omitempty"`
	Why  string `json:"why,omitempty"`
}

// IgHealth is one server's "Run checks".
type IgHealth struct {
	At       int64      `json:"at"`
	Took     int        `json:"took"` // ms
	Svcs     []IgHCheck `json:"svcs"`
	Exits    []IgHCheck `json:"exits"`
	GemAge   int        `json:"gemAge"` // seconds since the agent's own user-path check (-1 = none)
	Gem      string     `json:"gem,omitempty"`
	IgpAge   int        `json:"igpAge"`
	Igp      string     `json:"igp,omitempty"`
	PanelWhy string     `json:"panelWhy,omitempty"` // the agent's reason for the panel state (cached ≤ 5 min)
	Err      string     `json:"err,omitempty"`      // a part that could not be read (the proxies)
}

// igParseHealth turns the script's lines into the result (proxies are added by the caller).
func igParseHealth(lines []string) IgHealth {
	r := IgHealth{Svcs: []IgHCheck{}, Exits: []IgHCheck{}, GemAge: -1, IgpAge: -1}
	for _, l := range lines {
		f := strings.Split(strings.TrimRight(l, "\r"), "\t")
		switch {
		case f[0] == "E" && len(f) >= 6:
			c := IgHCheck{K: f[1], IP: f[4], Loc: f[5]}
			c.MS, _ = strconv.Atoi(f[3])
			c.OK = f[2] == "200" && c.IP != "" || f[2] == "dns"
			if len(f) >= 7 && f[6] != "" && !c.OK {
				// a WARP the agent took off the router on purpose (other exit IP, no music …): not a failure
				c.Idle, c.Why = true, f[6]
			} else if !c.OK {
				c.MS = 0
				c.Why = igHWhy(f[2])
			}
			r.Exits = append(r.Exits, c)
		case f[0] == "S" && len(f) >= 3:
			if f[1] == "RELAY" {
				r.Svcs = append(r.Svcs, IgHCheck{K: "RELAY", Why: "the users'-route relay isn't running here: update the agent (⋯ → Install / update agent)"})
				continue
			}
			code, ms, redir := f[2], 0, ""
			if len(f) >= 4 {
				if t, err := strconv.ParseFloat(f[3], 64); err == nil {
					ms = int(t * 1000)
				}
			}
			if len(f) >= 5 {
				redir = f[4]
			}
			c := IgHCheck{K: f[1], MS: ms}
			switch {
			case code == "" || code == "000":
				c.MS, c.Why = 0, "no answer through the users' route"
			case f[1] == "GOOGLE" && code != "204":
				c.Why = "Google answers http " + code + " instead of 204"
			case strings.Contains(redir, "/sorry/") || code == "429":
				c.Why = "Google shows its \"unusual traffic\" page (CAPTCHA) for this exit IP"
			case code[0] == '5':
				c.Why = "http " + code
			default:
				c.OK = true
			}
			r.Svcs = append(r.Svcs, c)
		case f[0] == "A" && len(f) >= 3:
			switch f[1] {
			case "gem", "igp":
				age := -1
				if len(f) >= 4 {
					age, _ = strconv.Atoi(f[3])
				}
				if f[1] == "gem" {
					r.Gem, r.GemAge = f[2], age
				} else {
					r.Igp, r.IgpAge = f[2], age
				}
			case "panel":
				if _, why, ok := strings.Cut(f[2], "|"); ok {
					r.PanelWhy = strings.TrimSpace(why)
				}
			}
		}
	}
	order := map[string]int{"IG": 0, "GOOGLE": 1, "GEMINI": 2, "RELAY": 3}
	sort.SliceStable(r.Svcs, func(i, j int) bool { return order[r.Svcs[i].K] < order[r.Svcs[j].K] })
	sort.SliceStable(r.Exits, func(i, j int) bool { return igHRank(r.Exits[i].K) < igHRank(r.Exits[j].K) })
	return r
}

// direct, ipv6, warp1…, proxy1… in that order
func igHRank(k string) int {
	switch {
	case k == "direct":
		return 0
	case k == "ipv6":
		return 1
	case strings.HasPrefix(k, "warp"):
		return 100 + atoiOr(k[4:])
	case strings.HasPrefix(k, "proxy"):
		return 1000 + atoiOr(k[5:])
	}
	return 10000
}

func igHWhy(code string) string {
	if code == "" || code == "000" {
		return "no answer"
	}
	return "http " + code
}

// igHProxy is one proxy's line from the Proxies tab's test.
func igHProxy(p *igProxyRow) IgHCheck {
	c := IgHCheck{K: "proxy" + strconv.Itoa(p.N)}
	t := p.Test
	switch {
	case t == nil || !t.OK:
		c.Why = "no answer"
	default:
		c.OK, c.MS, c.IP, c.Loc = true, t.MS, t.IP, t.Loc
		if p.Bad {
			c.Warn, c.Why = true, "Instagram rejected its IP: out of rotation"
		} else if !t.Google {
			c.Warn, c.Why = true, "Google doesn't answer through it"
		} else if t.MS == 0 {
			c.Warn, c.Why = true, "Instagram doesn't answer through it"
		}
	}
	return c
}

// The script's Gemini line is a plain HTTP request, and that can't see what users see. On
// 2026-11-13 it showed xe101 OK on the WARP exit that Google refuses to accounts (the page answers
// 200 there too), then CAPTCHA on its own IPv6, where a browser opens Gemini (Google: Germany).
// So the Gemini line is the panel's browser check of the users' route (gemProbe without the
// account, the same check that moves Google) whenever the test browser gives a verdict; the
// HTTP answer is kept only when it gives none (test browser down, relay not reachable from it).
var igHGemProbe = gemProbe

const igHGemWait = 60 * time.Second

func igHGemini(r *IgHealth, v string, p gemPage) {
	for i := range r.Svcs {
		c := &r.Svcs[i]
		if c.K != "GEMINI" {
			continue
		}
		httpOK, httpWhy := c.OK, c.Why
		switch v {
		case "ok":
			c.OK, c.Warn, c.Why, c.Loc = true, false, "", gemWhy(p)
			if !httpOK {
				c.Warn, c.Why = true, "a browser opens it; a plain HTTP request gets: "+httpWhy
			}
		case "refused":
			c.OK, c.Warn, c.Loc = false, false, ""
			c.Why = "Gemini refuses accounts on this exit (browser check: " + gemWhy(p) + ")"
		case "captcha":
			c.OK, c.Warn, c.Loc = false, false, ""
			c.Why = "a browser gets Google's \"unusual traffic\" page (CAPTCHA) on this exit"
		}
	}
}

var igHLast = struct {
	sync.Mutex
	m map[string]IgHealth
}{m: map[string]IgHealth{}}

func (a *App) igHealth(ctx context.Context, srv *Server) (IgHealth, error) {
	start := time.Now()
	var (
		wg   sync.WaitGroup
		px   []*igProxyRow
		perr error
	)
	wg.Add(1)
	go func() { defer wg.Done(); px, perr = a.igProxies(ctx, srv, true, 0) }()
	// Gemini the way a user's browser gets it (see igHGemini), at the same time
	var (
		gv string
		gp gemPage
	)
	if srv.IPv4 != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc, pcancel := context.WithTimeout(ctx, igHGemWait)
			defer pcancel()
			gv, gp, _ = igHGemProbe(pc, "socks5://"+srv.IPv4+":"+strconv.Itoa(gemRelayPort))
		}()
	}
	rc, lines, err := a.igShell(ctx, srv, igHealthScript, 45*time.Second)
	wg.Wait()
	if rc == 3 {
		return IgHealth{}, errors.New("igproxy is not installed on this server")
	}
	if rc != 0 {
		if err == nil {
			err = errors.New("the server answered with code " + strconv.Itoa(rc))
		}
		return IgHealth{}, err
	}
	r := igParseHealth(lines)
	igHGemini(&r, gv, gp)
	if perr != nil {
		r.Err = "proxies: " + perr.Error()
	}
	for _, p := range px {
		r.Exits = append(r.Exits, igHProxy(p))
	}
	sort.SliceStable(r.Exits, func(i, j int) bool { return igHRank(r.Exits[i].K) < igHRank(r.Exits[j].K) })
	r.At, r.Took = time.Now().Unix(), int(time.Since(start)/time.Millisecond)
	igHLast.Lock()
	igHLast.m[srv.ID] = r
	igHLast.Unlock()
	return r, nil
}

// GET /api/igproxy/health?id= : the last result (or {"at":0} — never run since the panel started)
func (s *Server2) igHealthGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	x, err := s.igServer(user, admin, r.URL.Query().Get("id"))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	igHLast.Lock()
	h, ok := igHLast.m[x.ID]
	igHLast.Unlock()
	if !ok {
		writeJSON(w, map[string]int{"at": 0})
		return
	}
	writeJSON(w, h)
}

// POST /api/igproxy/health/run {id} : run the checks now (≈ 10-25 s)
func (s *Server2) igHealthRun(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct{ ID string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, in.ID)
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	res, err := s.app.igHealth(ctx, x)
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, res)
}
