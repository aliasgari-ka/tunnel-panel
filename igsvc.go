package main

// IG Routing · services: the newer services of the igproxy agent (ChatGPT, Claude, Telegram,
// Netflix, GitHub …) with a light live check and an "Auto" exit.
//
// Every 10 minutes each server's users' route (the agent's relay 12370, the same rules the users
// get) opens one small page per service; Cloudflare-fronted ones also say the country they see
// (cdn-cgi/trace loc=). The answer is the ✓ / ⚠ on the page's chip.
//
// Auto (the default of every newer service; the older domain services Spotify, SoundCloud,
// Snapchat, Adult stay on the route a person gave them until someone picks Auto): the panel
// puts the service on its preferred exit (AI: WARP, else a proxy, else the server's own IP;
// the rest: the server's own IP first), and when its check fails twice in a row moves it to
// the next exit, trying the preferred one again after 30 min … 6 h. A pinned exit is never
// moved. Google, Instagram and YouTube Music keep their own guards (igauto.go, gemhome.go);
// nothing here sends Google anywhere, so the hub's users' Google rule (#177) is untouched.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type igSvcDef struct {
	Key, Cat string
	Auto     []string // exit kinds in order of preference: warp, proxy, direct
	URL      string   // the check page ("" = not checked)
	Trace    string   // a Cloudflare host of the service: its /cdn-cgi/trace says the country
	Block    string   // http codes that mean "refused here" (region), "|"-separated
}

var (
	igAutoAI   = []string{"warp", "proxy", "direct"}
	igAutoOwn  = []string{"direct", "warp", "proxy"}
	igSvcStart = []igSvcDef{
		// AI (Gemini is Google's: its own guards)
		{"OPENAI", "ai", igAutoAI, "https://api.openai.com/v1/models", "chatgpt.com", "403"},
		{"CLAUDE", "ai", igAutoAI, "https://api.anthropic.com/v1/models", "claude.ai", "403"},
		{"COPILOT", "ai", igAutoAI, "https://copilot.microsoft.com/", "", ""},
		{"PERPLEX", "ai", igAutoAI, "https://www.perplexity.ai/cdn-cgi/trace", "www.perplexity.ai", ""},
		{"GROK", "ai", igAutoAI, "https://grok.com/cdn-cgi/trace", "grok.com", ""},
		{"AICODE", "ai", igAutoAI, "https://cursor.com/", "", ""},
		// social
		{"X", "social", igAutoOwn, "https://x.com/", "", ""},
		{"TIKTOK", "social", igAutoOwn, "https://www.tiktok.com/", "", ""},
		{"REDDIT", "social", igAutoOwn, "https://www.reddit.com/robots.txt", "", ""},
		{"LINKEDIN", "social", igAutoOwn, "https://www.linkedin.com/robots.txt", "", ""},
		{"PINTEREST", "social", igAutoOwn, "https://www.pinterest.com/robots.txt", "", ""},
		{"SNAP", "social", igAutoOwn, "https://accounts.snapchat.com/", "", ""},
		// messaging
		{"TELEGRAM", "msg", igAutoOwn, "https://web.telegram.org/", "", ""},
		{"WHATSAPP", "msg", igAutoOwn, "https://web.whatsapp.com/", "", ""},
		{"DISCORD", "msg", igAutoOwn, "https://discord.com/api/v9/gateway", "", ""},
		// video, music, games
		{"YTM", "media", nil, "https://music.youtube.com/", "", ""},
		{"SPOTIFY", "media", igAutoOwn, "https://open.spotify.com/", "", ""},
		{"SCLOUD", "media", igAutoOwn, "https://soundcloud.com/", "", ""},
		{"NETFLIX", "media", igAutoOwn, "https://www.netflix.com/", "", ""},
		{"DISNEY", "media", igAutoOwn, "https://www.disneyplus.com/", "", ""},
		{"PRIME", "media", igAutoOwn, "https://www.primevideo.com/", "", ""},
		{"TWITCH", "media", igAutoOwn, "https://www.twitch.tv/", "", ""},
		{"APPLE", "media", igAutoOwn, "https://music.apple.com/", "", ""},
		{"GAMES", "media", igAutoOwn, "https://store.steampowered.com/", "", ""},
		// developer
		{"DEV", "dev", igAutoOwn, "https://github.com/", "", ""},
		// adult (not checked from our servers)
		{"ADULT", "adult", igAutoOwn, "", "", ""},
	}
	igSvcByKey = func() map[string]*igSvcDef {
		m := map[string]*igSvcDef{}
		for i := range igSvcStart {
			m[igSvcStart[i].Key] = &igSvcStart[i]
		}
		return m
	}()
	// the newer services: Auto unless a person pinned one exit
	igSvcNew = map[string]bool{"OPENAI": true, "CLAUDE": true, "COPILOT": true, "PERPLEX": true, "GROK": true, "AICODE": true,
		"X": true, "TIKTOK": true, "REDDIT": true, "LINKEDIN": true, "PINTEREST": true, "TELEGRAM": true, "WHATSAPP": true,
		"DISCORD": true, "NETFLIX": true, "DISNEY": true, "PRIME": true, "TWITCH": true, "APPLE": true, "GAMES": true, "DEV": true}
)

const (
	igSvcEvery    = 10 * time.Minute
	igSvcTick     = 2 * time.Minute
	igSvcLiveMax  = 25 * time.Minute // an older check is not shown
	igSvcBackMin  = 30 * time.Minute
	igSvcBackMax  = 6 * time.Hour
	igSvcBadTimes = 2 // failed checks in a row before Auto moves a service
)

// igSvcLive is the last check of one service of one server (memory only)
type igSvcLive struct {
	OK   bool
	Code string // http code ("000" = no connection)
	CC   string // the country the service sees ("" = unknown)
	At   time.Time
	Bad  int // failed checks in a row
}

var igSvcMem = struct {
	sync.Mutex
	live map[string]map[string]*igSvcLive
	busy map[string]bool
}{live: map[string]map[string]*igSvcLive{}, busy: map[string]bool{}}

// igSvcIsAuto: is this service of this server on Auto (the panel picks its exit)?
func igSvcIsAuto(rec *IgAutoSvc, svc string) bool {
	d := igSvcByKey[svc]
	if d == nil || d.Auto == nil {
		return false
	}
	if rec == nil {
		return igSvcNew[svc]
	}
	if rec.Pin != "" || rec.Off {
		return false
	}
	return igSvcNew[svc] || rec.Auto
}

// igSvcScript: one line "S <KEY> <code> <cc> <flag>" per service, through the users' route (12370).
func igSvcScript(keys []string) string {
	var b strings.Builder
	b.WriteString(`#igsvc
grep -q "^VER=" /usr/local/bin/igproxy 2>/dev/null || { echo __RC=3; exit 0; }
ss -ltn 2>/dev/null | grep -q ':12370 ' || { echo "NORELAY"; exit 0; }
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
X="-x socks5h://127.0.0.1:12370"
d=$(mktemp -d)
p(){ local k=$1 u=$2 t=$3 c r cc f=-
  r=$(curl -s -m 12 -A "$UA" $X -o "$d/$k" -w '%{http_code} %{redirect_url}' "$u" 2>/dev/null); c=${r%% *}
  grep -qs 'unsupported_country\|unavailable-in-region\|not available in your country' "$d/$k" && f=region
  case "${r#* }" in */app-unavailable-in-region*) f=region;; esac
  cc=$(sed -nE 's#.*netflix\.com/([a-z]{2})(-[a-z]{2})?/.*#\1#p' <<<"${r#* }" | tr a-z A-Z)
  [ -n "$t" ] && cc=$(curl -s -m 8 -A "$UA" $X "https://$t/cdn-cgi/trace" 2>/dev/null | sed -n 's/^loc=//p' | head -1)
  echo "S $k ${c:-000} ${cc:--} $f" > "$d/$k.r"; }
`)
	for _, k := range keys {
		d := igSvcByKey[k]
		fmt.Fprintf(&b, "p %s '%s' '%s' &\n", k, d.URL, d.Trace)
	}
	b.WriteString("wait; cat \"$d\"/*.r 2>/dev/null; rm -rf \"$d\"\n")
	return b.String()
}

// igSvcParse reads the check's lines: per service its live state (Bad not set here)
func igSvcParse(lines []string) (map[string]*igSvcLive, bool) {
	out := map[string]*igSvcLive{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "NORELAY" {
			return nil, false
		}
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != "S" || igSvcByKey[f[1]] == nil {
			continue
		}
		d, code, cc := igSvcByKey[f[1]], f[2], f[3]
		if cc == "-" || len(cc) != 2 || cc == "XX" || cc == "T1" {
			cc = ""
		}
		ok := code != "000" && code != "" && !strings.HasPrefix(code, "5")
		if ok && d.Block != "" && contains(strings.Split(d.Block, "|"), code) {
			ok = false
		}
		if len(f) > 4 && f[4] == "region" {
			ok = false
		}
		out[f[1]] = &igSvcLive{OK: ok, Code: code, CC: strings.ToUpper(cc), At: time.Now()}
	}
	return out, true
}

// igSvcCheckKeys: the services checked on this server (the agent must know them)
func igSvcCheckKeys(srv *Server, inf map[string]string) []string {
	var keys []string
	for _, d := range igSvcStart {
		if d.URL == "" {
			continue
		}
		if _, ok := inf[strings.ToLower(d.Key)]; !ok {
			continue
		}
		// the hub's own IP is the Google test account's exit: no Google page from it (YouTube Music on direct)
		if d.Key == "YTM" && gemIsHome(srv) && inf["ytm"] == "direct" {
			continue
		}
		keys = append(keys, d.Key)
	}
	return keys
}

// igSvcCheck checks one server's services and moves the Auto ones that fail; true = look again soon.
func (a *App) igSvcCheck(ctx context.Context, srv *Server) bool {
	igSvcMem.Lock()
	if igSvcMem.busy[srv.ID] {
		igSvcMem.Unlock()
		return false
	}
	igSvcMem.busy[srv.ID] = true
	igSvcMem.Unlock()
	defer func() { igSvcMem.Lock(); delete(igSvcMem.busy, srv.ID); igSvcMem.Unlock() }()

	inf := a.igInfo(ctx, srv)
	switch inf["state"] {
	case "OFFLINE", "NOAGENT", "SUDO", "PAUSED", "DOWN", "CHECKING", "":
		return false
	}
	if inf["ig"] == "" || inf["openai"] == "" { // an agent without the newer services
		return false
	}
	recs := a.igSvcRecs(srv.ID)

	// 1. Auto services not on their exit (new, or the server got / lost WARPs or proxies)
	sets := map[string]string{}
	for _, d := range igSvcStart {
		k := d.Key
		rec := recs[k]
		if !igSvcIsAuto(rec, k) {
			continue
		}
		cands := igSvcCands(d.Auto, inf)
		want := cands[0]
		if rec != nil && rec.Cur != "" && contains(cands, rec.Cur) {
			want = rec.Cur
		}
		if igSvcKind(inf[strings.ToLower(k)]) != want {
			sets[k] = want
		}
	}
	if len(sets) > 0 {
		if err := a.igSvcRoute(ctx, srv, sets); err != nil {
			a.igAutoLog(srv, "SVC", "fail", "Auto: "+err.Error())
			return false
		}
		a.igAutoLog(srv, "SVC", "info", "Auto: "+igSvcSetsWord(sets))
		inf = a.igInfo(ctx, srv)
		time.Sleep(3 * time.Second)
	}

	// 2. the check
	keys := igSvcCheckKeys(srv, inf)
	if len(keys) == 0 {
		return false
	}
	rc, lines, err := a.igShell(ctx, srv, igSvcScript(keys), 60*time.Second)
	if err != nil || rc != 0 {
		return false
	}
	live, relay := igSvcParse(lines)
	if !relay {
		return false
	}
	igSvcMem.Lock()
	m := igSvcMem.live[srv.ID]
	if m == nil {
		m = map[string]*igSvcLive{}
		igSvcMem.live[srv.ID] = m
	}
	bad := map[string]int{}
	for k, l := range live {
		if o := m[k]; o != nil && !l.OK {
			l.Bad = o.Bad + 1
		} else if !l.OK {
			l.Bad = 1
		}
		m[k] = l
		bad[k] = l.Bad
	}
	igSvcMem.Unlock()

	// 3. Auto: a failing service to the next exit; a moved one back to its preferred exit when due
	moves, again := map[string]string{}, false
	now := time.Now()
	for _, d := range igSvcStart {
		k := d.Key
		rec := recs[k]
		if !igSvcIsAuto(rec, k) || live[k] == nil {
			continue
		}
		cands := igSvcCands(d.Auto, inf)
		cur := igSvcKind(inf[strings.ToLower(k)])
		moved := rec != nil && rec.Cur != ""
		if !live[k].OK {
			if bad[k] < igSvcBadTimes {
				again = true
				continue
			}
			next := igSvcNext(cands, cur)
			if next == "" {
				if rec == nil || now.Unix()-rec.Alert > int64(igAutoAlertGap/time.Second) {
					a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Alert = now.Unix() })
					a.igAutoLog(srv, k, "fail", fmt.Sprintf("%s does not open on any exit of this server (http %s)", igSvcName(k), live[k].Code))
				}
				continue
			}
			why := "http " + live[k].Code
			moves[k] = next
			a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) {
				if s.Want == "" {
					s.Want = cands[0]
				}
				back := igSvcBackMin << uint(min(s.Tries, 4))
				if back > igSvcBackMax {
					back = igSvcBackMax
				}
				s.Cur, s.Why, s.Since, s.Next = next, why, now.Unix(), now.Add(back).Unix()
			})
			a.igAutoLog(srv, k, "fix", fmt.Sprintf("%s failed on %s (%s) → %s", igSvcName(k), igRouteWord(cur), why, igRouteWord(next)))
			continue
		}
		if moved && now.Unix() >= rec.Next && cur != cands[0] {
			moves[k] = cands[0]
			a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Cur, s.Why, s.Tries = "", "", s.Tries+1 })
			a.igAutoLog(srv, k, "back", fmt.Sprintf("%s: trying %s again", igSvcName(k), igRouteWord(cands[0])))
			again = true
		} else if moved && cur == cands[0] {
			a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Cur, s.Why, s.Tries = "", "", 0 })
		} else if !moved && rec != nil && rec.Tries > 0 && now.Unix()-rec.Since > int64(igSvcBackMax/time.Second) {
			a.igAutoPut(srv.ID, k, func(s *IgAutoSvc) { s.Tries = 0 })
		}
	}
	if len(moves) > 0 {
		if err := a.igSvcRoute(ctx, srv, moves); err != nil {
			a.igAutoLog(srv, "SVC", "fail", "Auto: "+err.Error())
			return false
		}
		again = true
	}
	return again
}

// igSvcCands: the exits of an Auto service that exist on this server ("direct" is always there)
func igSvcCands(pref []string, inf map[string]string) []string {
	var out []string
	for _, k := range pref {
		switch {
		case k == "warp" && atoiOr(inf["warps"]) > 0, k == "proxy" && atoiOr(inf["proxies"]) > 0, k == "direct":
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		out = []string{"direct"}
	}
	return out
}

// igSvcKind: the agent's route as an Auto exit kind (warp6 = warp, proxyN = proxy)
func igSvcKind(v string) string {
	switch {
	case strings.HasPrefix(v, "warp"):
		return "warp"
	case strings.HasPrefix(v, "proxy"):
		return "proxy"
	}
	return v
}

func igSvcNext(cands []string, cur string) string {
	for i, c := range cands {
		if c == cur && i+1 < len(cands) {
			return cands[i+1]
		}
	}
	if !contains(cands, cur) && len(cands) > 1 {
		return cands[1]
	}
	return ""
}

func igSvcSetsWord(sets map[string]string) string {
	var p []string
	for k, v := range sets {
		p = append(p, igSvcName(k)+" → "+igRouteWord(v))
	}
	sort.Strings(p)
	return strings.Join(p, ", ")
}

// igSvcRoute sets several routes in one go (agent "routeset": one live reload); an agent without
// it gets them one by one.
func (a *App) igSvcRoute(ctx context.Context, srv *Server, sets map[string]string) error {
	keys := make([]string, 0, len(sets))
	for k := range sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := []string{"routeset"}
	for _, k := range keys {
		args = append(args, k+"="+sets[k])
	}
	rc, out := a.igRun(ctx, srv, args, "", 180, nil)
	if rc != 0 && !strings.Contains(out, "must be") && !strings.Contains(out, "there is no") { // an older agent: no routeset
		rc = 0
		for _, k := range keys {
			if r, o := a.igRun(ctx, srv, []string{"route", k, sets[k]}, "", 180, nil); r != 0 {
				rc, out = r, o
			}
		}
	}
	a.igForget(srv.ID)
	if rc != 0 {
		return fmt.Errorf("%s: %s", igSvcSetsWord(sets), clipTo(strings.TrimSpace(out), 160))
	}
	return nil
}

func (a *App) igSvcRecs(id string) map[string]*IgAutoSvc {
	out := map[string]*IgAutoSvc{}
	a.store.View(func(st *State) {
		for k, v := range st.IgAuto[id] {
			c := *v
			out[k] = &c
		}
	})
	return out
}

func (a *App) igSvcLoop() {
	next := map[string]time.Time{}
	time.Sleep(3 * time.Minute) // after a restart: after the page and igauto
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
			if t, ok := next[srv.ID]; ok && now.Before(t) {
				continue
			}
			next[srv.ID] = now.Add(igSvcEvery + time.Duration(i%5)*9*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
			if a.igSvcCheck(ctx, srv) {
				next[srv.ID] = time.Now().Add(igSvcTick)
			}
			cancel()
		}
		time.Sleep(igSvcTick)
	}
}

// ---- what the page gets

type igSvcView struct {
	Mode string `json:"mode"`           // auto | pin | manual
	Pin  string `json:"pin,omitempty"`  // the pinned exit
	Cur  string `json:"cur,omitempty"`  // Auto moved it here (its preferred exit failed)
	Why  string `json:"why,omitempty"`  // why
	OK   string `json:"ok,omitempty"`   // ok | bad ("" = not checked)
	Code string `json:"code,omitempty"` // http code of the check
	CC   string `json:"cc,omitempty"`   // the country the service sees
	At   int64  `json:"at,omitempty"`
}

func (a *App) igSvcViewOf(id string) map[string]igSvcView {
	recs := a.igSvcRecs(id)
	out := map[string]igSvcView{}
	for _, d := range igSvcStart {
		k, rec := d.Key, recs[d.Key]
		v := igSvcView{Mode: "manual"}
		if igSvcIsAuto(rec, k) {
			v.Mode = "auto"
			if rec != nil {
				v.Cur, v.Why = rec.Cur, rec.Why
			}
		} else if rec != nil && rec.Pin != "" {
			v.Mode, v.Pin = "pin", rec.Pin
		}
		out[k] = v
	}
	igSvcMem.Lock()
	for k, l := range igSvcMem.live[id] {
		if time.Since(l.At) > igSvcLiveMax {
			continue
		}
		v := out[k]
		v.OK, v.Code, v.CC, v.At = "bad", l.Code, l.CC, l.At.Unix()
		if l.OK {
			v.OK = "ok"
		}
		out[k] = v
	}
	igSvcMem.Unlock()
	return out
}

// POST /api/igproxy/svc {id, set: {SVC: "auto" | exit}}: several services of one server at once
// (one live reload). Instagram / Google / YouTube Music: "auto" = their own guards, an exit = pinned.
func (s *Server2) igSvcSet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct {
		ID  string
		Set map[string]string
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, in.ID)
	if err == nil && len(in.Set) == 0 {
		err = errors.New("nothing to change")
	}
	sets := map[string]string{}
	for k, v := range in.Set {
		if err != nil {
			break
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch {
		case !contains(igServices, k):
			err = errors.New("unknown service " + k)
		case v == "auto" && k != "IG" && k != "GOOGLE" && k != "YTM" && (igSvcByKey[k] == nil || igSvcByKey[k].Auto == nil):
			err = errors.New(igSvcName(k) + " has no Auto")
		case v != "auto" && !igAutoVia.MatchString(v):
			err = errors.New("unknown exit " + v)
		case v != "auto" && gemHomeRouteBad(x, k, v):
			err = errors.New(gemHomeRefusal)
		}
		in.Set[k] = v
		if v != "auto" {
			sets[k] = v
		}
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 200*time.Second)
	defer cancel()
	if len(sets) > 0 {
		if err := s.app.igSvcRoute(ctx, x, sets); err != nil {
			httpErr(w, 502, err.Error())
			return
		}
	}
	var auto []string
	for k, v := range in.Set {
		if _, ok := igSvcByKey[k]; !ok && k != "IG" && k != "GOOGLE" && k != "YTM" && k != "CUSTOM" {
			continue
		}
		if v == "auto" {
			auto = append(auto, k)
		}
		s.app.igAutoPut(x.ID, k, func(a *IgAutoSvc) {
			if v == "auto" {
				a.Off, a.Pin, a.Auto = false, "", true
				return
			}
			a.Off, a.Auto, a.Pin, a.Want, a.Cur, a.Why, a.Tries, a.Next = false, false, v, v, "", "", 0, 0
		})
	}
	word := igSvcSetsWord(in.Set)
	s.app.igAutoLog(x, "SVC", "info", strings.ReplaceAll(word, "→ auto", "→ Auto")+" (by "+orDash(user)+")")
	go func() { // Auto services get their exit and every chip its check at once
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		if _, ok := in.Set["IG"]; ok {
			s.app.igAutoCheck(ctx, x)
		}
		s.app.igSvcCheck(ctx, x)
	}()
	v := s.app.igAutoViewOf(x.ID)
	writeJSON(w, v)
}
