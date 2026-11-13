package main

// The Proxies tab of IG routing: each server's proxies as data (not the agent's text), a real
// test of each one, adding with a per-server result, and deleting / pinning a proxy by what it
// is rather than by its number (the number shifts when the list changes under the page).
//
// The agent keeps its proxies in /etc/igproxy/proxies, one per line:
//   <http|socks5> <host> <port> <user|-> <password|->
// The panel reads that file on the server itself and sends back everything but the password;
// the page gets the user masked.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	igProxyFile = "/etc/igproxy/proxies"
	igXoutTB    = 12300 // the agent's XOUT_TB: 127.0.0.1:12300+n = Xray outbound n (tests)
)

// ---- one proxy, checked before it reaches the agent

var (
	igHostName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)
	igCred     = regexp.MustCompile(`^[^\s]{1,200}$`)
)

// igDigits turns Persian and Arabic digits into ASCII ones ("۸۰۸۰" -> "8080").
func igDigits(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '۰' && r <= '۹':
			return '0' + (r - '۰')
		case r >= '٠' && r <= '٩':
			return '0' + (r - '٠')
		}
		return r
	}, s)
}

type igProxyIn struct{ Type, Host, Port, User, Pass string }

// line is how the agent stores it ("-" = none).
func (p igProxyIn) line() string {
	u, pw := p.User, p.Pass
	if u == "" {
		u = "-"
	}
	if pw == "" {
		pw = "-"
	}
	return strings.Join([]string{p.Type, p.Host, p.Port, u, pw}, " ")
}

// igProxyNorm checks one proxy and writes it the way the agent reads it. What the agent's own
// parsing got wrong is refused here with the reason:
//   - an IPv6 host without brackets made "http://2001:db8::1:3128" (curl reads the port wrong);
//     it is stored as [2001:db8::1] (curl and Xray both take that)
//   - a user with ":" was split by curl's -U user:pass into another user and password
//   - a password without a user was dropped without a word ("-" user = no login)
//   - a password of just "-" meant "no password"
//   - any type but "socks5" silently became HTTP
func igProxyNorm(t, host, port, user, pass string) (igProxyIn, error) {
	var p igProxyIn
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "http":
		p.Type = "http"
	case "socks5", "socks", "socks5h":
		p.Type = "socks5"
	default:
		return p, errors.New("type: HTTP or SOCKS5 (an HTTPS proxy is not supported)")
	}
	h := strings.TrimSpace(igDigits(host))
	if h == "" {
		return p, errors.New("host is empty")
	}
	if ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")); ip != nil {
		if ip.To4() != nil {
			h = ip.To4().String()
		} else {
			h = "[" + ip.String() + "]"
		}
	} else if len(h) > 253 || !igHostName.MatchString(h) {
		return p, errors.New("host: an IP address or a domain name only (no http://, no :port)")
	}
	p.Host = h
	pn, err := strconv.Atoi(strings.TrimSpace(igDigits(port)))
	if err != nil || pn < 1 || pn > 65535 {
		return p, errors.New("port: a number from 1 to 65535")
	}
	p.Port = strconv.Itoa(pn)
	p.User, p.Pass = strings.TrimSpace(user), pass
	if p.User != "" {
		if !igCred.MatchString(p.User) || strings.Contains(p.User, ":") || p.User == "-" {
			return p, errors.New(`user: no spaces and no ":"`)
		}
	}
	if p.Pass != "" {
		if !igCred.MatchString(p.Pass) || p.Pass == "-" {
			return p, errors.New(`password: no spaces (and not just "-")`)
		}
		if p.User == "" {
			return p, errors.New("a password needs a user")
		}
	}
	return p, nil
}

// ---- what is on a server

type igProxyTest struct {
	OK     bool   `json:"ok"`
	MS     int    `json:"ms,omitempty"` // to Instagram, through the proxy
	IP     string `json:"ip,omitempty"` // the exit IP the internet sees
	Loc    string `json:"loc,omitempty"`
	Google bool   `json:"google"` // Google's generate_204 answered through it
	At     int64  `json:"at"`
}

type igProxyRow struct {
	N       int          `json:"n"`
	Type    string       `json:"type"`
	Host    string       `json:"host"`
	Port    string       `json:"port"`
	User    string       `json:"user,omitempty"` // masked
	Kind    string       `json:"kind"`             // http / socks5 / vless-reality / vmess / trojan / ss / hy2 / xray
	Badge   string       `json:"badge"`            // HTTP, SOCKS5, VLESS·Reality …
	Remark  string       `json:"remark,omitempty"` // an Xray config's name
	Sub     string       `json:"sub,omitempty"`    // the subscription it came from (its id)
	Gone    bool         `json:"gone,omitempty"`   // no longer in that subscription
	Key     string       `json:"key"`
	Twin    string       `json:"twin"`            // the same for two lines with one host, port and user (one HTTP, one SOCKS5)
	Bad     bool         `json:"bad,omitempty"`   // Instagram rejected its IP: out of rotation
	Music   string       `json:"music,omitempty"` // the agent's last music test through it: ok / no / err …
	MusicAt int64        `json:"musicAt,omitempty"`
	Test    *igProxyTest `json:"test,omitempty"`
	user    string       // the real user: never sent
}

func igProxyKey(t, h, p, u string) string {
	s := sha1.Sum([]byte(t + "\x00" + h + "\x00" + p + "\x00" + u))
	return hex.EncodeToString(s[:])[:12]
}

// igMaskUser keeps enough of a user to tell two apart: "nodemaven5Jfgq" -> "node…gq".
func igMaskUser(u string) string {
	if u == "" || u == "-" {
		return ""
	}
	r := []rune(u)
	if len(r) >= 8 {
		return string(r[:4]) + "…" + string(r[len(r)-2:])
	}
	return string(r[:1]) + "…"
}

// the last test of each proxy, per server and proxy key (a test result follows the proxy, not its number)
var igPxTests = struct {
	sync.Mutex
	m map[string]map[string]igProxyTest
}{m: map[string]map[string]igProxyTest{}}

func igPxRemember(srv, key string, t igProxyTest) {
	igPxTests.Lock()
	defer igPxTests.Unlock()
	if igPxTests.m[srv] == nil {
		igPxTests.m[srv] = map[string]igProxyTest{}
	}
	igPxTests.m[srv][key] = t
}

func igPxLast(srv, key string) *igProxyTest {
	igPxTests.Lock()
	defer igPxTests.Unlock()
	if t, ok := igPxTests.m[srv][key]; ok {
		return &t
	}
	return nil
}

// igPxScript reads the proxy file on the server (#igpx-list) and, with test, tests every proxy
// at once (#igpx-test). The password stays on the server: it goes from the file to curl only.
// only: the proxy numbers to test (none = all)
func igPxScript(test bool, only []int) string {
	var on []string
	for _, n := range only {
		if n > 0 {
			on = append(on, strconv.Itoa(n))
		}
	}
	s := `#igpx-list
f=` + igProxyFile + `; R=/run/igproxy
[ -r "$f" ] || { grep -q "^VER=" /usr/local/bin/igproxy 2>/dev/null && echo __RC=0 || echo __RC=3; exit 0; }
n=0
while IFS= read -r l || [ -n "$l" ]; do
  n=$((n+1)); read -r t h p u pw _ <<<"$l"; [ -z "$t" ] && continue
  printf 'P\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$t" "$h" "$p" "${u:--}" "$([ -f "$R/pbad_$n" ] && echo 1 || echo 0)"
  if [ -f "$R/pmus_$n" ] && read -r mt mr _ < "$R/pmus_$n"; then printf 'M\t%s\t%s\t%s\n' "$n" "$mt" "$mr"; fi
done < "$f"
`
	if test {
		s += `#igpx-test
d=$(mktemp -d); n=0; only=" ` + strings.Join(on, " ") + ` "
tst(){ # n type host port user pass
  local s=socks5h hh=$3 pw=$6 a tr ms g; [ "$2" = http ] && s=http; [ "$pw" = - ] && pw=""
  case "$hh" in \[*) ;; *:*) hh="[$hh]";; esac
  a=(-x "$s://$hh:$4"); [ -n "$5" ] && [ "$5" != - ] && a+=(--proxy-user "$5:$pw")
  [ "$2" = xray ] && a=(-x "socks5h://127.0.0.1:$((` + strconv.Itoa(igXoutTB) + `+$1))")   # an Xray outbound: the router's test socket for line n
  tr=$(curl -s -m 10 "${a[@]}" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
  ms=$(curl -s -m 8 "${a[@]}" -o /dev/null -w '%{http_code} %{time_total}' https://i.instagram.com/ 2>/dev/null | awk '$1!="000"{printf "%d",$2*1000}')
  g=$(curl -s -m 8 "${a[@]}" -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 2>/dev/null)
  printf 'T\t%s\t%s\t%s\t%s\t%s\n' "$1" "${ms:--}" "$(sed -n 's/^ip=//p' <<<"$tr")" "$(sed -n 's/^loc=//p' <<<"$tr")" "${g:-000}"
}
while IFS= read -r l || [ -n "$l" ]; do
  n=$((n+1)); read -r t h p u pw _ <<<"$l"; [ -z "$t" ] && continue; [ "$only" = "  " ] || [[ "$only" == *" $n "* ]] || continue
  tst "$n" "$t" "$h" "$p" "${u:--}" "${pw:--}" > "$d/$n" &
done < "$f"
wait; cat "$d"/* 2>/dev/null; rm -rf "$d"
`
	}
	return s + "echo __RC=0\n"
}

// igShell runs a script of the panel's own on the server (not an igproxy command); rc 255 = not reached.
func (a *App) igShell(ctx context.Context, srv *Server, script string, tmo time.Duration) (int, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, tmo)
	defer cancel()
	h, err := a.igHost(ctx, srv)
	if err != nil {
		return 255, nil, err
	}
	rc := 255
	var lines []string
	_, err = h.Run(ctx, script, func(l string) {
		l = igClean(l)
		if strings.HasPrefix(l, "__RC=") {
			rc, _ = strconv.Atoi(strings.TrimPrefix(l, "__RC="))
			return
		}
		lines = append(lines, l)
	})
	if rc == 255 && err == nil {
		err = errors.New("no answer from the server")
	}
	return rc, lines, err
}

// igProxies reads (and with test, tests) a server's proxies.
// only: test just these proxy numbers (none = all)
func (a *App) igProxies(ctx context.Context, srv *Server, test bool, only ...int) ([]*igProxyRow, error) {
	tmo := 40 * time.Second
	if test {
		tmo = 90 * time.Second
	}
	rc, lines, err := a.igShell(ctx, srv, igPxScript(test, only), tmo)
	if rc == 3 {
		return nil, errors.New("igproxy is not installed on this server")
	}
	if rc != 0 {
		if err == nil {
			err = fmt.Errorf("the server answered with code %d", rc)
		}
		return nil, err
	}
	rows := []*igProxyRow{}
	byN := map[int]*igProxyRow{}
	now := time.Now().Unix()
	for _, l := range lines {
		f := strings.Split(l, "\t")
		switch {
		case f[0] == "P" && len(f) >= 7:
			n, _ := strconv.Atoi(f[1])
			u := f[5]
			if u == "-" {
				u = ""
			}
			r :=&igProxyRow{N: n, Type: f[2], Host: f[3], Port: f[4], User: igMaskUser(u), Key: igProxyKey(f[2], f[3], f[4], u), Twin: igProxyKey("", f[3], f[4], u), Bad: f[6] == "1", user: u, Kind: f[2]}
			if f[2] == "xray" { // the 4th field is kind~remark~hash, not a user: shown as the type and name
				r.User = ""
				r.Kind, r.Remark = igOutLabel(u)
				r.Twin = r.Key // two configs to one server are different outbounds
			}
			r.Badge = igOutBadge(r.Kind)
			rows = append(rows, r)
			byN[n] = r
		case f[0] == "M" && len(f) >= 4:
			if r := byN[atoiOr(f[1])]; r != nil {
				r.MusicAt, _ = strconv.ParseInt(f[2], 10, 64)
				r.Music = f[3]
			}
		case f[0] == "T" && len(f) >= 6:
			if r := byN[atoiOr(f[1])]; r != nil {
				t := igProxyTest{IP: f[3], Loc: f[4], Google: f[5] == "204", At: now}
				if ms, err := strconv.Atoi(f[2]); err == nil {
					t.MS, t.OK = ms, true
				}
				if t.IP != "" && !t.OK && t.Google { // Instagram alone didn't answer: the proxy itself works
					t.OK = true
				}
				igPxRemember(srv.ID, r.Key, t)
			}
		}
	}
	for _, r := range rows {
		r.Test = igPxLast(srv.ID, r.Key)
	}
	igOutsRemember(srv.ID, rows)
	return rows, nil
}

func atoiOr(s string) int { n, _ := strconv.Atoi(s); return n }

// ---- HTTP

func (s *Server2) igProxyList(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, igStr(p["srv"]))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	var only []int // "n": one proxy (the row's Test), "ns": "1,3,5" (the selected ones)
	for _, f := range strings.Split(igStr(p["ns"])+","+igStr(p["n"]), ",") {
		if n := atoiOr(strings.TrimSpace(f)); n > 0 {
			only = append(only, n)
		}
	}
	rows, err := s.app.igProxies(r.Context(), x, igStr(p["test"]) != "", only...)
	if err != nil {
		httpErr(w, 502, igLabel(x)+": "+err.Error())
		return
	}
	subs, from, gone := s.app.igSubsFor(user, admin)
	mine := []igSubView{}
	for _, v := range subs {
		if contains(v.Servers, x.ID) {
			v.Gone = 0
			for _, r := range rows {
				if gone[x.ID][r.Key] && from[x.ID][r.Key] == v.ID {
					v.Gone++
				}
			}
			mine = append(mine, v)
		}
	}
	for _, r := range rows {
		r.Sub = from[x.ID][r.Key]
		r.Gone = gone[x.ID][r.Key]
	}
	writeJSON(w, map[string]any{"proxies": rows, "subs": mine, "t": time.Now().Unix()})
}

type igPxResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // added | exists | failed | unreachable
	Msg    string `json:"msg,omitempty"`
	N      int    `json:"n,omitempty"`
	IP     string `json:"ip,omitempty"`
	Loc    string `json:"loc,omitempty"`
	MS     int    `json:"ms,omitempty"`
}

var (
	igPxOK    = regexp.MustCompile(`OK - exit IP (\S*) \(([^)]*)\)\s+(\d+)ms`)
	igPxAdded = regexp.MustCompile(`proxy (\d+) added`)
)

// igProxyAddOne: the agent tests the proxy first and adds it only if it works. A proxy that is
// already there with the same type, host, port and user is not added again (the agent compared
// the whole line, so the same proxy with another password was added twice).
func (a *App) igProxyAddOne(ctx context.Context, x *Server, p igProxyIn) igPxResult {
	res := igPxResult{ID: x.ID, Name: igLabel(x)}
	rows, err := a.igProxies(ctx, x, false)
	if err != nil {
		res.Status, res.Msg = "unreachable", err.Error()
		return res
	}
	key := igProxyKey(p.Type, p.Host, p.Port, p.User)
	for _, r := range rows {
		if r.Key == key {
			res.Status, res.N, res.Msg = "exists", r.N, "already on this server (delete it first to change its password)"
			return res
		}
	}
	rc, out := a.igRun(ctx, x, []string{"proxy", "add", "-"}, p.line(), 120, nil)
	a.igForget(x.ID)
	if m := igPxOK.FindStringSubmatch(out); m != nil {
		res.IP, res.Loc = m[1], m[2]
		res.MS, _ = strconv.Atoi(m[3])
	}
	switch {
	case rc == 255:
		res.Status, res.Msg = "unreachable", strings.TrimSpace(lastLineOf(out))
	case rc != 0:
		res.Status, res.Msg = "failed", igLastErr(out, rc)
	case strings.Contains(out, "already in the list"):
		res.Status, res.Msg = "exists", "already on this server"
	default:
		res.Status = "added"
		if m := igPxAdded.FindStringSubmatch(out); m != nil {
			res.N, _ = strconv.Atoi(m[1])
		}
	}
	if res.IP != "" {
		igPxRemember(x.ID, key, igProxyTest{OK: true, MS: res.MS, IP: res.IP, Loc: res.Loc, Google: true, At: time.Now().Unix()})
	}
	return res
}

// igLastErr: the agent's "!! reason" (or its last line) without the marks.
func igLastErr(out string, rc int) string {
	msg := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "!!") {
			msg = strings.TrimSpace(strings.TrimPrefix(l, "!!"))
		}
	}
	if msg == "" {
		msg = lastLineOf(out)
	}
	if msg == "" {
		msg = fmt.Sprintf("exit code %d", rc)
	}
	return msg
}

func (s *Server2) igProxyAdd(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(igStr(p["text"])) != "" { // Outbounds: links / subscription / JSON / proxies, many at once
		s.igOutAdd(w, r, p)
		return
	}
	px, err := igProxyNorm(igStr(p["type"]), igStr(p["host"]), igStr(p["port"]), igStr(p["user"]), igStr(p["pass"]))
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	tl, err := s.igTargets(user, admin, p["srv"], igStr(p["view"]))
	if err == nil && len(tl) == 0 {
		err = errors.New("no servers")
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	out := make([]igPxResult, len(tl))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, x := range tl {
		wg.Add(1)
		go func(i int, x *Server) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = s.app.igProxyAddOne(ctx, x, px)
		}(i, x)
	}
	wg.Wait()
	n := map[string]int{}
	for _, x := range out {
		n[x.Status]++
	}
	// ok only when every server has it now: "all servers" used to read as done when some failed
	writeJSON(w, map[string]any{"results": out, "ok": n["added"]+n["exists"] == len(out), "added": n["added"], "exists": n["exists"], "failed": n["failed"] + n["unreachable"]})
}

// igProxyFind: the proxy with this key on the server now, whatever its number is by now.
func (a *App) igProxyFind(ctx context.Context, x *Server, key string) (*igProxyRow, error) {
	rows, err := a.igProxies(ctx, x, false)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Key == key {
			return r, nil
		}
	}
	return nil, errors.New("that proxy is no longer on this server (the list changed) - reloaded")
}

// igPxGuard runs an igproxy command about proxy n only while line n is still that proxy:
// "proxy del 2" after another page removed proxy 1 deleted the wrong one.
func igPxGuard(r *igProxyRow, args []string, tmo int) string {
	u := r.user
	if u == "" {
		u = "-"
	}
	q := make([]string, len(args))
	for i, x := range args {
		q[i] = shq(x)
	}
	return fmt.Sprintf(`#igpx-guard n=%d
l=$(sed -n '%dp' %s); read -r t h p u _ <<<"$l"
[ "$t $h $p $u" = %s ] || { echo __CHANGED; echo __RC=0; exit 0; }
timeout %d igproxy %s </dev/null 2>&1; echo "__RC=$?"
`, r.N, r.N, igProxyFile, shq(r.Type+" "+r.Host+" "+r.Port+" "+u), tmo, strings.Join(q, " "))
}

func (s *Server2) igProxyCmd(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, igStr(p["srv"]))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	row, err := s.app.igProxyFind(ctx, x, igStr(p["key"]))
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	var args []string
	tmo := 180
	switch igStr(p["do"]) {
	case "del":
		args = []string{"proxy", "del", strconv.Itoa(row.N)}
	case "use": // only this proxy for one service (Instagram, Google …)
		svc := strings.ToUpper(igStr(p["svc"]))
		if !contains(igServices, svc) {
			httpErr(w, 400, "bad service")
			return
		}
		args = []string{"route", svc, "proxy" + strconv.Itoa(row.N)}
	default:
		httpErr(w, 400, "unknown action")
		return
	}
	rc, lines, err := s.app.igShell(ctx, x, igPxGuard(row, args, tmo), time.Duration(tmo+20)*time.Second)
	s.app.igForget(x.ID)
	for _, l := range lines {
		if l == "__CHANGED" {
			httpErr(w, 409, "the proxy list changed on the server meanwhile - nothing was done, reloaded")
			return
		}
	}
	if rc != 0 {
		msg := igLastErr(strings.Join(lines, "\n"), rc)
		if rc == 255 && err != nil {
			msg = err.Error()
		}
		httpErr(w, 502, msg)
		return
	}
	var said []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			said = append(said, l)
		}
	}
	writeJSON(w, map[string]any{"ok": true, "out": said})
}
