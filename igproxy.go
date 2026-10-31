package main

// IG routing: the igproxy agents on the foreign servers (a private Xray SNI router that sends
// Instagram, Google/Gemini, YouTube Music … out through proxies, Cloudflare WARP or IPv6).
// This used to be a panel of its own (igpanel, port 2083, with its own accounts, server list
// and SSH keys); here every action is still "igproxy <command>" on the server, run over the
// panel's own connection to that server, and the servers, accounts and jobs are the panel's.

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	igAgentFile = "/etc/igpm/igproxy.sh" // the agent script the panel installs (igpm keeps it current)
	igAgentSrc  = "/etc/igpm/src"        // the folder igpm.sh runs from: a newer igproxy.sh there wins
	igLocalBin  = "/usr/local/bin/igproxy"
	igInfoTTL   = 20 * time.Second // a server's "igproxy info" is read again after this
	igInfoWait  = 12 * time.Second // the server list waits this long for the slowest server
)

var igServices = []string{"IG", "GOOGLE", "YTM", "ADULT", "SPOTIFY", "SCLOUD", "CUSTOM"}

var (
	igANSI    = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	igNum     = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)
	igVia     = regexp.MustCompile(`^(proxy|proxy[1-9][0-9]*|warp|warp6|ipv6|direct)$`)
	igHostRx  = regexp.MustCompile(`^[A-Za-z0-9.:_\-\[\]]{1,253}$`)
	igWord    = regexp.MustCompile(`^[A-Za-z0-9._:/\-]{0,80}$`)
	igNoSpace = regexp.MustCompile(`^[^\s]{0,200}$`)
	igPort    = regexp.MustCompile(`^[0-9]{1,5}$`)
	igSite    = regexp.MustCompile(`^[A-Za-z0-9._:/*\-]{1,200}$`)
	igCC      = regexp.MustCompile(`^[A-Z]{2}( [A-Z]{2}){0,60}$`)
	igParts   = regexp.MustCompile(`^(routes|proxies|ig|tg|opts)( (routes|proxies|ig|tg|opts))*$`)
	igBackup  = regexp.MustCompile(`^([A-Za-z0-9]+)-([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6})\.igpx$`)
)

// ---- the agent script

func igIsAgent(b []byte) bool {
	return regexp.MustCompile(`(?m)^VER=`).Match(b) && regexp.MustCompile(`igproxy v[0-9]* \(agent\)`).Match(b)
}

var igAgentMu sync.Mutex

// igAgent returns the agent script to install and its id (first 8 hex of its md5, what
// "igproxy info" reports as sum=). A newer igproxy.sh next to igpm.sh replaces the copy first.
func igAgent() ([]byte, string) {
	igAgentMu.Lock()
	defer igAgentMu.Unlock()
	if src, err := os.ReadFile(igAgentSrc); err == nil && strings.TrimSpace(string(src)) != "" {
		if b, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(src)), "igproxy.sh")); err == nil && igIsAgent(b) {
			b = bytes.ReplaceAll(b, []byte("\r"), nil)
			if old, _ := os.ReadFile(igAgentFile); !bytes.Equal(old, b) {
				_ = writeFileAtomic(igAgentFile, b, 0o600)
			}
		}
	}
	b, err := os.ReadFile(igAgentFile)
	if err != nil || !igIsAgent(b) {
		if lb, err := os.ReadFile(igLocalBin); err == nil && igIsAgent(lb) {
			_ = os.MkdirAll(filepath.Dir(igAgentFile), 0o700)
			_ = writeFileAtomic(igAgentFile, lb, 0o600)
			b = lb
		} else {
			return nil, ""
		}
	}
	sum := md5.Sum(b)
	return b, hex.EncodeToString(sum[:])[:8]
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- running igproxy on a server

// isPanelHost: the server is this panel's own machine.
func (a *App) isPanelHost(srv *Server) bool {
	set := a.settings()
	for _, x := range []string{srv.IPv4, srv.IPv6, srv.SSHHost} {
		if x == "" {
			continue
		}
		if x == set.LocalIPv4 || x == set.LocalIPv6 {
			return true
		}
		if ip := net.ParseIP(strings.Trim(x, "[]")); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
			return true
		}
	}
	return false
}

// igHost is how igproxy commands reach a server: the panel host itself runs them locally,
// but only for the admin's server — a user's server that points at the panel host would hand
// that user root commands on the panel machine.
func (a *App) igHost(ctx context.Context, srv *Server) (Host, error) {
	if a.hostFor != nil {
		if h := a.hostFor(srv); h != nil {
			return h, nil
		}
	}
	if a.isPanelHost(srv) {
		if srv.Owner != "" {
			return nil, errors.New("this address is the panel server itself")
		}
		return LocalHost{}, nil
	}
	h, _, err := a.reach(ctx, srv, nil)
	return h, err
}

// igScript is the shell that runs one igproxy command: input (if any) arrives on its stdin —
// never in a process argument — and the exit code comes back as the last line.
func igScript(args []string, input string, tmo int) string {
	q := make([]string, len(args))
	for i, x := range args {
		q[i] = shq(x)
	}
	feed := "</dev/null"
	if input != "" {
		feed = ""
	}
	cmd := fmt.Sprintf("timeout %d igproxy %s %s", tmo, strings.Join(q, " "), feed)
	if input != "" {
		cmd = fmt.Sprintf("printf '%%s\\n' %s | %s", shq(strings.TrimRight(input, "\n")), cmd)
	}
	return `grep -q "^VER=" /usr/local/bin/igproxy 2>/dev/null || { echo "igproxy is not installed here (missing, or the old v5) -> Install / update"; echo __RC=3; exit 0; }
` + cmd + `
echo "__RC=$?"
`
}

// igClean turns raw output into what a person reads: no colour codes, and of a line redrawn
// with \r (progress) only its last state.
func igClean(l string) string {
	l = igANSI.ReplaceAllString(l, "")
	if strings.Contains(l, "\r") {
		parts := strings.Split(l, "\r")
		l = ""
		for i := len(parts) - 1; i >= 0; i-- {
			if parts[i] != "" {
				l = parts[i]
				break
			}
		}
	}
	return l
}

// igRun runs "igproxy args…" on srv; out gets each output line. rc 255 = never reached it.
func (a *App) igRun(ctx context.Context, srv *Server, args []string, input string, tmo int, out func(string)) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(tmo+25)*time.Second)
	defer cancel()
	h, err := a.igHost(ctx, srv)
	if err != nil {
		if out != nil {
			out("!! " + err.Error())
		}
		return 255, err.Error()
	}
	rc := 255
	var buf strings.Builder
	_, err = h.Run(ctx, igScript(args, input, tmo), func(l string) {
		l = igClean(l)
		if strings.HasPrefix(l, "__RC=") {
			rc, _ = strconv.Atoi(strings.TrimPrefix(l, "__RC="))
			return
		}
		buf.WriteString(l + "\n")
		if out != nil {
			out(l)
		}
	})
	if rc == 255 && err != nil {
		buf.WriteString(err.Error())
		if out != nil {
			out("!! " + err.Error())
		}
	}
	return rc, buf.String()
}

// ---- state of a server ("igproxy info": one line of key=value)

func igParseInfo(rc int, text, agentSum string) map[string]string {
	S := map[string]string{"rc": strconv.Itoa(rc)}
	t := strings.TrimSpace(text)
	if i := strings.LastIndex(t, "\n"); i >= 0 && rc != 255 {
		t = t[i+1:]
	}
	if rc != 255 {
		for _, kv := range strings.Fields(t) {
			if k, v, ok := strings.Cut(kv, "="); ok {
				S[k] = v
			}
		}
	}
	var st string
	switch _, ig := S["ig"]; {
	case ig && agentSum != "" && S["sum"] != agentSum:
		st = "UPDATE"
	case ig && S["paused"] == "YES":
		st = "PAUSED"
	case ig && (S["router"] != "active" || S["redirect"] != "ON"):
		st = "DOWN"
	case ig && (S["panel"] == "BLOCK" || S["panel"] == "AWAY" || S["panel"] == "MARK" || S["panel"] == "V6" || S["panel"] == "SOME"):
		st = "PANEL"
	case ig && S["gem"] == "FAIL":
		st = "GEMFAIL"
	case ig && S["igp"] == "FAIL":
		st = "IGFAIL"
	case ig:
		st = "OK"
	case rc == 3:
		st = "NOAGENT"
	case rc == 1:
		st = "UPDATE"
	case strings.Contains(strings.ToLower(text), "sudo") && strings.Contains(strings.ToLower(text), "password"):
		st = "SUDO"
	default:
		st = "OFFLINE"
		e := strings.TrimSpace(text)
		if len(e) > 300 {
			e = e[len(e)-300:]
		}
		S["err"] = e
	}
	S["state"] = st
	return S
}

type igEntry struct {
	info map[string]string
	at   time.Time
}

// igCache keeps each server's last info; one read per server at a time, however many pages ask.
type igCache struct {
	mu       sync.Mutex
	m        map[string]igEntry
	inflight map[string]chan struct{}
}

func (a *App) igInfo(ctx context.Context, srv *Server) map[string]string {
	_, sum := igAgent()
	rc, out := a.igRun(ctx, srv, []string{"info"}, "", 20, nil)
	inf := igParseInfo(rc, out, sum)
	a.ig.mu.Lock()
	if a.ig.m == nil {
		a.ig.m = map[string]igEntry{}
	}
	a.ig.m[srv.ID] = igEntry{inf, time.Now()}
	a.ig.mu.Unlock()
	return inf
}

// igInfos returns the info of every server: fresh ones from the cache, the rest read at once.
// A server still not answering after igInfoWait shows its last known info (or CHECKING): one
// unreachable server held the old panel's whole page for half a minute. Its read goes on and
// fills the cache for the page's next look.
func (a *App) igInfos(list []*Server, fresh bool) map[string]map[string]string {
	res := map[string]map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range list {
		a.ig.mu.Lock()
		if a.ig.m == nil {
			a.ig.m = map[string]igEntry{}
		}
		if a.ig.inflight == nil {
			a.ig.inflight = map[string]chan struct{}{}
		}
		e, ok := a.ig.m[s.ID]
		if ok && !fresh && time.Since(e.at) < igInfoTTL {
			res[s.ID] = e.info
			a.ig.mu.Unlock()
			continue
		}
		ch, running := a.ig.inflight[s.ID]
		if !running {
			ch = make(chan struct{})
			a.ig.inflight[s.ID] = ch
			go func(s *Server, ch chan struct{}) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				a.igInfo(ctx, s)
				a.ig.mu.Lock()
				delete(a.ig.inflight, s.ID)
				a.ig.mu.Unlock()
				close(ch)
			}(s, ch)
		}
		a.ig.mu.Unlock()
		wg.Add(1)
		go func(s *Server, ch chan struct{}, old igEntry, had bool) {
			defer wg.Done()
			select {
			case <-ch:
				a.ig.mu.Lock()
				inf := a.ig.m[s.ID].info
				a.ig.mu.Unlock()
				mu.Lock()
				res[s.ID] = inf
				mu.Unlock()
			case <-time.After(igInfoWait):
				inf := map[string]string{"state": "CHECKING"}
				if had {
					inf = old.info
				}
				mu.Lock()
				res[s.ID] = inf
				mu.Unlock()
			}
		}(s, ch, e, ok)
	}
	wg.Wait()
	return res
}

func (a *App) igForget(id string) {
	a.ig.mu.Lock()
	delete(a.ig.m, id)
	a.ig.mu.Unlock()
}

// ---- actions: a whitelist that becomes igproxy arguments

type igCmd struct {
	title string
	args  []string
	input string
	tmo   int
}

func igNeed(v any, rx *regexp.Regexp, what string) (string, error) {
	s := strings.TrimSpace(igStr(v))
	if !rx.MatchString(s) {
		return "", fmt.Errorf("bad %s: %q", what, s)
	}
	return s, nil
}

func igStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "1"
		}
		return ""
	}
	return fmt.Sprint(v)
}

func igBuild(a string, p map[string]any) (igCmd, error) {
	g := func(k string) string { return strings.TrimSpace(igStr(p[k])) }
	switch a {
	case "route":
		svc := strings.ToUpper(g("svc"))
		if svc != "ALL" && !contains(igServices, svc) {
			return igCmd{}, errors.New("bad service")
		}
		via, err := igNeed(p["via"], igVia, "route")
		if err != nil {
			return igCmd{}, err
		}
		return igCmd{"route " + svc + " -> " + via, []string{"route", svc, via}, "", 180}, nil
	case "proxy_add":
		t := "http"
		if g("type") == "socks5" {
			t = "socks5"
		}
		host, err := igNeed(p["host"], igHostRx, "host")
		if err != nil {
			return igCmd{}, err
		}
		port, err := igNeed(p["port"], igPort, "port")
		if err != nil {
			return igCmd{}, err
		}
		user, pass := g("user"), igStr(p["pass"])
		if user == "" {
			user = "-"
		}
		if pass == "" {
			pass = "-"
		}
		if !igNoSpace.MatchString(user) || !igNoSpace.MatchString(pass) {
			return igCmd{}, errors.New("user and password can't have spaces")
		}
		return igCmd{"add proxy", []string{"proxy", "add", "-"}, strings.Join([]string{t, host, port, user, pass}, " "), 120}, nil
	case "custom_add":
		r := g("route")
		if r != "" && !regexp.MustCompile(`^(proxy|proxy[1-9][0-9]*|warp|direct)$`).MatchString(r) {
			return igCmd{}, errors.New("bad route")
		}
		site, err := igNeed(p["site"], igSite, "site")
		if err != nil {
			return igCmd{}, err
		}
		args := []string{"custom", "add", site}
		if r != "" {
			args = append(args, r)
		}
		return igCmd{"add site " + site, args, "", 120}, nil
	case "set":
		k := g("key")
		if k == "gcountries" { // Google's allowed WARP countries (ISO codes)
			v := strings.ToUpper(strings.Join(strings.FieldsFunc(g("val"), func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }), " "))
			if !igCC.MatchString(v) {
				return igCmd{}, errors.New("country list: two-letter codes with spaces, like US GB DE")
			}
			return igCmd{"Google countries: " + v, []string{"set", "gcountries", v}, "", 120}, nil
		}
		v := strings.ToLower(g("val"))
		var rx *regexp.Regexp
		switch k {
		case "gwarps":
			rx = regexp.MustCompile(`^[0-9]$`)
		case "minspeed", "minwarps", "grotate", "musiccheck":
			rx = regexp.MustCompile(`^[0-9]{1,5}$`)
		case "autokey", "geosite", "gspread", "warpauto", "gall", "guard":
			rx = regexp.MustCompile(`^(on|off|toggle)$`)
		case "mode":
			rx = regexp.MustCompile(`^(balance|failover|toggle)$`)
		default:
			return igCmd{}, errors.New("bad setting")
		}
		if !rx.MatchString(v) {
			return igCmd{}, fmt.Errorf("bad value for %s: %q", k, v)
		}
		return igCmd{"set " + k + " " + v, []string{"set", k, v}, "", 180}, nil
	case "speedtest":
		t := g("target")
		if t == "" {
			t = "all"
		}
		if !regexp.MustCompile(`^(all|d|6|p[0-9]+|w[0-9]+)$`).MatchString(t) {
			return igCmd{}, errors.New("bad target")
		}
		return igCmd{"speed test", []string{"speedtest", t}, "", 600}, nil
	case "recent", "watch":
		w, err := igNeed(p["word"], igWord, "filter")
		if err != nil {
			return igCmd{}, err
		}
		c := igCmd{"last connections", []string{a}, "", 30}
		if a == "watch" {
			c = igCmd{"live traffic (60 s)", []string{a}, "", 60}
		}
		if w != "" {
			c.args = append(c.args, w)
		}
		return c, nil
	case "logs", "gemusers":
		def, what, title := "80", "lines", "logs"
		if a == "gemusers" {
			def, what, title = "10", "minutes", "Gemini users"
		}
		n := g("n")
		if n == "" {
			n = def
		}
		if !igNum.MatchString(n) {
			return igCmd{}, fmt.Errorf("bad %s", what)
		}
		return igCmd{title, []string{a, n}, "", 30}, nil
	case "google_use": // Google-only pin (Instagram stays where it is)
		n, err := igNeed(p["n"], igNum, "number")
		if err != nil {
			return igCmd{}, err
		}
		return igCmd{"Google -> WARP " + n, []string{"google", "use", n}, "", 120}, nil
	case "proxy_del", "warp_del", "warp_use", "custom_del":
		n, err := igNeed(p["n"], igNum, "number")
		if err != nil {
			return igCmd{}, err
		}
		x := strings.SplitN(a, "_", 2)
		return igCmd{x[0] + " " + x[1] + " " + n, []string{x[0], x[1], n}, "", 300}, nil
	case "ig_session":
		sid, err := igNeed(p["sid"], regexp.MustCompile(`^[^\s]{1,200}$`), "sessionid")
		if err != nil {
			return igCmd{}, err
		}
		return igCmd{"Instagram test account", []string{"ig", "session", "-"}, sid, 180}, nil
	case "gemkey_set":
		k, err := igNeed(p["key"], regexp.MustCompile(`^[A-Za-z0-9._-]{30,200}$`), "API key")
		if err != nil {
			return igCmd{}, err
		}
		return igCmd{"Gemini API key", []string{"gemkey", "set", "-"}, k, 120}, nil
	case "tg_setup":
		t, err := igNeed(p["token"], regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{20,}$`), "token")
		if err != nil {
			return igCmd{}, err
		}
		return igCmd{"Telegram bot setup (send /start to the bot now)", []string{"tg", "setup"}, t, 120}, nil
	}
	fixed := map[string]igCmd{
		"status": {"full test", []string{"status"}, "", 300}, "status_short": {"short test", []string{"status-short"}, "", 300},
		"proxy_list": {"proxies", []string{"proxy", "list"}, "", 120}, "warp_list": {"WARP (tested)", []string{"warp", "list"}, "", 180},
		"warp_ls": {"WARP", []string{"warp", "ls"}, "", 30}, "warp_add": {"add WARP", []string{"warp", "add"}, "", 600},
		"custom_list": {"my sites", []string{"custom", "list"}, "", 30}, "routes": {"routes", []string{"route"}, "", 30},
		"google_rotate":    {"Google -> fresh WARP IP", []string{"google", "rotate"}, "", 300},
		"google_countries": {"countries per WARP", []string{"google", "countries"}, "", 120},
		"panel_check":      {"panel check", []string{"panel", "check"}, "", 60}, "panel_fix": {"panel fix", []string{"panel", "fix"}, "", 180},
		"panel_undo": {"panel undo", []string{"panel", "undo"}, "", 180}, "diag": {"diagnose Gemini / Google", []string{"diag"}, "", 300},
		"apply": {"re-apply", []string{"apply"}, "", 180}, "pause": {"stop (everything DIRECT)", []string{"stop"}, "", 60},
		"settings": {"settings", []string{"settings"}, "", 60}, "ig_test": {"music test", []string{"ig", "test"}, "", 300},
		"ig_del": {"remove test account", []string{"ig", "del"}, "", 30}, "gemkey_test": {"Gemini API test", []string{"gemkey", "test"}, "", 300},
		"gemkey_del": {"remove Gemini key", []string{"gemkey", "del"}, "", 30}, "tg_test": {"Telegram test", []string{"tg", "test"}, "", 120},
		"tg_del": {"remove Telegram bot", []string{"tg", "del"}, "", 30}, "uninstall": {"UNINSTALL igproxy", []string{"uninstall"}, "", 120},
	}
	if c, ok := fixed[a]; ok {
		return c, nil
	}
	return igCmd{}, errors.New("unknown action")
}

// ---- jobs: each action runs in the background as one of the panel's jobs

func (a *App) igJob(owner, title string, tmo time.Duration, fn func(ctx context.Context, out func(string)) bool) (string, error) {
	j, err := a.jobs.start("", "igproxy")
	if err != nil {
		return "", err
	}
	j.Owner = owner
	j.Kind = "igproxy: " + title
	go func() {
		ctx, cancel := j.context(tmo)
		defer cancel()
		ok := fn(ctx, func(l string) { j.log("%s", l) })
		if ok {
			j.finish("ok")
		} else {
			j.finish("error")
		}
	}()
	return j.ID, nil
}

func igLabel(s *Server) string {
	if s.Owner == "" {
		return s.Name
	}
	return s.Name + " (" + s.Owner + ")"
}

// igDeploy installs / updates the agent on one server.
func (a *App) igDeploy(ctx context.Context, srv *Server, out func(string)) bool {
	data, sum := igAgent()
	if data == nil {
		out("!! no agent script on the panel host (" + igAgentFile + ") - put igproxy.sh next to igpm.sh")
		return false
	}
	out(fmt.Sprintf("-> %s: installing / updating igproxy (%s) ...", srv.Name, sum))
	h, err := a.igHost(ctx, srv)
	if err != nil {
		out("!! " + err.Error())
		return false
	}
	const tmp = "/tmp/igproxy-install.sh"
	if err := h.WriteFile(tmp, data, 0o600); err != nil {
		out("!! copy failed: " + err.Error())
		return false
	}
	ictx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	_, _ = h.Run(ictx, "bash "+tmp+" install </dev/null; rc=$?; rm -f "+tmp+"; exit $rc", func(l string) { out(igClean(l)) })
	cancel()
	inf := a.igInfo(ctx, srv)
	if inf["sum"] == sum {
		out(fmt.Sprintf("OK - %s runs the new agent (%s)", srv.Name, sum))
		return true
	}
	out(fmt.Sprintf("!! %s still does not run the new agent (see above)", srv.Name))
	return false
}

// ---- backups (one folder per account; 10 per server; WARP accounts are never in them)

func igBackupDir(owner string) string {
	if owner == "" {
		owner = "_admin"
	}
	return filepath.Join(dataDir, "igproxy-backup", owner)
}

type igBackupFile struct {
	File   string `json:"file"`
	Owner  string `json:"owner"`
	Server string `json:"server"`
	T      int64  `json:"t"`
}

func igBackups(owners []string) []igBackupFile {
	var out []igBackupFile
	for _, o := range owners {
		ents, _ := os.ReadDir(igBackupDir(o))
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".igpx") {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			b := igBackupFile{File: e.Name(), Owner: o, T: fi.ModTime().Unix()}
			if m := igBackup.FindStringSubmatch(e.Name()); m != nil {
				b.Server = m[1]
			}
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T > out[j].T })
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

func igSaveBackup(srv *Server, data string) (string, error) {
	dir := igBackupDir(srv.Owner)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := srv.ID + "-" + time.Now().Format("2006-01-02-150405") + ".igpx"
	if err := writeFileAtomic(filepath.Join(dir, name), []byte(data+"\n"), 0o600); err != nil {
		return "", err
	}
	old, _ := filepath.Glob(filepath.Join(dir, srv.ID+"-*.igpx"))
	sort.Sort(sort.Reverse(sort.StringSlice(old))) // the stamp sorts by time
	for _, f := range old[min(len(old), 10):] {
		_ = os.Remove(f)
	}
	return name, nil
}

// ---- the old igpanel's data, read once

// where the old igpanel kept its accounts' server lists and backups (tests point them elsewhere)
var igpmDir, igpanelUsers = "/etc/igpm", "/etc/igpanel/users"

// igImport marks the servers the old igpanel (and igpm) managed and brings their backups
// over: admin's list /etc/igpm/servers, each account's /etc/igpanel/users/<name>/servers.
// A line is matched to a panel server of the same account by address; "local" is the
// panel host.
func (a *App) igImport() {
	done := false
	a.store.View(func(st *State) { done = st.IgproxyImported })
	if done {
		return
	}
	type list struct{ owner, base string }
	lists := []list{{"", igpmDir}}
	if ents, err := os.ReadDir(igpanelUsers); err == nil {
		for _, e := range ents {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				lists = append(lists, list{e.Name(), filepath.Join(igpanelUsers, e.Name())})
			}
		}
	}
	if _, err := os.Stat(filepath.Join(lists[0].base, "servers")); err != nil && len(lists) == 1 {
		_ = a.store.Update(func(st *State) error { st.IgproxyImported = true; return nil })
		return
	}
	set := a.settings()
	moves := map[string]string{} // old backup tag -> panel server id
	_ = a.store.Update(func(st *State) error {
		for _, l := range lists {
			oldOwner := l.owner
			if oldOwner == "" {
				oldOwner = "admin"
			}
			b, err := os.ReadFile(filepath.Join(l.base, "servers"))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				f := strings.Fields(line)
				if len(f) < 4 {
					continue
				}
				host := f[1]
				var hit *Server
				for _, x := range st.Servers {
					if x.Owner != l.owner {
						continue
					}
					if host == "local" {
						if l.owner == "" && x.IPv4 != "" && x.IPv4 == set.LocalIPv4 {
							hit = x
						}
					} else if host == x.IPv4 || host == x.IPv6 || host == x.SSHHost {
						hit = x
					}
					if hit != nil {
						break
					}
				}
				if hit == nil {
					log.Printf("igproxy import: %s (%s of %s) has no panel server - add it under Servers", f[0], host, oldOwner)
					continue
				}
				hit.Igproxy = true
				tag := sha1.Sum([]byte(host + ":" + f[2] + ":" + f[3]))
				moves[l.base+"|"+hex.EncodeToString(tag[:])[:10]] = hit.ID
				log.Printf("igproxy import: %s (%s) -> %s", f[0], oldOwner, hit.Name)
			}
		}
		st.IgproxyImported = true
		return nil
	})
	// backups: <name>-<tag>-<stamp>.igpx -> <server id>-<stamp>.igpx in the account's folder
	old := regexp.MustCompile(`-([0-9a-f]{10})-([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6})\.igpx$`)
	for _, l := range lists {
		files, _ := filepath.Glob(filepath.Join(l.base, "backup", "*.igpx"))
		for _, f := range files {
			m := old.FindStringSubmatch(f)
			if m == nil {
				continue
			}
			id, ok := moves[l.base+"|"+m[1]]
			if !ok {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			dir := igBackupDir(l.owner)
			_ = os.MkdirAll(dir, 0o700)
			dst := filepath.Join(dir, id+"-"+m[2]+".igpx")
			if err := os.WriteFile(dst, b, 0o600); err == nil {
				if fi, err := os.Stat(f); err == nil {
					_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
				}
			}
		}
	}
}
