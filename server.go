package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Server2 struct {
	app      *App
	failMu   sync.Mutex
	failures map[string][]time.Time // ip -> recent failed logins
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	s := &Server2{app: a, failures: map[string][]time.Time{}}

	root := webRoot()
	fileSrv := http.FileServer(http.FS(root))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			if _, err := fs.Stat(root, strings.TrimPrefix(r.URL.Path, "/")); err == nil {
				// always revalidate: after an update the browser must not keep an old app.js
				w.Header().Set("Cache-Control", "no-cache")
				fileSrv.ServeHTTP(w, r)
				return
			}
		}
		serveFile(w, root, "index.html", "text/html; charset=utf-8")
	})

	mux.HandleFunc("/api/setup-state", s.setupState)
	mux.HandleFunc("/api/register", s.json(s.register))
	mux.HandleFunc("/api/login", s.json(s.login))
	mux.HandleFunc("/api/logout", s.json(s.logout))

	// g: signed in + JSON + the account may touch what the request names (see access.go).
	// Only these answer a GET (they only read, or read on GET and change on POST); the rest
	// act, so they take POST alone: the session cookie is SameSite=Lax and rides along on a
	// link someone else made, so a GET that acts was one click from running for them (a link
	// to /api/repair started a repair).
	reads := map[string]bool{"/api/me": true, "/api/mybot": true, "/api/settings": true, "/api/methods": true,
		"/api/servers": true, "/api/tunnels": true, "/api/tunnels/status": true, "/api/tunnels/lastjob": true,
		"/api/traffic": true, "/api/jobs": true, "/api/bench/results": true, "/api/bench/active": true,
		"/api/bench/history": true, "/api/routes/skip": true, "/api/outages": true, "/api/backup": true,
		"/api/helpers": true, "/api/users": true, "/api/owner": true, "/api/domain": true,
		"/api/igproxy/servers": true, "/api/igproxy/info": true, "/api/igproxy/backups": true}
	g := func(path, kind string, h http.HandlerFunc) {
		if !reads[path] {
			h = postOnly(h)
		}
		mux.HandleFunc(path, s.auth(s.json(s.guard(kind, h))))
	}
	g("/api/me", "self", s.me)
	g("/api/password", "self", s.password)
	g("/api/mybot", "self", s.myBot)
	g("/api/settings", "self", s.settings) // GET: what a user needs; POST: admin (in the handler)
	g("/api/methods", "self", s.listMethods)
	g("/api/servers", "self", s.servers)
	g("/api/servers/test", "server", s.serverTest)
	g("/api/servers/delete", "server", s.serverDelete)
	g("/api/servers/agent", "server", s.serverAgent)
	g("/api/servers/resetkey", "server", s.serverResetKey)
	g("/api/servers/bridge", "admin", s.serverBridge) // opens a port on the panel host
	g("/api/servers/optimize", "server", s.serverOptimize)
	g("/api/servers/prepare", "server", s.serverPrepare)
	g("/api/tunnels", "self", s.tunnels)
	g("/api/tunnels/save", "self", s.tunnelSave)
	g("/api/tunnels/delete", "tunnel", s.tunnelDelete)
	g("/api/tunnels/apply", "tunnel", s.tunnelApply)
	g("/api/tunnels/stop", "tunnel", s.tunnelStop)
	g("/api/tunnels/status", "tunnel", s.tunnelStatus)
	g("/api/tunnels/lastjob", "tunnel", s.tunnelLastJob)
	g("/api/tunnels/speedtest", "tunnel", s.tunnelSpeedTest)
	g("/api/tunnels/diagnose", "tunnel", s.tunnelDiagnose)
	g("/api/tunnels/trace", "tunnel", s.tunnelTrace)
	g("/api/tunnels/hsmode", "tunnel", s.tunnelHSMode)
	g("/api/tunnels/hspin", "tunnel", s.tunnelHSPin)
	g("/api/traffic", "self", s.trafficGet)
	g("/api/jobs", "job", s.job)
	g("/api/jobs/cancel", "job", s.jobCancel)
	g("/api/bench/start", "pair", s.benchStart)
	g("/api/bench/results", "pair", s.benchResults)
	g("/api/bench/active", "self", s.benchActive)
	g("/api/bench/history", "self", s.benchHistory)
	g("/api/routes/skip", "self", s.routeSkip)
	g("/api/repair", "admin", s.repair)
	g("/api/outages", "admin", s.outages)
	g("/api/backup", "admin", s.backup)
	g("/api/helpers", "self", s.helpers) // read-only list
	// multipart, not JSON
	mux.HandleFunc("/api/helpers/upload", s.auth(s.guard("admin", s.helperUpload)))
	g("/api/helpers/fetch", "admin", s.helperFetch)
	g("/api/users", "admin", s.users)
	g("/api/users/delete", "admin", s.userDelete)
	g("/api/owner", "admin", s.owner)
	g("/api/domain", "admin", s.domain)
	// IG routing (igproxy.go): each handler keeps an account to its own servers
	g("/api/igproxy/servers", "self", s.igServers)
	g("/api/igproxy/info", "self", s.igInfoGet)
	g("/api/igproxy/action", "self", s.igAction)
	g("/api/igproxy/enable", "self", s.igEnable)
	g("/api/igproxy/copy", "self", s.igCopy)
	g("/api/igproxy/backup", "self", s.igBackupRun)
	g("/api/igproxy/backups", "self", s.igBackupList)
	g("/api/igproxy/restore", "self", s.igRestore)
	return securityHeaders(mux)
}

// postOnly refuses anything but POST (see the reads list above).
func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			httpErr(w, 405, "this action takes POST")
			return
		}
		h(w, r)
	}
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// a second line behind esc(): even a missed escape can't run script in a page that
		// can run commands as root on every server (inline styles are used, inline scripts not)
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func serveFile(w http.ResponseWriter, root fs.FS, name, ct string) {
	b, err := fs.ReadFile(root, name)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	// cache-bust the script per build, so a new version is picked up without a hard refresh
	b = bytes.ReplaceAll(b, []byte(`src="/app.js"`), []byte(`src="/app.js?v=`+version+`"`))
	_, _ = w.Write(b)
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// json rejects state-changing requests that are not application/json. Browsers cannot
// send that content type cross-site without a CORS preflight, which closes form-based CSRF.
func (s *Server2) json(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			httpErr(w, 415, "expected application/json")
			return
		}
		h(w, r)
	}
}

// ---- sessions (HMAC cookie) ----

func (s *Server2) sign(user string, exp int64) string {
	var secret string
	gen := 0
	s.app.store.View(func(st *State) {
		secret = st.Secret
		for _, u := range st.Users {
			if u.Username == user {
				gen = u.Gen
			}
		}
	})
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s|%d|%d", user, exp, gen)
	return hex.EncodeToString(mac.Sum(nil))
}

// bumpGen ends every session of user issued so far.
func (s *Server2) bumpGen(st *State, user string) {
	for i := range st.Users {
		if st.Users[i].Username == user {
			st.Users[i].Gen++
		}
	}
}

// cookieSecure: the panel runs with a trusted certificate (Let's Encrypt), so the session
// cookie can be Secure. Not with a self-signed one: browsers then refuse to store it.
var cookieSecure bool

func (s *Server2) setCookie(w http.ResponseWriter, r *http.Request, user string) {
	exp := time.Now().Add(72 * time.Hour).Unix()
	// base64url the payload so the cookie value has no '|' or other bytes that some
	// browsers/proxies mangle (that was the login-loop bug on some setups).
	raw := fmt.Sprintf("%s|%d|%s", user, exp, s.sign(user, exp))
	val := base64.RawURLEncoding.EncodeToString([]byte(raw))
	// Deliberately NOT setting Secure: browsers refuse to store a Secure cookie on a
	// self-signed-HTTPS origin (shown as "Not secure"), which caused a login loop. The
	// cookie is still HttpOnly + SameSite=Lax; use --ip-ssl/--domain for a trusted cert.
	http.SetCookie(w, &http.Cookie{Name: "tp_session", Value: val, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 72 * 3600, Secure: cookieSecure && r.TLS != nil})
}

func (s *Server2) currentUser(r *http.Request) string {
	c, err := r.Cookie("tp_session")
	if err != nil {
		return ""
	}
	dec, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(dec), "|", 3)
	if len(parts) != 3 {
		return ""
	}
	exp, _ := strconv.ParseInt(parts[1], 10, 64)
	if time.Now().Unix() > exp {
		return ""
	}
	if !hmac.Equal([]byte(parts[2]), []byte(s.sign(parts[0], exp))) {
		return ""
	}
	known := false
	s.app.store.View(func(st *State) {
		for _, u := range st.Users {
			if u.Username == parts[0] {
				known = true
			}
		}
	})
	if !known {
		return ""
	}
	return parts[0]
}

func (s *Server2) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.currentUser(r) == "" {
			httpErr(w, 401, "unauthorized")
			return
		}
		h(w, r)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// tooManyFailures limits login attempts to 5 per 5 minutes per IP.
func (s *Server2) tooManyFailures(ip string, add bool) bool {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	cut := time.Now().Add(-5 * time.Minute)
	var keep []time.Time
	for _, t := range s.failures[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if add {
		keep = append(keep, time.Now())
	}
	if len(keep) == 0 {
		delete(s.failures, ip) // or the map keeps every address that ever tried
	} else {
		s.failures[ip] = keep
	}
	return len(keep) >= 5
}

// ---- auth endpoints ----

func (s *Server2) setupState(w http.ResponseWriter, r *http.Request) {
	configured, name := false, ""
	s.app.store.View(func(st *State) { configured = len(st.Users) > 0; name = st.Settings.PanelName })
	writeJSON(w, map[string]any{"configured": configured, "panelName": name})
}

// register creates the first admin account; it needs the setup code (installer output,
// the log, or `tunnel-panel setup-code` on the server).
func (s *Server2) register(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooManyFailures(ip, false) {
		httpErr(w, 429, "Too many failed attempts. Wait 5 minutes and try again.")
		return
	}
	var in struct{ Username, Password, Code string }
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Username) == "" || len(in.Password) < 8 {
		httpErr(w, 400, "Username and a password of at least 8 characters are required.")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	badCode := false
	err := s.app.store.Update(func(st *State) error {
		if len(st.Users) > 0 {
			return fmt.Errorf("already configured")
		}
		code := strings.ToLower(strings.TrimSpace(in.Code))
		if st.SetupCode == "" || subtle.ConstantTimeCompare([]byte(code), []byte(st.SetupCode)) != 1 {
			badCode = true
			return fmt.Errorf("wrong setup code — it was printed by the installer; on the server run:  tunnel-panel setup-code")
		}
		st.Users = append(st.Users, User{Username: in.Username, Hash: string(hash)})
		st.SetupCode = ""
		return nil
	})
	if err != nil {
		if badCode {
			s.tooManyFailures(ip, true)
			httpErr(w, 403, err.Error())
			return
		}
		httpErr(w, 409, err.Error())
		return
	}
	s.setCookie(w, r, in.Username)
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooManyFailures(ip, false) {
		httpErr(w, 429, "Too many failed attempts. Wait 5 minutes and try again.")
		return
	}
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	var hash string
	s.app.store.View(func(st *State) {
		for _, u := range st.Users {
			if u.Username == in.Username {
				hash = u.Hash
			}
		}
	})
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil {
		s.tooManyFailures(ip, true)
		httpErr(w, 401, "Wrong username or password.")
		return
	}
	s.setCookie(w, r, in.Username)
	writeJSON(w, map[string]string{"ok": "1"})
}

// logout ends the session for good: the signature generation moves on, so this cookie (and
// any copy of it) is refused from now on — on every browser this account is signed in.
func (s *Server2) logout(w http.ResponseWriter, r *http.Request) {
	if u := s.currentUser(r); u != "" {
		_ = s.app.store.Update(func(st *State) error { s.bumpGen(st, u); return nil })
	}
	http.SetCookie(w, &http.Cookie{Name: "tp_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) me(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	role := "admin"
	if !admin {
		role = roleUser
	}
	writeJSON(w, map[string]string{"user": user, "role": role, "version": version})
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)

// password changes the signed-in account's password and/or username (NewUser); both need
// the current password, and every other session of the account ends.
func (s *Server2) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ Old, New, NewUser string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	in.NewUser = strings.TrimSpace(in.NewUser)
	if in.New == "" && in.NewUser == "" {
		httpErr(w, 400, "Enter a new password or a new username.")
		return
	}
	if in.New != "" && len(in.New) < 8 {
		httpErr(w, 400, "The new password must be at least 8 characters.")
		return
	}
	if in.NewUser != "" && !usernameRe.MatchString(in.NewUser) {
		httpErr(w, 400, "A username is 1–32 characters: letters, digits and . _ @ -")
		return
	}
	user := s.currentUser(r)
	name := user
	err := s.app.store.Update(func(st *State) error {
		for i, u := range st.Users {
			if u.Username == user {
				if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(in.Old)) != nil {
					return fmt.Errorf("The current password is wrong.")
				}
				if in.NewUser != "" && in.NewUser != user {
					for _, o := range st.Users {
						if o.Username == in.NewUser {
							return fmt.Errorf("The username %q is taken.", in.NewUser)
						}
					}
					st.Users[i].Username, name = in.NewUser, in.NewUser
					// what the account owns follows the new name (ownership is by username)
					renameOwnerLocked(st, user, in.NewUser)
				}
				if in.New != "" {
					h, _ := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
					st.Users[i].Hash = string(h)
				}
				st.Users[i].Gen++ // sessions from before the change end
				return nil
			}
		}
		return fmt.Errorf("user not found")
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if name != user {
		go s.app.restartBot() // a user's own bot belongs to the account by name
	}
	s.setCookie(w, r, name) // this browser stays signed in; every other session has ended
	writeJSON(w, map[string]string{"ok": "1", "user": name})
}

// ---- settings ----

func (s *Server2) settings(w http.ResponseWriter, r *http.Request) {
	if _, admin := s.who(r); !admin {
		if r.Method != http.MethodGet {
			httpErr(w, 403, "only the panel admin can change the settings")
			return
		}
		// a user sees the panel's name and nothing of the admin's setup
		writeJSON(w, map[string]any{"settings": map[string]string{"panelName": s.app.settings().PanelName}, "hostArch": runtime.GOARCH})
		return
	}
	if r.Method == http.MethodGet {
		set := s.app.settings()
		set.TelegramTok = maskStr(set.TelegramTok)
		writeJSON(w, map[string]any{"settings": set, "agentPin": s.app.agents.pin, "agentPort": s.app.agentPort, "hostArch": runtime.GOARCH})
		return
	}
	var in Settings
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	var err error
	// both end up inside shell scripts run as root: only what they really look like
	if v := strings.TrimSpace(in.FRPVersion); v != "" && !frpVerRe.MatchString(v) {
		httpErr(w, 400, "FRP version: use a version number like 0.61.1 (blank = latest)")
		return
	}
	if v := strings.TrimSpace(in.GitHubProxy); v != "" && !ghProxyRe.MatchString(v) {
		httpErr(w, 400, "GitHub download prefix: a plain URL like https://ghproxy.net/ (letters, digits, . - _ / : only)")
		return
	}
	in.FRPVersion, in.GitHubProxy = strings.TrimSpace(in.FRPVersion), strings.TrimSpace(in.GitHubProxy)
	if v := strings.TrimSpace(in.AutoBench); v != "" {
		if n, e := strconv.Atoi(v); e != nil || n < 0 || n > 720 {
			httpErr(w, 400, "Automatic benchmark: hours must be 0 (off) to 720")
			return
		}
	}
	if in.TelegramReport = strings.TrimSpace(in.TelegramReport); in.TelegramReport != "" {
		if _, e := time.Parse("15:04", in.TelegramReport); e != nil || len(in.TelegramReport) != 5 {
			httpErr(w, 400, "Daily report time: HH:MM in Tehran time, e.g. 09:00 (blank = off)")
			return
		}
	}
	if in.LocalIPv4, err = normIP(in.LocalIPv4, false); err != nil {
		httpErr(w, 400, "IPv4: "+err.Error())
		return
	}
	if in.LocalIPv6, err = normIP(in.LocalIPv6, true); err != nil {
		httpErr(w, 400, "IPv6: "+err.Error())
		return
	}
	_ = s.app.store.Update(func(st *State) error {
		if in.PanelName == "" {
			in.PanelName = st.Settings.PanelName
		}
		if in.TelegramTok == "********" { // unchanged; an empty field clears the token
			in.TelegramTok = st.Settings.TelegramTok
		}
		st.Settings = in
		return nil
	})
	s.app.restartBot()
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) listMethods(w http.ResponseWriter, r *http.Request) { writeJSON(w, methods) }

// ---- servers ----

// serverView is a server as the UI sees it: secrets masked, live agent state added.
type serverView struct {
	*Server
	AgentOnline bool   `json:"agentOnline"`
	AgentHost   string `json:"agentHost,omitempty"`
	// Shared: another account's server that carries one of this user's tunnels (read-only)
	Shared bool `json:"shared,omitempty"`
}

func (s *Server2) servers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		out := []serverView{}
		user, admin := s.who(r)
		s.app.store.View(func(st *State) {
			var shared map[string]bool
			if !admin {
				shared = sharedServersLocked(st, user)
			}
			for _, x := range st.Servers {
				if shared[x.ID] {
					out = append(out, serverView{Server: sharedView(x), Shared: true})
					continue
				}
				if !visible(user, admin, x.Owner) {
					continue
				}
				cp := *x
				cp.Password, cp.PrivateKey = maskStr(cp.Password), maskStr(cp.PrivateKey)
				cp.AgentToken = ""
				v := serverView{Server: &cp}
				if ac := s.app.agents.online(x.ID); ac != nil {
					v.AgentOnline, v.AgentHost = true, ac.hostname
				}
				out = append(out, v)
			}
		})
		writeJSON(w, out)
		return
	}
	var in Server
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	if in.Role != "foreign" {
		in.Role = "iran"
	}
	if in.Proxy != "" && !regexp.MustCompile(`^(socks5h?|https?)://`).MatchString(in.Proxy) {
		httpErr(w, 400, "Proxy must start with socks5://, socks5h://, http:// or https://")
		return
	}
	var err error
	if in.IPv4, err = normIP(in.IPv4, false); err != nil {
		httpErr(w, 400, "IPv4: "+err.Error())
		return
	}
	if in.IPv6, err = normIP(in.IPv6, true); err != nil {
		httpErr(w, 400, "IPv6: "+err.Error())
		return
	}
	user, admin := s.who(r)
	err = s.app.store.Update(func(st *State) error {
		// a jump host must be a server of the same account (a user never goes through
		// someone else's servers)
		if in.Via != "" {
			via := s.app.store.serverLocked(st, in.Via)
			if via == nil || !visible(user, admin, via.Owner) {
				return fmt.Errorf("jump server not found")
			}
		}
		if !admin {
			in.Owner = user
		} else if in.Owner != "" && !accountExists(st, in.Owner) {
			return fmt.Errorf("no account %q", in.Owner)
		}
		if in.ID == "" {
			in.ID = newID()
			in.CreatedAt = time.Now().Unix()
			in.HostKey, in.AgentToken, in.Prepared = "", "", false
			st.Servers = append(st.Servers, &in)
			return nil
		}
		x := s.app.store.serverLocked(st, in.ID)
		if x == nil || !visible(user, admin, x.Owner) {
			return fmt.Errorf("server not found")
		}

		x.Name, x.IPv4, x.IPv6, x.SSHHost, x.SSHPort, x.SSHUser = in.Name, in.IPv4, in.IPv6, in.SSHHost, in.SSHPort, in.SSHUser
		x.Role, x.Proxy, x.Via = in.Role, in.Proxy, in.Via
		if in.Country != "" {
			x.Country = strings.ToUpper(in.Country)
		}
		if !isMasked(in.Password) {
			x.Password = in.Password
		}
		if !isMasked(in.PrivateKey) {
			x.PrivateKey = in.PrivateKey
		}
		return nil
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	dropHost(in.ID)
	if srv := s.app.store.Server(in.ID); srv != nil {
		go s.app.annotateGeo(srv)
		// a blank address (IPv6 above all) is read from the server itself as soon as SSH
		// works — the same as pressing Test connection, without having to
		var v4, v6 string
		s.app.store.View(func(*State) { v4, v6 = srv.IPv4, srv.IPv6 })
		if v4 == "" || v6 == "" {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				s.app.TestServer(ctx, srv)
			}()
		}
	}
	writeJSON(w, map[string]string{"ok": "1", "id": in.ID})
}

func (s *Server2) serverDelete(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	err := s.app.store.Update(func(st *State) error {
		for _, t := range st.Tunnels {
			if t.ServerID == in.ID || t.ForeignID == in.ID {
				return fmt.Errorf("Tunnel %q still uses this server. Delete or move it first.", t.Name)
			}
		}
		var keep []*Server
		for _, x := range st.Servers {
			if x.ID != in.ID {
				keep = append(keep, x)
			}
		}
		st.Servers = keep
		return nil
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	dropHost(in.ID)
	s.app.syncAgentTokens()
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) serverResetKey(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	_ = s.app.store.Update(func(st *State) error {
		if x := s.app.store.serverLocked(st, in.ID); x != nil {
			x.HostKey = ""
		}
		return nil
	})
	dropHost(in.ID)
	writeJSON(w, map[string]string{"ok": "1"})
}

// serverTest checks every path to a server and reports which ones work.
func (s *Server2) serverTest(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	srv := s.app.store.Server(in.ID)
	if srv == nil {
		httpErr(w, 404, "server not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res := s.app.TestServer(ctx, srv)
	go s.app.annotateGeo(srv)
	writeJSON(w, res)
}

// serverAgent returns (creating if needed) the one-line agent install command for a server.
func (s *Server2) serverAgent(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string
		Rotate bool
	}
	_ = readJSON(r, &in)
	var tok string
	err := s.app.store.Update(func(st *State) error {
		x := s.app.store.serverLocked(st, in.ID)
		if x == nil {
			return fmt.Errorf("server not found")
		}
		if x.AgentToken == "" || in.Rotate {
			x.AgentToken = randHex(24)
		}
		tok = x.AgentToken
		return nil
	})
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	s.app.syncAgentTokens()
	connect := s.app.agentConnect()
	if connect == "" {
		httpErr(w, 400, "Set this server's public IP (or the agent address) in Settings first.")
		return
	}
	pin := s.app.agents.pin
	cmd := fmt.Sprintf("curl -fsSk --pinnedpubkey 'sha256//%s' 'https://%s/agent/install?t=%s' | bash", pin, connect, tok)
	writeJSON(w, map[string]string{"command": cmd, "connect": connect, "pin": pin})
}

// serverBridge opens a local SSH bridge to an Iran server and returns the ssh command.
func (s *Server2) serverBridge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID     string
		Public bool
	}
	_ = readJSON(r, &in)
	srv := s.app.store.Server(in.ID)
	if srv == nil {
		httpErr(w, 404, "server not found")
		return
	}
	b, err := s.app.OpenBridge(srv, in.Public, 30*time.Minute)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	user := srv.SSHUser
	if user == "" {
		user = "root"
	}
	host := s.app.settings().LocalIPv4
	if !in.Public || host == "" {
		host = "127.0.0.1"
	}
	writeJSON(w, map[string]any{
		"port": b.Port, "public": in.Public,
		"command": fmt.Sprintf("ssh -p %d %s@%s", b.Port, user, host),
		"note":    "Open for 30 minutes. Each new SSH connection is proxied to the Iran server over the active path.",
	})
}

// serverOptimize detects a server and recommends/applies kernel tuning.
func (s *Server2) serverOptimize(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID    string
		Apply bool
	}
	_ = readJSON(r, &in)
	srv := s.app.store.Server(in.ID)
	if srv == nil {
		httpErr(w, 404, "server not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	writeJSON(w, s.app.Optimize(ctx, srv, in.Apply))
}

func maskStr(s string) string {
	if s == "" {
		return ""
	}
	return "********"
}
func isMasked(s string) bool { return s == "" || s == "********" }

// ---- tunnels ----

func (s *Server2) tunnels(w http.ResponseWriter, r *http.Request) {
	type tv struct {
		Tunnel
		Families []string `json:"families"`        // address families both of its servers can use
		Clash    string   `json:"clash,omitempty"` // a port another tunnel on this Iran server holds
		HS       *hsView  `json:"hs,omitempty"`    // hot standby: the switcher's state
		Health   *string  `json:"health"`          // monitor's last verdict: "" ok, a reason, null = not checked yet
	}
	out := []tv{}
	user, admin := s.who(r)
	s.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if !visible(user, admin, t.Owner) {
				continue
			}
			cp := t.clone()  // deep copy: encoded after the lock is released
			cp.Secrets = nil // never send tokens/PSKs to the browser
			clash := ""
			if err := portClash(st, t, ""); err != nil {
				clash = err.Error()
			}
			var hp *string
			if r, ok := s.app.cachedHealth(t.ID); ok {
				hp = &r
			}
			out = append(out, tv{cp, s.app.routeFamiliesLocked(st, t), clash, s.app.hsViewOf(t.ID), hp})
		}
	})
	writeJSON(w, out)
}

var portSpecRe = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?(=\d{1,5})?$`)

// validatePorts checks the spec and refuses ports that would cut off SSH or the panel.
func validatePorts(spec string, reserved map[int]string) error {
	if strings.TrimSpace(spec) == "" {
		return fmt.Errorf("Add at least one port.")
	}
	for _, p := range splitPorts(spec) {
		raw := p.listen
		if p.dst != p.listen {
			raw += "=" + p.dst
		}
		if !portSpecRe.MatchString(raw) {
			return fmt.Errorf("%q is not a valid port entry. Use 443, 8080=80 or 2000-2010.", raw)
		}
		lo, hi := portRange(p.listen)
		if lo < 1 || hi > 65535 || lo > hi {
			return fmt.Errorf("%q is out of range.", p.listen)
		}
		if p.dst != p.listen {
			if d, _ := strconv.Atoi(p.dst); d < 1 || d > 65535 {
				return fmt.Errorf("%q: the destination port %s is out of range (1-65535).", raw, p.dst)
			}
		}
		for port, what := range reserved {
			if port >= lo && port <= hi {
				return fmt.Errorf("Port %d is used by %s on the Iran server; forwarding it would lock you out.", port, what)
			}
		}
	}
	return nil
}

func portRange(s string) (int, int) {
	parts := strings.SplitN(s, "-", 2)
	lo, _ := strconv.Atoi(parts[0])
	hi := lo
	if len(parts) == 2 {
		hi, _ = strconv.Atoi(parts[1])
	}
	return lo, hi
}

func (s *Server2) tunnelSave(w http.ResponseWriter, r *http.Request) {
	var in Tunnel
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	if in.Family != "v6" {
		in.Family = "v4"
	}
	// the name ends up in unit files and logs: no control characters
	in.Name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(in.Name))
	if in.Name == "" {
		httpErr(w, 400, "Give the tunnel a name.")
		return
	}
	if err := validateOptions(in.Options); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	user, admin := s.who(r)
	srv := s.app.store.Server(in.ServerID)
	// a user may keep their tunnel on the servers it already runs on, even when those are
	// the admin's (the admin set the tunnel up for them); moving it needs their own servers
	samePair := false
	if !admin && in.ID != "" {
		if old := s.app.store.Tunnel(in.ID); old != nil {
			s.app.store.View(func(*State) {
				samePair = old.Owner == user && old.ServerID == in.ServerID && old.ForeignID == in.ForeignID
			})
		}
	}
	if srv == nil || (!samePair && !s.serverVisible(user, admin, in.ServerID)) {
		httpErr(w, 400, "Pick an Iran server.")
		return
	}
	// a user's tunnel ends on one of their foreign servers, never on the panel host
	if !admin && !samePair && (in.ForeignID == "" || !s.serverVisible(user, admin, in.ForeignID)) {
		httpErr(w, 400, "Pick one of your foreign servers.")
		return
	}
	sshPort := srv.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	if err := validatePorts(in.Ports, map[int]string{sshPort: "SSH"}); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	err := s.app.store.Update(func(st *State) error {
		if in.ID == "" {
			in.ID = newID()
			if in.Index = s.app.store.nextIndexLocked(st); in.Index == 0 {
				return fmt.Errorf("All 249 tunnel slots are in use (hot-standby paths take one each) — delete a tunnel first.")
			}
			in.Updated = time.Now().Unix()
			in.Active, in.Secrets, in.Failover = "", nil, nil
			// the panel's own bookkeeping never comes from the request
			in.Paths, in.Applying, in.HSPin, in.HSSeen = nil, "", "", 0
			if !admin {
				in.Owner = user
			} else if in.Owner != "" && !accountExists(st, in.Owner) {
				return fmt.Errorf("no account %q", in.Owner)
			}
			in.Shape = normalizeShape(in.Shape)
			if in.Options == nil {
				in.Options = map[string]map[string]string{}
			}
			if err := portClash(st, &in, ""); err != nil {
				return err
			}
			st.Tunnels = append(st.Tunnels, &in)
			return nil
		}
		t := s.app.store.tunnelLocked(st, in.ID)
		if t == nil || !visible(user, admin, t.Owner) {
			return fmt.Errorf("tunnel not found")
		}
		if t.Active != "" && (t.ServerID != in.ServerID || t.ForeignID != in.ForeignID || t.Family != in.Family) {
			return fmt.Errorf("Stop the tunnel before changing its servers or address family.")
		}
		// refuse before changing anything: a failed Update doesn't roll back
		cand := *t
		cand.Ports, cand.ServerID = in.Ports, in.ServerID
		cand.Options = map[string]map[string]string{}
		for mid, opts := range t.Options {
			cand.Options[mid] = opts
		}
		for mid, opts := range in.Options {
			cand.Options[mid] = opts
		}
		if in.Selected != "" {
			cand.Selected = in.Selected
		}
		if err := portClash(st, &cand, ""); err != nil {
			return err
		}
		t.Name, t.ServerID, t.ForeignID, t.Family, t.Ports, t.Note = in.Name, in.ServerID, in.ForeignID, in.Family, in.Ports, in.Note
		t.Shape = normalizeShape(in.Shape)
		t.NoFailover = in.NoFailover
		t.HotStandby = in.HotStandby
		if t.HSAuto != in.HSAuto {
			t.HSAuto = in.HSAuto
			if t.HotStandby && t.Active != "" {
				cp := t
				go func() { _, _ = s.app.pushHSMode(context.Background(), cp) }()
			}
		}
		if in.Selected != "" {
			t.Selected = in.Selected
		}
		// copy-on-write: the monitor and traffic collector read Options without the lock
		no := make(map[string]map[string]string, len(t.Options)+len(in.Options))
		for mid, opts := range t.Options {
			no[mid] = opts
		}
		for mid, opts := range in.Options {
			no[mid] = opts
		}
		t.Options = no
		t.Updated = time.Now().Unix()
		return nil
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": "1", "id": in.ID})
}

func (s *Server2) tunnelDelete(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	if t.Active != "" {
		httpErr(w, 400, "Stop the tunnel first, then delete it.")
		return
	}
	if s.app.jobs.running(t.ID) != "" || s.app.jobs.running(failoverJobKey+t.ID) != "" {
		httpErr(w, 409, "A job is still running on this tunnel — wait for it or cancel it first.")
		return
	}
	// a failed Apply can leave the foreign side deployed; remove whatever is left on both
	// servers so its unit, rules and interface don't clash with the next tunnel on this index
	warn := s.app.purge(r.Context(), t)
	_ = s.app.store.Update(func(st *State) error {
		var keep []*Tunnel
		for _, x := range st.Tunnels {
			if x.ID != in.ID {
				keep = append(keep, x)
			}
		}
		st.Tunnels = keep
		return nil
	})
	writeJSON(w, map[string]string{"ok": "1", "warning": warn})
}

func (s *Server2) tunnelApply(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Method, Family string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	j, err := s.app.ApplyRoute(t, in.Method, in.Family)
	if err != nil {
		code := 400
		if strings.Contains(err.Error(), "still running") {
			code = 409
		}
		httpErr(w, code, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

func (s *Server2) tunnelStop(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	// Stop always wins: cancel whatever is still running on the tunnel first
	if id := s.app.jobs.running(t.ID); id != "" {
		_, _ = s.app.jobs.cancel(id)
	}
	if id := s.app.jobs.running(failoverJobKey + t.ID); id != "" {
		_, _ = s.app.jobs.cancel(id)
	}
	s.app.clearFailover(t)
	j, err := s.app.Stop(t)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

// tunnelHSMode switches hot standby between manual and auto, live.
func (s *Server2) tunnelHSMode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID   string
		Auto bool
	}
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	msg, err := s.app.setHSMode(ctx, t, in.Auto)
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": msg})
}

// tunnelHSPin moves a hot-standby tunnel's users to one of its running paths, live.
func (s *Server2) tunnelHSPin(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Path string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	f := strings.SplitN(in.Path, "|", 2)
	if len(f) != 2 || hsIndex(t, f[0], f[1]) < 0 {
		httpErr(w, 400, "that path isn't running on this tunnel")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	msg, err := s.app.hsPinTo(ctx, t, in.Path)
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": msg})
}

// repair re-applies every running tunnel that has a problem (see repair.go).
func (s *Server2) repair(w http.ResponseWriter, r *http.Request) {
	j, err := s.app.Repair("from the panel")
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

func (s *Server2) tunnelStatus(w http.ResponseWriter, r *http.Request) {
	t := s.app.store.Tunnel(r.URL.Query().Get("id"))
	if t == nil {
		httpErr(w, 404, "not found")
		return
	}
	if t.Active == "" {
		writeJSON(w, map[string]string{"active": "", "iran": "stopped", "foreign": "stopped"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	ir, kh, link := s.app.Health(ctx, t)
	writeJSON(w, map[string]string{"active": t.Active, "iran": ir, "foreign": kh, "link": link})
}

// trafficGet returns live traffic (starting the collector) plus the last speed tests.
func (s *Server2) trafficGet(w http.ResponseWriter, r *http.Request) {
	snap := s.app.Traffic()
	speed := map[string]*SpeedResult{}
	s.app.speedMu.Lock()
	for k, v := range s.app.speedRes {
		speed[k] = v
	}
	s.app.speedMu.Unlock()
	if user, admin := s.who(r); !admin {
		// a user sees the counters of their own tunnels and servers only
		for id := range snap.Tunnels {
			if !s.tunnelVisible(user, admin, id) {
				delete(snap.Tunnels, id)
			}
		}
		for id := range speed {
			if !s.tunnelVisible(user, admin, id) {
				delete(speed, id)
			}
		}
		for id := range snap.Servers {
			if !s.serverVisible(user, admin, id) {
				delete(snap.Servers, id)
			}
		}
		for id := range snap.Res {
			if !s.serverVisible(user, admin, id) {
				delete(snap.Res, id)
			}
		}
	}
	writeJSON(w, map[string]any{"tunnels": snap.Tunnels, "servers": snap.Servers, "res": snap.Res, "speed": speed})
}

func (s *Server2) tunnelSpeedTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      string
		Seconds int
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	j, err := s.app.SpeedTest(t, in.Seconds)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

func (s *Server2) tunnelTrace(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      string
		Seconds int
	}
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	j, err := s.app.Trace(t, in.Seconds)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

func (s *Server2) tunnelDiagnose(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	j, err := s.app.Diagnose(t)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

func (s *Server2) tunnelLastJob(w http.ResponseWriter, r *http.Request) {
	j := s.app.jobs.latestFor(r.URL.Query().Get("id"))
	if j == nil {
		httpErr(w, 404, "no jobs yet")
		return
	}
	writeJSON(w, j.snapshot())
}

func (s *Server2) jobCancel(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	j, err := s.app.jobs.cancel(in.ID)
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	writeJSON(w, j.snapshot())
}

func (s *Server2) job(w http.ResponseWriter, r *http.Request) {
	j := s.app.jobs.get(r.URL.Query().Get("id"))
	if j == nil {
		httpErr(w, 404, "job not found")
		return
	}
	writeJSON(w, j.snapshot())
}

// ---- benchmark ----

func (s *Server2) benchStart(w http.ResponseWriter, r *http.Request) {
	var in BenchRequest
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	j, err := s.app.Bench(in)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if user, admin := s.who(r); !admin {
		j.mu.Lock()
		j.Owner = user // lets this user follow the job
		j.mu.Unlock()
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

// benchHistory lists saved benchmark runs, newest first (DELETE-style ?clear=1 empties it).
// outages: the server/tunnel outage log, newest first (POST {Clear:true} empties it).
func (s *Server2) outages(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct{ Clear bool }
		_ = readJSON(r, &in)
		if in.Clear {
			_ = s.app.store.Update(func(st *State) error {
				var open []Outage // keep the ones still going on
				for _, o := range st.Outages {
					if o.End == 0 {
						open = append(open, o)
					}
				}
				st.Outages = open
				return nil
			})
		}
	}
	out := []Outage{}
	s.app.store.View(func(st *State) {
		for i := len(st.Outages) - 1; i >= 0; i-- {
			out = append(out, st.Outages[i])
		}
	})
	writeJSON(w, map[string]any{"outages": out, "now": time.Now().Unix(), "every": int(serverEvery.Seconds())})
}

func (s *Server2) benchHistory(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	if r.Method == http.MethodPost && !admin {
		httpErr(w, 403, "only the panel admin can clear the history")
		return
	}
	if r.Method == http.MethodPost {
		var in struct{ Clear bool }
		_ = readJSON(r, &in)
		if in.Clear {
			_ = s.app.store.Update(func(st *State) error { st.BenchHistory = nil; return nil })
		}
	}
	out := []BenchRecord{}
	s.app.store.View(func(st *State) {
		for i := len(st.BenchHistory) - 1; i >= 0; i-- {
			b := st.BenchHistory[i]
			if pairVisibleLocked(st, user, admin, b.IranID, b.ForeignID) {
				out = append(out, b)
			}
		}
	})
	writeJSON(w, out)
}

// benchActive returns the running or last benchmark ({} when none), so the page can re-attach.
func (s *Server2) benchActive(w http.ResponseWriter, r *http.Request) {
	if b := s.app.activeBench(); b != nil {
		if user, admin := s.who(r); admin || s.pairVisible(user, admin, b.Req.IranID, b.Req.ForeignID) {
			writeJSON(w, b)
			return
		}
	}
	writeJSON(w, map[string]string{})
}

// serverPrepare pre-installs every method's binaries/packages on a server ("" = this panel host).
func (s *Server2) serverPrepare(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	_ = readJSON(r, &in)
	var srv *Server
	if in.ID != "" {
		if srv = s.app.store.Server(in.ID); srv == nil {
			httpErr(w, 404, "server not found")
			return
		}
	}
	j, err := s.app.Prepare(srv)
	if err != nil {
		httpErr(w, 409, err.Error())
		return
	}
	if user, admin := s.who(r); !admin {
		j.mu.Lock()
		j.Owner = user
		j.mu.Unlock()
	}
	writeJSON(w, map[string]string{"job": j.ID})
}

func (s *Server2) benchResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	writeJSON(w, s.app.benchResults(q.Get("iran"), q.Get("foreign"), q.Get("family")))
}

// ---- helper binaries (e.g. the Backhaul Premium core) ----

var helperNameRe = regexp.MustCompile(`^[a-z0-9_.-]+-(amd64|arm64)$`)

func (s *Server2) helpers(w http.ResponseWriter, r *http.Request) {
	type hv struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
		Source string `json:"source"`
	}
	out := []hv{}
	seen := map[string]bool{}
	if ents, err := os.ReadDir(helpersDir()); err == nil {
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(helpersDir(), e.Name()))
			if err != nil || len(b) == 0 || strings.HasSuffix(e.Name(), ".part") {
				continue
			}
			sum := sha256.Sum256(b)
			out = append(out, hv{e.Name(), int64(len(b)), hex.EncodeToString(sum[:]), "uploaded"})
			seen[e.Name()] = true
		}
	}
	if ents, err := fs.ReadDir(assetsFS, "assets"); err == nil {
		for _, e := range ents {
			if seen[e.Name()] || strings.HasPrefix(e.Name(), "tp-agent-") || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			b, _ := assetsFS.ReadFile("assets/" + e.Name())
			if len(b) == 0 || !helperNameRe.MatchString(e.Name()) {
				continue // placeholder (not built for this arch) or not a helper
			}
			sum := sha256.Sum256(b)
			out = append(out, hv{e.Name(), int64(len(b)), hex.EncodeToString(sum[:]), "built-in"})
		}
	}
	writeJSON(w, out)
}

func (s *Server2) helperUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, 405, "POST only")
		return
	}
	if r.Header.Get("X-TP-Upload") != "1" { // custom header forces a CORS preflight cross-site
		httpErr(w, 400, "missing upload header")
		return
	}
	name := r.URL.Query().Get("name")
	if !helperNameRe.MatchString(name) {
		httpErr(w, 400, "Name must look like backhaul_premium-amd64.")
		return
	}
	if err := os.MkdirAll(helpersDir(), 0o700); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	tmp := filepath.Join(helpersDir(), name+".part")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	n, err := io.Copy(f, io.LimitReader(r.Body, 200<<20))
	f.Close()
	if err != nil || n == 0 {
		os.Remove(tmp)
		httpErr(w, 400, "upload failed")
		return
	}
	// a .tar.gz straight from the vendor is unpacked; then the ELF must match the name's arch
	if err := normalizeHelper(tmp, name); err != nil {
		os.Remove(tmp)
		httpErr(w, 400, err.Error())
		return
	}
	if st, err := os.Stat(tmp); err == nil {
		n = st.Size()
	}
	note := ""
	if strings.HasPrefix(name, "backhaul_premium-") {
		// a v1.x core (the vendor's arm64 build) belongs to the v1 method, not the v2 one
		if b, err := os.ReadFile(tmp); err == nil && !bytes.Contains(b, []byte("anytls")) {
			name = "backhaul_premium_v1-" + strings.TrimPrefix(name, "backhaul_premium-")
			note = "This is a Backhaul Premium v1.x core: saved as " + name + " for the \"Backhaul Premium v1 (legacy)\" method (it can't talk to the v2 core)."
		}
	}
	if err := os.Rename(tmp, filepath.Join(helpersDir(), name)); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "size": n, "name": name, "note": note})
}

// normalizeHelper unpacks an uploaded .tar.gz (the first ELF inside wins) and checks
// that the binary is a Linux ELF for the architecture in its name, so an amd64 core
// can't be stored as "-arm64" by mistake.
func normalizeHelper(path, name string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("bad .tar.gz: %v", err)
		}
		tr := tar.NewReader(zr)
		var found []byte
		for {
			hd, err := tr.Next()
			if err != nil {
				break
			}
			if hd.Typeflag != tar.TypeReg || hd.Size < 4 || hd.Size > 200<<20 {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, 200<<20))
			if err == nil && bytes.HasPrefix(b, []byte("\x7fELF")) {
				found = b
				break
			}
		}
		if found == nil {
			return fmt.Errorf("no Linux binary found inside the archive")
		}
		raw = found
		if err := os.WriteFile(path, raw, 0o700); err != nil {
			return err
		}
	}
	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("not a Linux binary (ELF): %v", err)
	}
	want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[name[strings.LastIndex(name, "-")+1:]]
	if ef.Machine != want {
		got := map[elf.Machine]string{elf.EM_X86_64: "amd64", elf.EM_AARCH64: "arm64"}[ef.Machine]
		if got == "" {
			got = ef.Machine.String()
		}
		return fmt.Errorf("this binary is for %s but the name says %s — rename it to %s-%s", got, name[strings.LastIndex(name, "-")+1:], name[:strings.LastIndex(name, "-")], got)
	}
	return nil
}

func (s *Server2) helperFetch(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string }
	if err := readJSON(r, &in); err != nil || !helperNameRe.MatchString(in.Name) {
		httpErr(w, 400, "name must look like backhaul_premium-arm64")
		return
	}
	res, err := fetchVendorHelper(in.Name)
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "source": res.Source, "sha256": res.SHA256, "size": res.Size, "note": res.Note})
}

var (
	optTextRe = regexp.MustCompile(`^[A-Za-z0-9_.:/@,=-]*$`)
	frpVerRe  = regexp.MustCompile(`^v?[0-9]{1,3}(\.[0-9]{1,3}){1,3}$`)
	ghProxyRe = regexp.MustCompile(`^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	// text options with a known shape, checked by key
	optShape = map[string]*regexp.Regexp{
		"fec":           regexp.MustCompile(`^([0-9]{1,3}:[0-9]{1,3})?$`),
		"sni":           regexp.MustCompile(`^[A-Za-z0-9.-]{0,253}$`),
		"sni_domain":    regexp.MustCompile(`^[A-Za-z0-9.-]{0,253}$`),
		"xdp_interface": regexp.MustCompile(`^[A-Za-z0-9_.@-]{0,15}$`),
	}
	// numbers with a narrower sensible range than a port
	optRange = map[string][2]int{"mtu": {576, 9000}, "mux_con": {1, 64}, "mux_concurrency": {1, 64},
		"keepalive_period": {5, 600}, "heartbeat": {2, 300}, "heartbeat_interval": {1, 120}, "heartbeat_timeout": {3, 600},
		"channel_size": {64, 65535}, "connection_pool": {1, 128}}
)

// validateOptions checks method options before they reach configs and shell scripts:
// numbers must be numbers, selects one of their choices, free text a safe charset.
func validateOptions(opts map[string]map[string]string) error {
	for mid, kv := range opts {
		m := methodByID[mid]
		if m == nil {
			return fmt.Errorf("unknown method %q", mid)
		}
		for k, v := range kv {
			f := methodField(m, k)
			if f == nil {
				return fmt.Errorf("%s has no option %q", m.Title, k)
			}
			switch f.Type {
			case "number":
				if v != "" {
					n, err := strconv.Atoi(v)
					if err != nil || n < 0 || n > 65535 {
						return fmt.Errorf("%s: %s must be a number", m.Title, f.Label)
					}
					if r, ok := optRange[k]; ok && (n < r[0] || n > r[1]) {
						return fmt.Errorf("%s: %s must be between %d and %d", m.Title, f.Label, r[0], r[1])
					}
				}
			case "bool":
				if v != "" && v != "true" && v != "false" {
					return fmt.Errorf("%s: %s must be true or false", m.Title, f.Label)
				}
			case "select":
				if v != "" && !contains(f.Options, v) {
					return fmt.Errorf("%s: %s must be one of %s", m.Title, f.Label, strings.Join(f.Options, ", "))
				}
			default:
				if re := optShape[k]; re != nil && !re.MatchString(v) {
					return fmt.Errorf("%s: %s %q doesn't look right", m.Title, f.Label, v)
				}
				if strings.HasSuffix(k, "_ip") && v != "" && net.ParseIP(v) == nil {
					return fmt.Errorf("%s: %s must be an IP address", m.Title, f.Label)
				}
				if !optTextRe.MatchString(v) || len(v) > 200 {
					return fmt.Errorf("%s: %s contains characters that aren't allowed", m.Title, f.Label)
				}
			}
		}
	}
	return nil
}
