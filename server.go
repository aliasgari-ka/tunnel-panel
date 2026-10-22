package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

	p := func(path string, h http.HandlerFunc) { mux.HandleFunc(path, s.auth(s.json(h))) }
	p("/api/me", s.me)
	p("/api/password", s.password)
	p("/api/settings", s.settings)
	p("/api/methods", s.listMethods)
	p("/api/servers", s.servers)
	p("/api/servers/test", s.serverTest)
	p("/api/servers/delete", s.serverDelete)
	p("/api/servers/agent", s.serverAgent)
	p("/api/servers/resetkey", s.serverResetKey)
	p("/api/servers/bridge", s.serverBridge)
	p("/api/servers/optimize", s.serverOptimize)
	p("/api/tunnels", s.tunnels)
	p("/api/tunnels/save", s.tunnelSave)
	p("/api/tunnels/delete", s.tunnelDelete)
	p("/api/tunnels/apply", s.tunnelApply)
	p("/api/tunnels/stop", s.tunnelStop)
	p("/api/tunnels/status", s.tunnelStatus)
	p("/api/tunnels/lastjob", s.tunnelLastJob)
	p("/api/jobs", s.job)
	p("/api/bench/start", s.benchStart)
	p("/api/bench/results", s.benchResults)
	p("/api/helpers", s.helpers)
	mux.HandleFunc("/api/helpers/upload", s.auth(s.helperUpload)) // multipart, not JSON
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
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
	s.app.store.View(func(st *State) { secret = st.Secret })
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s|%d", user, exp)
	return hex.EncodeToString(mac.Sum(nil))
}

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
		SameSite: http.SameSiteLaxMode, MaxAge: 72 * 3600})
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
	s.failures[ip] = keep
	return len(keep) >= 5
}

// ---- auth endpoints ----

func (s *Server2) setupState(w http.ResponseWriter, r *http.Request) {
	configured, name := false, ""
	s.app.store.View(func(st *State) { configured = len(st.Users) > 0; name = st.Settings.PanelName })
	writeJSON(w, map[string]any{"configured": configured, "panelName": name})
}

func (s *Server2) register(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Username) == "" || len(in.Password) < 8 {
		httpErr(w, 400, "Username and a password of at least 8 characters are required.")
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	err := s.app.store.Update(func(st *State) error {
		if len(st.Users) > 0 {
			return fmt.Errorf("already configured")
		}
		st.Users = append(st.Users, User{Username: in.Username, Hash: string(hash)})
		return nil
	})
	if err != nil {
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

func (s *Server2) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "tp_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"user": s.currentUser(r)})
}

func (s *Server2) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ Old, New string }
	if err := readJSON(r, &in); err != nil || len(in.New) < 8 {
		httpErr(w, 400, "The new password must be at least 8 characters.")
		return
	}
	user := s.currentUser(r)
	err := s.app.store.Update(func(st *State) error {
		for i, u := range st.Users {
			if u.Username == user {
				if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(in.Old)) != nil {
					return fmt.Errorf("The current password is wrong.")
				}
				h, _ := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
				st.Users[i].Hash = string(h)
				return nil
			}
		}
		return fmt.Errorf("user not found")
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

// ---- settings ----

func (s *Server2) settings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		set := s.app.settings()
		set.TelegramTok = maskStr(set.TelegramTok)
		writeJSON(w, map[string]any{"settings": set, "agentPin": s.app.agents.pin, "agentPort": s.app.agentPort})
		return
	}
	var in Settings
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	_ = s.app.store.Update(func(st *State) error {
		if in.PanelName == "" {
			in.PanelName = st.Settings.PanelName
		}
		if isMasked(in.TelegramTok) {
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
}

func (s *Server2) servers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		var out []serverView
		s.app.store.View(func(st *State) {
			for _, x := range st.Servers {
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
	err := s.app.store.Update(func(st *State) error {
		if in.ID == "" {
			in.ID = newID()
			in.CreatedAt = time.Now().Unix()
			in.HostKey, in.AgentToken, in.Prepared = "", "", false
			st.Servers = append(st.Servers, &in)
			return nil
		}
		x := s.app.store.serverLocked(st, in.ID)
		if x == nil {
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
	var out []Tunnel
	s.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			cp := *t
			cp.Secrets = nil // never send tokens/PSKs to the browser
			out = append(out, cp)
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
	if strings.TrimSpace(in.Name) == "" {
		httpErr(w, 400, "Give the tunnel a name.")
		return
	}
	srv := s.app.store.Server(in.ServerID)
	if srv == nil {
		httpErr(w, 400, "Pick an Iran server.")
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
			in.Index = s.app.store.nextIndexLocked(st)
			in.Updated = time.Now().Unix()
			in.Active, in.Secrets = "", nil
			in.Shape = normalizeShape(in.Shape)
			if in.Options == nil {
				in.Options = map[string]map[string]string{}
			}
			st.Tunnels = append(st.Tunnels, &in)
			return nil
		}
		t := s.app.store.tunnelLocked(st, in.ID)
		if t == nil {
			return fmt.Errorf("tunnel not found")
		}
		if t.Active != "" && (t.ServerID != in.ServerID || t.ForeignID != in.ForeignID || t.Family != in.Family) {
			return fmt.Errorf("Stop the tunnel before changing its servers or address family.")
		}
		t.Name, t.ServerID, t.ForeignID, t.Family, t.Ports, t.Note = in.Name, in.ServerID, in.ForeignID, in.Family, in.Ports, in.Note
		t.Shape = normalizeShape(in.Shape)
		if in.Selected != "" {
			t.Selected = in.Selected
		}
		if t.Options == nil {
			t.Options = map[string]map[string]string{}
		}
		for mid, opts := range in.Options {
			t.Options[mid] = opts
		}
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
	writeJSON(w, map[string]string{"ok": "1"})
}

func (s *Server2) tunnelApply(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Method string }
	_ = readJSON(r, &in)
	t := s.app.store.Tunnel(in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	m := methodByID[in.Method]
	if m == nil {
		httpErr(w, 400, "unknown method")
		return
	}
	if !supportsFamily(m, t.Family) {
		httpErr(w, 400, fmt.Sprintf("%s does not work over %s.", m.Title, t.Family))
		return
	}
	j, err := s.app.Apply(t, in.Method)
	if err != nil {
		httpErr(w, 409, err.Error())
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
	j, err := s.app.Stop(t)
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
	ir, kh := s.app.Status(ctx, t)
	writeJSON(w, map[string]string{"active": t.Active, "iran": ir, "foreign": kh})
}

func (s *Server2) tunnelLastJob(w http.ResponseWriter, r *http.Request) {
	j := s.app.jobs.latestFor(r.URL.Query().Get("id"))
	if j == nil {
		httpErr(w, 404, "no jobs yet")
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
	var out []hv
	seen := map[string]bool{}
	if ents, err := os.ReadDir(helpersDir()); err == nil {
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(helpersDir(), e.Name()))
			if err != nil {
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
	if err := os.Rename(tmp, filepath.Join(helpersDir(), name)); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "size": n})
}
