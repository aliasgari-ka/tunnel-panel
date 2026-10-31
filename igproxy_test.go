package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestIgParseInfo(t *testing.T) {
	ok := "noise\nig=direct google=warp router=active redirect=ON panel=OK gem=OK igp=OK sum=abc12345"
	for _, c := range []struct {
		rc        int
		text, sum string
		want      string
	}{
		{0, ok, "abc12345", "OK"},
		{0, ok, "fff00000", "UPDATE"},
		{0, strings.Replace(ok, "router=active", "router=failed", 1), "", "DOWN"},
		{0, strings.Replace(ok, "panel=OK", "panel=BLOCK", 1), "", "PANEL"},
		{0, strings.Replace(ok, "gem=OK", "gem=FAIL", 1), "", "GEMFAIL"},
		{0, ok + " paused=YES", "", "PAUSED"},
		{3, "igproxy is not installed here", "", "NOAGENT"},
		{1, "usage: igproxy", "", "UPDATE"},
		{255, "dial tcp: i/o timeout", "", "OFFLINE"},
	} {
		if got := igParseInfo(c.rc, c.text, c.sum)["state"]; got != c.want {
			t.Errorf("rc %d %q: state %s, want %s", c.rc, c.text, got, c.want)
		}
	}
	// a server that never answered must not show key=value pairs from an error text
	if inf := igParseInfo(255, "x ig=1 router=active", ""); inf["state"] != "OFFLINE" || inf["ig"] != "" {
		t.Errorf("unreached server parsed as an answer: %v", inf)
	}
}

func TestIgBuild(t *testing.T) {
	bad := []map[string]any{
		{"action": "route", "svc": "IG", "via": "proxy; reboot"},
		{"action": "route", "svc": "NETFLIX", "via": "warp"},
		{"action": "proxy_add", "host": "1.2.3.4;id", "port": "80"},
		{"action": "proxy_add", "host": "1.2.3.4", "port": "80", "user": "a b"},
		{"action": "set", "key": "evil", "val": "on"},
		{"action": "set", "key": "minspeed", "val": "1;id"},
		{"action": "set", "key": "gcountries", "val": "USA"},
		{"action": "logs", "n": "0"},
		{"action": "custom_add", "site": "a.com", "route": "warp6"},
		{"action": "tg_setup", "token": "nope"},
		{"action": "rm"},
	}
	for _, p := range bad {
		if _, err := igBuild(igStr(p["action"]), p); err == nil {
			t.Errorf("accepted %v", p)
		}
	}
	c, err := igBuild("proxy_add", map[string]any{"type": "socks5", "host": "1.2.3.4", "port": float64(1080), "user": "u", "pass": "p'w"})
	if err != nil || strings.Join(c.args, " ") != "proxy add -" || c.input != "socks5 1.2.3.4 1080 u p'w" {
		t.Errorf("proxy_add: %+v %v", c, err)
	}
	c, err = igBuild("set", map[string]any{"key": "gcountries", "val": "us, gb  de"})
	if err != nil || strings.Join(c.args, " ") != "set gcountries US GB DE" {
		t.Errorf("gcountries: %+v %v", c, err)
	}
	// secrets go in on stdin, quoted, never as an argument of a process
	sc := igScript([]string{"gemkey", "set", "-"}, "AIza'secret", 120)
	if !strings.Contains(sc, `printf '%s\n' 'AIza'"'"'secret' | timeout 120 igproxy 'gemkey' 'set' '-'`) {
		t.Errorf("script:\n%s", sc)
	}
	if sc := igScript([]string{"info"}, "", 20); !strings.Contains(sc, "timeout 20 igproxy 'info' </dev/null") {
		t.Errorf("script:\n%s", sc)
	}
}

// igFake answers every igproxy command like a healthy agent and records what it ran.
type igFake struct {
	mu   sync.Mutex
	name string
	ran  []string
}

func (h *igFake) Label() string { return h.name }
func (h *igFake) Run(ctx context.Context, script string, log func(string)) (string, error) {
	h.mu.Lock()
	h.ran = append(h.ran, script)
	h.mu.Unlock()
	out := "ig=direct router=active redirect=ON sum=-\n__RC=0"
	for _, l := range strings.Split(out, "\n") {
		if log != nil {
			log(l)
		}
	}
	return out, nil
}
func (h *igFake) WriteFile(string, []byte, os.FileMode) error { return nil }
func (h *igFake) count() int                                  { h.mu.Lock(); defer h.mu.Unlock(); return len(h.ran) }

// A user sees and runs igproxy only on its own servers; the admin's servers and the panel
// host itself stay out of its reach.
func TestIgAccess(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	pw, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(pw)}, {Username: "ali", Hash: string(pw), Role: roleUser}}
		s.Settings.LocalIPv4 = "203.0.113.9"
		s.Servers = []*Server{
			{ID: "a1", Name: "admin-de", IPv4: "198.51.100.1", Role: "foreign", Igproxy: true},
			{ID: "u1", Name: "ali-de", IPv4: "198.51.100.2", Role: "foreign", Owner: "ali", Igproxy: true},
			{ID: "u2", Name: "ali-nl", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
			{ID: "u3", Name: "ali-sneaky", IPv4: "203.0.113.9", Role: "foreign", Owner: "ali"},
		}
		return nil
	})
	app := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	hosts := map[string]*igFake{}
	for _, id := range []string{"a1", "u1", "u2"} {
		hosts[id] = &igFake{name: id}
	}
	app.hostFor = func(s *Server) Host {
		if h, ok := hosts[s.ID]; ok {
			return h
		}
		return nil
	}
	s := &Server2{app: app, failures: map[string][]time.Time{}}
	cookie := func(u string) *http.Cookie {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+u+`","password":"password1"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return k
			}
		}
		t.Fatalf("no session for %s", u)
		return nil
	}
	boss, ali := cookie("boss"), cookie("ali")
	call := func(c *http.Cookie, h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(c)
		h(w, r)
		return w
	}
	list := func(c *http.Cookie) (srv, cand string) {
		var v struct {
			Servers    []struct{ ID string }
			Candidates []struct{ ID string }
		}
		_ = json.Unmarshal(call(c, s.igServers, "GET", "/api/igproxy/servers", "").Body.Bytes(), &v)
		var a, b []string
		for _, x := range v.Servers {
			a = append(a, x.ID)
		}
		for _, x := range v.Candidates {
			b = append(b, x.ID)
		}
		return strings.Join(a, ","), strings.Join(b, ",")
	}
	if srv, cand := list(ali); srv != "u1" || cand != "u2,u3" {
		t.Errorf("user sees servers %q, candidates %q", srv, cand)
	}
	if srv, _ := list(boss); srv != "a1,u1" {
		t.Errorf("admin sees %q", srv)
	}
	wait := func(w *httptest.ResponseRecorder) string {
		var v struct{ Job, Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		if v.Job == "" {
			return "refused: " + v.Error
		}
		for i := 0; i < 100; i++ {
			if j := app.jobs.get(v.Job).snapshot(); j.Status != "running" {
				return j.Status
			}
			time.Sleep(20 * time.Millisecond)
		}
		return "timeout"
	}
	before := hosts["a1"].count()
	if got := wait(call(ali, s.igAction, "POST", "/api/igproxy/action", `{"srv":"a1","action":"apply"}`)); !strings.HasPrefix(got, "refused") {
		t.Errorf("user ran igproxy on the admin's server: %s", got)
	}
	if got := wait(call(ali, s.igAction, "POST", "/api/igproxy/action", `{"srv":["u1","a1"],"action":"apply"}`)); !strings.HasPrefix(got, "refused") {
		t.Errorf("user ran igproxy on a list with the admin's server: %s", got)
	}
	if got := wait(call(ali, s.igAction, "POST", "/api/igproxy/action", `{"srv":"all","action":"apply","view":""}`)); got != "ok" {
		t.Errorf("user's apply on all: %s", got)
	}
	if hosts["a1"].count() != before {
		t.Errorf("the admin's server ran a user's command")
	}
	if hosts["u1"].count() == 0 {
		t.Errorf("the user's own server ran nothing")
	}
	// a user's server with the panel host's address can't join (it would run as root here)
	if w := call(ali, s.igEnable, "POST", "/api/igproxy/enable", `{"ID":"u3","On":true}`); w.Code != 400 {
		t.Errorf("panel host as a user's igproxy server: %d %s", w.Code, w.Body)
	}
	if got := wait(call(ali, s.igEnable, "POST", "/api/igproxy/enable", `{"ID":"u2","On":true}`)); got != "ok" {
		t.Errorf("enable own server: %s", got)
	}
	if srv, _ := list(ali); srv != "u1,u2" {
		t.Errorf("after enable the user sees %q", srv)
	}
	if w := call(ali, s.igEnable, "POST", "/api/igproxy/enable", `{"ID":"a1","On":false}`); w.Code != 404 {
		t.Errorf("user took the admin's server off the page: %d", w.Code)
	}
	// the admin's view filter narrows "all"
	tl, _ := s.igTargets("boss", true, "all", "-")
	if len(tl) != 1 || tl[0].ID != "a1" {
		t.Errorf("admin's own view: %v", tl)
	}
	// backups: a user lists and restores only its own
	if _, err := igSaveBackup(st.Server("a1"), "ADMINDATA"); err != nil {
		t.Fatal(err)
	}
	name, _ := igSaveBackup(st.Server("u1"), "ALIDATA")
	var bl struct{ Files []igBackupFile }
	_ = json.Unmarshal(call(ali, s.igBackupList, "GET", "/api/igproxy/backups", "").Body.Bytes(), &bl)
	if len(bl.Files) != 1 || bl.Files[0].File != name || bl.Files[0].Server != "u1" {
		t.Errorf("user's backups: %+v", bl.Files)
	}
	adminFile := igBackups([]string{""})[0].File
	if got := wait(call(ali, s.igRestore, "POST", "/api/igproxy/restore", `{"File":"`+adminFile+`","Owner":"","Srv":"u1"}`)); !strings.HasPrefix(got, "refused") {
		t.Errorf("user restored the admin's backup: %s", got)
	}
	if got := wait(call(ali, s.igRestore, "POST", "/api/igproxy/restore", `{"File":"../../state.json","Srv":"u1"}`)); !strings.HasPrefix(got, "refused") {
		t.Errorf("restore read a file outside the backups: %s", got)
	}
}

func TestIgImport(t *testing.T) {
	dataDir = t.TempDir()
	old := t.TempDir()
	igpmDir, igpanelUsers = filepath.Join(old, "igpm"), filepath.Join(old, "users")
	defer func() { igpmDir, igpanelUsers = "/etc/igpm", "/etc/igpanel/users" }()
	_ = os.MkdirAll(filepath.Join(igpmDir, "backup"), 0o700)
	_ = os.MkdirAll(filepath.Join(igpanelUsers, "ali"), 0o700)
	_ = os.WriteFile(filepath.Join(igpmDir, "servers"), []byte("de 198.51.100.1 22 root\nlocal local 0 root\ngone 192.0.2.99 22 root\n"), 0o600)
	_ = os.WriteFile(filepath.Join(igpanelUsers, "ali", "servers"), []byte("x 198.51.100.1 22 root\n"), 0o600)
	// the old backup name: <name>-<sha1(host:port:user)[:10]>-<stamp>.igpx
	sum := sha1.Sum([]byte("198.51.100.1:22:root"))
	_ = os.WriteFile(filepath.Join(igpmDir, "backup", "de-"+hex.EncodeToString(sum[:])[:10]+"-2026-10-30-101010.igpx"), []byte("X"), 0o600)
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Settings.LocalIPv4 = "203.0.113.9"
		s.Users = []User{{Username: "ali", Role: roleUser}}
		s.Servers = []*Server{
			{ID: "aaaaaaaaaaaa", Name: "de", IPv4: "198.51.100.1", Role: "foreign"},
			{ID: "bbbbbbbbbbbb", Name: "panel", IPv4: "203.0.113.9", Role: "foreign"},
			{ID: "cccccccccccc", Name: "ali-de", IPv4: "198.51.100.1", Role: "foreign", Owner: "ali"},
			{ID: "dddddddddddd", Name: "other", IPv4: "198.51.100.7", Role: "foreign"},
		}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	a.igImport()
	want := map[string]bool{"aaaaaaaaaaaa": true, "bbbbbbbbbbbb": true, "cccccccccccc": true, "dddddddddddd": false}
	for id, w := range want {
		if got := st.Server(id).Igproxy; got != w {
			t.Errorf("%s igproxy=%v, want %v", id, got, w)
		}
	}
	if b := igBackups([]string{""}); len(b) != 1 || b[0].File != "aaaaaaaaaaaa-2026-10-30-101010.igpx" || b[0].Server != "aaaaaaaaaaaa" {
		t.Errorf("migrated backups: %+v", b)
	}
	// a second start doesn't import again (a server taken off the page stays off)
	_ = st.Update(func(s *State) error { s.Servers[0].Igproxy = false; return nil })
	a.igImport()
	if st.Server("aaaaaaaaaaaa").Igproxy {
		t.Errorf("imported twice")
	}
}
