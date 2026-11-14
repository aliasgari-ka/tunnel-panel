package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// hunt2Env is a panel with an admin (boss) and a user (ali), both "password1".
type hunt2Env struct {
	t  *testing.T
	st *Store
	a  *App
	s  *Server2
}

func newHunt2Env(t *testing.T, setup func(*State)) *hunt2Env {
	t.Helper()
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s1", Name: "admin-iran", IPv4: "192.0.2.1", Role: "iran"},
			{ID: "s2", Name: "ali-iran", IPv4: "192.0.2.2", Role: "iran", Owner: "ali"},
			{ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
		}
		if setup != nil {
			setup(s)
		}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	return &hunt2Env{t: t, st: st, a: a, s: &Server2{app: a, failures: map[string][]time.Time{}}}
}

func (e *hunt2Env) login(u, pw string) *http.Cookie {
	e.t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, u, pw)))
	r.RemoteAddr = "192.0.2.200:1000"
	e.s.login(w, r)
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			return k
		}
	}
	return nil
}

func (e *hunt2Env) cookie(u string) *http.Cookie {
	e.t.Helper()
	c := e.login(u, "password1")
	if c == nil {
		e.t.Fatalf("no session for %s", u)
	}
	return c
}

func (e *hunt2Env) call(c *http.Cookie, h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if c != nil {
		r.AddCookie(c)
	}
	h(w, r)
	return w
}

func (e *hunt2Env) user(name string) (User, bool) {
	var out User
	ok := false
	e.st.View(func(st *State) {
		for _, u := range st.Users {
			if u.Username == name {
				out, ok = u, true
			}
		}
	})
	return out, ok
}

// A password over bcrypt's 72 bytes is refused everywhere; it used to store an empty hash
// (register: an account nobody could sign in to and setup gone; users: the same; password:
// "changed" with the old one wiped).
func TestHunt2LongPassword(t *testing.T) {
	long := strings.Repeat("p", 80)

	// register on an empty panel
	e := newHunt2Env(t, func(s *State) { s.Users, s.SetupCode = nil, "abcdefabcdef" })
	w := e.call(nil, e.s.register, "POST", "/api/register", fmt.Sprintf(`{"username":"root","password":%q,"code":"abcdefabcdef"}`, long))
	if w.Code != 400 {
		t.Fatalf("register with an 80-byte password: %d %s", w.Code, w.Body)
	}
	var code string
	var n int
	e.st.View(func(st *State) { code, n = st.SetupCode, len(st.Users) })
	if n != 0 || code == "" {
		t.Fatalf("register stored an account (%d) or used up the setup code (%q)", n, code)
	}
	// an already configured panel says so before any hashing
	e2 := newHunt2Env(t, nil)
	if w := e2.call(nil, e2.s.register, "POST", "/api/register", `{"username":"x","password":"password9","code":"zzz"}`); w.Code != 409 {
		t.Fatalf("register on a configured panel: %d", w.Code)
	}

	// /api/users
	e = newHunt2Env(t, nil)
	boss := e.cookie("boss")
	if w := e.call(boss, e.s.users, "POST", "/api/users", fmt.Sprintf(`{"username":"neo","password":%q,"role":"user"}`, long)); w.Code != 400 {
		t.Fatalf("users with an 80-byte password: %d", w.Code)
	}
	if _, ok := e.user("neo"); ok {
		t.Fatal("account created with an unusable password")
	}
	if w := e.call(boss, e.s.users, "POST", "/api/users", fmt.Sprintf(`{"username":"ali","password":%q}`, long)); w.Code != 400 {
		t.Fatalf("users password change with 80 bytes: %d", w.Code)
	}

	// /api/password
	ali := e.cookie("ali")
	if w := e.call(ali, e.s.password, "POST", "/api/password", fmt.Sprintf(`{"old":"password1","new":%q}`, long)); w.Code != 400 {
		t.Fatalf("password change to 80 bytes: %d %s", w.Code, w.Body)
	}
	if u, _ := e.user("ali"); u.Hash == "" || bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte("password1")) != nil {
		t.Fatal("the old password no longer works after a refused change")
	}
}

// POST /api/users for an existing account without a role keeps its role (a password reset
// by the admin made a user an admin).
func TestHunt2UsersKeepsRole(t *testing.T) {
	e := newHunt2Env(t, nil)
	boss := e.cookie("boss")
	if w := e.call(boss, e.s.users, "POST", "/api/users", `{"username":"ali","password":"newpassword"}`); w.Code != 200 {
		t.Fatalf("password reset: %d %s", w.Code, w.Body)
	}
	if u, _ := e.user("ali"); u.Role != roleUser {
		t.Fatalf("ali's role became %q", u.Role)
	}
	// a new account without a role is still an admin, an explicit role still changes it
	if w := e.call(boss, e.s.users, "POST", "/api/users", `{"username":"neo","password":"newpassword"}`); w.Code != 200 {
		t.Fatalf("create: %d", w.Code)
	}
	if u, _ := e.user("neo"); !isAdminRole(u.Role) {
		t.Fatalf("new account role %q", u.Role)
	}
	if w := e.call(boss, e.s.users, "POST", "/api/users", `{"username":"ali","role":"admin"}`); w.Code != 200 {
		t.Fatalf("promote: %d", w.Code)
	}
	if u, _ := e.user("ali"); !isAdminRole(u.Role) {
		t.Fatal("explicit role not applied")
	}
}

// /api/logout takes POST only: a GET from a link signed out every session of the account.
func TestHunt2LogoutPostOnly(t *testing.T) {
	e := newHunt2Env(t, nil)
	ali := e.cookie("ali")
	before, _ := e.user("ali")
	h := e.a.routes()
	r := httptest.NewRequest("GET", "/api/logout", nil)
	r.AddCookie(ali)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatalf("GET /api/logout: %d", w.Code)
	}
	if after, _ := e.user("ali"); after.Gen != before.Gen {
		t.Fatal("a GET ended the sessions")
	}
	r = httptest.NewRequest("POST", "/api/logout", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(ali)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if after, _ := e.user("ali"); w.Code != 200 || after.Gen == before.Gen {
		t.Fatalf("POST /api/logout: %d", w.Code)
	}
}

// The sign-in limit counts an IPv6 /64 as one address, also counts per username, and old
// entries are swept.
func TestHunt2LoginLimiter(t *testing.T) {
	e := newHunt2Env(t, nil)
	try := func(ip, user string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":"wrong-one"}`, user)))
		r.RemoteAddr = ip
		e.s.login(w, r)
		return w.Code
	}
	for i := 1; i <= 5; i++ {
		if c := try(fmt.Sprintf("[2001:db8:1:2::%x]:1000", i), "boss"); c != 401 {
			t.Fatalf("try %d: %d", i, c)
		}
	}
	if c := try("[2001:db8:1:2::ffff]:1000", "boss"); c != 429 {
		t.Fatalf("a 6th try from the same /64: %d, want 429", c)
	}
	if c := try("[2001:db8:1:3::1]:1000", "boss"); c != 401 {
		t.Fatalf("another /64: %d", c)
	}

	// one name from many addresses
	e = newHunt2Env(t, nil)
	for i := 1; i <= loginMaxUser; i++ {
		if c := try(fmt.Sprintf("198.51.100.%d:1000", i), "boss"); c != 401 {
			t.Fatalf("user try %d: %d", i, c)
		}
	}
	// past the per-name limit a try is slowed down, not refused: a few addresses guessing
	// must not keep the real owner out
	loginSlow = 50 * time.Millisecond
	defer func() { loginSlow = 3 * time.Second }()
	t0 := time.Now()
	if c := try("203.0.113.1:1000", "boss"); c != 401 {
		t.Fatalf("try %d on one username: %d, want 401 (slowed)", loginMaxUser+1, c)
	}
	if time.Since(t0) < loginSlow {
		t.Fatalf("try past the per-name limit was not slowed down")
	}
	if c := try("203.0.113.2:1000", "ali"); c != 401 {
		t.Fatalf("another username: %d", c)
	}

	// the sweep forgets keys whose tries are old
	old := time.Now().Add(-time.Hour)
	e.s.failMu.Lock()
	for i := 0; i < 100; i++ {
		e.s.failures[fmt.Sprintf("10.0.0.%d", i)] = []time.Time{old}
	}
	e.s.swept = time.Time{}
	e.s.failMu.Unlock()
	try("203.0.113.3:1000", "ali")
	e.s.failMu.Lock()
	n := 0
	for k := range e.s.failures {
		if strings.HasPrefix(k, "10.0.0.") {
			n++
		}
	}
	e.s.failMu.Unlock()
	if n != 0 {
		t.Fatalf("%d old keys left after the sweep", n)
	}
}

// reset-password is refused while the service runs: its next save overwrote the change.
func TestHunt2ResetPasswordWhileRunning(t *testing.T) {
	dir := t.TempDir()
	st, _ := LoadStore(dir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error { s.Users = []User{{Username: "admin", Hash: string(h)}}; return nil })
	old := panelServiceActive
	defer func() { panelServiceActive = old }()
	panelServiceActive = func() bool { return true }
	if err := resetPassword(dir, "admin", "newpassword"); err == nil || !strings.Contains(err.Error(), "systemctl stop tunnel-panel") {
		t.Fatalf("reset while the service runs: %v", err)
	}
	if err := resetPassword(dir, "admin", ""); err == nil {
		t.Fatal("clearing the accounts while the service runs was allowed")
	}
	st2, _ := LoadStore(dir)
	var hash string
	st2.View(func(s *State) {
		if len(s.Users) == 1 {
			hash = s.Users[0].Hash
		}
	})
	if hash != string(h) {
		t.Fatal("the state changed")
	}
	panelServiceActive = func() bool { return false }
	if err := resetPassword(dir, "admin", strings.Repeat("x", 80)); err == nil {
		t.Fatal("an 80-byte password was accepted")
	}
	if err := resetPassword(dir, "admin", "newpassword"); err != nil {
		t.Fatal(err)
	}
}
