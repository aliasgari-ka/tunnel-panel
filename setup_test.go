package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A fresh panel can't be claimed without the setup code; the right code works once.
func TestRegisterNeedsSetupCode(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	var code string
	st.View(func(s *State) { code = s.SetupCode })
	if len(code) != 14 {
		t.Fatalf("no setup code on a fresh store: %q", code)
	}
	s := &Server2{app: &App{store: st, jobs: newJobs()}, failures: map[string][]time.Time{}}
	try := func(c string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/register", strings.NewReader(`{"username":"admin","password":"longenough1","code":"`+c+`"}`))
		r.Header.Set("Content-Type", "application/json")
		s.register(w, r)
		return w.Code
	}
	if c := try(""); c != 403 {
		t.Errorf("no code: %d", c)
	}
	if c := try("aaaa-bbbb-cccc"); c != 403 {
		t.Errorf("wrong code: %d", c)
	}
	if c := try(" " + strings.ToUpper(code) + " "); c != 200 {
		t.Errorf("right code: %d", c)
	}
	if c := try(code); c != 409 {
		t.Errorf("second account: %d", c)
	}
	st.View(func(s *State) { code = s.SetupCode })
	if code != "" {
		t.Error("code not cleared after use")
	}
}

// Sign-out and a password change end the sessions issued before; the browser that changed
// the password stays signed in.
func TestSessionsEnd(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error { s.Users = []User{{Username: "admin", Hash: string(h)}}; return nil })
	s := &Server2{app: &App{store: st, jobs: newJobs()}, failures: map[string][]time.Time{}}
	login := func() *http.Cookie {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"oldpassword"}`))
		s.login(w, r)
		return w.Result().Cookies()[0]
	}
	who := func(c *http.Cookie) string {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.AddCookie(c)
		return s.currentUser(r)
	}
	a, b := login(), login()
	if who(a) != "admin" || who(b) != "admin" {
		t.Fatal("login doesn't work")
	}
	// sign out in browser a: its cookie (and a copy of it) is refused from now on
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/logout", nil)
	r.AddCookie(a)
	s.logout(w, r)
	if who(a) != "" {
		t.Error("a signed-out cookie still works")
	}
	// password change in browser c: c stays in with its new cookie, older ones (d) end
	c, d := login(), login()
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/password", strings.NewReader(`{"Old":"oldpassword","New":"newpassword1"}`))
	r.AddCookie(c)
	s.password(w, r)
	if w.Code != 200 {
		t.Fatalf("password change: %d %s", w.Code, w.Body)
	}
	if who(d) != "" {
		t.Error("a session from before the password change still works")
	}
	var nc *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			nc = k
		}
	}
	if nc == nil || who(nc) != "admin" {
		t.Error("the browser that changed the password was signed out")
	}
}
