package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The panel host's users' Google must never leave from the test account's IP.
func TestGemHomeRouteBad(t *testing.T) {
	home := &Server{IPv4: gemHomeHost()}
	other := &Server{IPv4: "159.195.78.190"}
	for _, c := range []struct {
		s        *Server
		svc, via string
		bad      bool
	}{
		{home, "GOOGLE", "direct", true},
		{home, "google", " direct ", true},
		{home, "ALL", "direct", true},
		{home, "GOOGLE", "warp6", false},
		{home, "IG", "direct", false},
		{other, "GOOGLE", "direct", false},
		{nil, "GOOGLE", "direct", false},
	} {
		if got := gemHomeRouteBad(c.s, c.svc, c.via); got != c.bad {
			t.Errorf("%v %s %s: bad=%v, want %v", c.s, c.svc, c.via, got, c.bad)
		}
	}
	if gemHomeHost() != "152.53.86.103" {
		t.Fatalf("home host %q", gemHomeHost())
	}
}

func TestGemHomeRisk(t *testing.T) {
	if gemHomeRisk(map[string]string{"google": "warp6"}) != "" {
		t.Fatal("warp6 flagged")
	}
	if !strings.Contains(gemHomeRisk(map[string]string{"google": "direct"}), "GOOGLE=direct") {
		t.Fatal("direct not flagged")
	}
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	gemHomeSeen("users on the account's IP", now)
	if !strings.Contains(gemHomeRecent(now.Add(time.Hour)), "users on the account's IP") {
		t.Fatal("recent risk lost")
	}
	if gemHomeRecent(now.Add(49*time.Hour)) != "" {
		t.Fatal("old risk kept")
	}
	gemHomeSeen("", time.Time{})
}

// The sign-out alert carries its cause.
func TestGemAcctCause(t *testing.T) {
	if c := gemAcctCause("", 12, "de", ""); !strings.Contains(c, "Google ended the session itself") {
		t.Fatalf("plain: %s", c)
	}
	if c := gemAcctCause("route GOOGLE=direct", 12, "de", ""); !strings.Contains(c, "GOOGLE=direct") || strings.Contains(c, "itself") {
		t.Fatalf("risk: %s", c)
	}
	if c := gemAcctCause("", 0, "", ""); !strings.Contains(c, "wiped") {
		t.Fatalf("wiped: %s", c)
	}
	if c := gemAcctCause("", 5, "ru", ""); !strings.Contains(c, ".ru") {
		t.Fatalf("moved: %s", c)
	}
	g := &gemAcctT{}
	t0 := time.Now()
	g.note("in", "", nil, t0)
	if !g.wentOut("out") {
		t.Fatal("in -> out not seen as going out")
	}
	m := g.note("out", "route GOOGLE=direct", nil, t0.Add(time.Minute))
	if !strings.Contains(m, "Why: route GOOGLE=direct") || g.Cause == "" {
		t.Fatalf("alert without its cause: %q", m)
	}
	if g.wentOut("out") {
		t.Fatal("still out counted as going out")
	}
	if g.note("in", "", nil, t0.Add(time.Hour)); g.Cause != "" {
		t.Fatal("cause kept after signing in")
	}
}

// The test browser opens in a window on the panel's page now: it may be framed by the panel
// only, and stays the admin's alone.
func TestGbrowserAdminOnlyAndFramedBySelf(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	cookie := func(user string) *http.Cookie {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+user+`","password":"password1"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return k
			}
		}
		t.Fatalf("no session for %s", user)
		return nil
	}
	gb := s.auth(s.guard("admin", s.gbrowser()))
	get := func(c *http.Cookie) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/gbrowser/vnc.html", nil)
		if c != nil {
			r.AddCookie(c)
		}
		securityHeaders(gb).ServeHTTP(w, r)
		return w
	}
	if w := get(nil); w.Code == 200 || w.Code == 502 {
		t.Fatalf("no session reached the test browser: %d", w.Code)
	}
	if w := get(cookie("ali")); w.Code != 403 {
		t.Fatalf("a user reached the test browser: %d", w.Code)
	}
	w := get(cookie("boss")) // nothing listens on 6077 here: the proxy answers 502
	if w.Code != 502 {
		t.Fatalf("admin: %d", w.Code)
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("framing headers: %q / %q", w.Header().Get("X-Frame-Options"), w.Header().Get("Content-Security-Policy"))
	}
}
