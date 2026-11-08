package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A handler that reads ?id (status, lastjob, bench results) answered a POST whose body named
// the user's own tunnel while ?id named the admin's: every name in the request is checked now.
func TestGuardPostWithQuery(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{{ID: "s1", Name: "admin-iran", IPv4: "192.0.2.1", Role: "iran"}, {ID: "s2", Name: "ali-iran", IPv4: "192.0.2.2", Role: "iran", Owner: "ali"}, {ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"}}
		s.Tunnels = []*Tunnel{{ID: "t1", Name: "admin tunnel", ServerID: "s1", Family: "v4", Ports: "443", Index: 1, LastJob: "x"}, {ID: "t2", Name: "ali tunnel", ServerID: "s2", ForeignID: "s3", Family: "v4", Ports: "8443", Index: 2, Owner: "ali"}}
		return nil
	})
	app := &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon()}
	s := &Server2{app: app, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"ali","password":"password1"}`)))
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			c = k
		}
	}
	mux := app.routes()
	for _, p := range []string{"/api/tunnels/lastjob?id=t1", "/api/tunnels/status?id=t1", "/api/bench/results?iran=s1&foreign=s3", "/api/servers/console?id=s1"} {
		for _, m := range []string{"POST", "PUT"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(m, p, strings.NewReader(`{"ID":"t2","IranID":"s2","ForeignID":"s3"}`))
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(c)
			mux.ServeHTTP(w, r)
			if w.Code != 404 || !strings.Contains(w.Body.String(), "not found") {
				t.Errorf("%s %s -> %d %.120s", m, p, w.Code, strings.TrimSpace(w.Body.String()))
			}
		}
	}
}
