package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The guard and the handler read the same names: a body with junk after the JSON (the
// guard's Unmarshal failed and it checked ?id, the handler's Decoder took the body's ID) and
// a GET with a body (the guard checked the body, the handler read ?id) both reached the
// admin's servers from a user account.
func TestGuardSameNamesAsHandler(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s1", Name: "admin-iran", IPv4: "192.0.2.1", Role: "iran"},
			{ID: "s2", Name: "ali-iran", IPv4: "192.0.2.2", Role: "iran", Owner: "ali"},
			{ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "t1", Name: "admin tunnel", ServerID: "s1", Family: "v4", Ports: "443", Index: 1},
			{ID: "t2", Name: "ali tunnel", ServerID: "s2", ForeignID: "s3", Family: "v4", Ports: "8443", Index: 2, Owner: "ali"},
		}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"ali","password":"password1"}`)))
	var ali *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			ali = k
		}
	}
	reached := ""
	probe := func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID string }
		if r.Method == http.MethodGet {
			in.ID = r.URL.Query().Get("id")
		} else {
			_ = readJSON(r, &in)
		}
		reached = in.ID
		writeJSON(w, map[string]string{"ok": "1"})
	}
	call := func(kind, method, path, body string) (int, string) {
		reached = ""
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(ali)
		s.guard(kind, probe)(w, r)
		return w.Code, reached
	}
	for _, c := range []struct {
		kind, method, path, body string
	}{
		{"server", "POST", "/api/servers/delete?id=s2", `{"ID":"s1"} x`},
		{"server", "POST", "/api/servers/delete?id=s2", `{"ID":"s1"}{"ID":"s2"}`},
		{"server", "POST", "/api/servers/delete?id=s1", `{"ID":"s2"}`},
		{"server", "GET", "/api/servers/console?id=s1", `{"ID":"s2"}`},
		{"tunnel", "GET", "/api/tunnels/lastjob?id=t1", `{"ID":"t2"}`},
		{"pair", "GET", "/api/bench/results?iran=s1&foreign=s3", `{"IranID":"s2","ForeignID":"s3"}`},
	} {
		if code, got := call(c.kind, c.method, c.path, c.body); got != "" || code == 200 {
			t.Errorf("%s %s %s: %d, the handler reached %q", c.method, c.path, c.body, code, got)
		}
	}
	// the user's own requests still go through
	for _, c := range []struct {
		kind, method, path, body, want string
	}{
		{"server", "POST", "/api/servers/test", `{"ID":"s2"}`, "s2"},
		{"server", "POST", "/api/servers/test?id=s2", `{"ID":"s2"}`, "s2"},
		{"tunnel", "GET", "/api/tunnels/status?id=t2", "", "t2"},
		{"pair", "GET", "/api/bench/results?iran=s2&foreign=s3", "", ""},
	} {
		if code, got := call(c.kind, c.method, c.path, c.body); code != 200 || got != c.want {
			t.Errorf("own %s %s %s: %d, reached %q", c.method, c.path, c.body, code, got)
		}
	}
}
