package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A user account sees and runs only its own servers and tunnels; the admin sees everything.
func TestAccountsSeparate(t *testing.T) {
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
		s.Settings.TelegramTok = "123:secret"
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
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
	ids := func(w *httptest.ResponseRecorder) string {
		var v []struct{ ID string }
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		var out []string
		for _, x := range v {
			out = append(out, x.ID)
		}
		return strings.Join(out, ",")
	}

	if got := ids(call(ali, s.servers, "GET", "/api/servers", "")); got != "s2,s3" {
		t.Errorf("user's servers: %q", got)
	}
	if got := ids(call(boss, s.servers, "GET", "/api/servers", "")); got != "s1,s2,s3" {
		t.Errorf("admin's servers: %q", got)
	}
	if got := ids(call(ali, s.tunnels, "GET", "/api/tunnels", "")); got != "t2" {
		t.Errorf("user's tunnels: %q", got)
	}
	ok := func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"ok": "1"}) }
	for _, c := range []struct {
		who        *http.Cookie
		kind, body string
		want       int
	}{
		{ali, "tunnel", `{"ID":"t1"}`, 404},
		{ali, "tunnel", `{"ID":"t2"}`, 200},
		{ali, "server", `{"ID":"s1"}`, 404},
		{ali, "server", `{"ID":""}`, 404}, // the panel host
		{ali, "server", `{"ID":"s3"}`, 200},
		{ali, "pair", `{"iranId":"s2","foreignId":"s3"}`, 200},
		{ali, "pair", `{"iranId":"s1","foreignId":"s3"}`, 404},
		{ali, "pair", `{"iranId":"s2","foreignId":""}`, 404},
		{ali, "admin", `{}`, 403},
		{boss, "admin", `{}`, 200},
		{boss, "tunnel", `{"ID":"t2"}`, 200},
	} {
		if w := call(c.who, s.guard(c.kind, ok), "POST", "/x", c.body); w.Code != c.want {
			t.Errorf("%s %s: %d, want %d", c.kind, c.body, w.Code, c.want)
		}
	}
	if w := call(ali, s.guard("tunnel", ok), "GET", "/x?id=t1", ""); w.Code != 404 {
		t.Errorf("?id of another account's tunnel: %d", w.Code)
	}

	// a user's new tunnel: on their own servers, never the panel host; owned by them
	if w := call(ali, s.tunnelSave, "POST", "/api/tunnels/save", `{"name":"x","serverId":"s1","foreignId":"s3","ports":"9000"}`); w.Code != 400 {
		t.Errorf("tunnel on the admin's Iran server: %d", w.Code)
	}
	if w := call(ali, s.tunnelSave, "POST", "/api/tunnels/save", `{"name":"x","serverId":"s2","foreignId":"","ports":"9000"}`); w.Code != 400 {
		t.Errorf("tunnel to the panel host: %d", w.Code)
	}
	if w := call(ali, s.tunnelSave, "POST", "/api/tunnels/save", `{"name":"x","serverId":"s2","foreignId":"s3","ports":"9000","owner":"boss","applying":"gre"}`); w.Code != 200 {
		t.Fatalf("own tunnel: %d %s", w.Code, w.Body)
	}
	st.View(func(s *State) {
		n := s.Tunnels[len(s.Tunnels)-1]
		if n.Owner != "ali" || n.Applying != "" {
			t.Errorf("new tunnel owner %q applying %q", n.Owner, n.Applying)
		}
	})
	// editing another account's tunnel
	if w := call(ali, s.tunnelSave, "POST", "/api/tunnels/save", `{"ID":"t1","name":"mine","serverId":"s2","foreignId":"s3","ports":"443"}`); w.Code != 400 {
		t.Errorf("edit of the admin's tunnel: %d", w.Code)
	}
	// servers: a user's new server is theirs, and can't jump through the admin's
	if w := call(ali, s.servers, "POST", "/api/servers", `{"name":"n","ipv4":"203.0.113.9","via":"s1"}`); w.Code != 400 {
		t.Errorf("jump through the admin's server: %d", w.Code)
	}
	if w := call(ali, s.servers, "POST", "/api/servers", `{"name":"n","ipv4":"203.0.113.9","owner":"boss"}`); w.Code != 200 {
		t.Fatalf("own server: %d %s", w.Code, w.Body)
	}
	st.View(func(s *State) {
		if o := s.Servers[len(s.Servers)-1].Owner; o != "ali" {
			t.Errorf("new server owner %q", o)
		}
	})
	if w := call(ali, s.servers, "POST", "/api/servers", `{"ID":"s1","name":"taken","ipv4":"192.0.2.1"}`); w.Code != 400 {
		t.Errorf("edit of the admin's server: %d", w.Code)
	}
	// settings: a user gets the panel name, no secrets, and can't save
	if b := call(ali, s.settings, "GET", "/api/settings", "").Body.String(); strings.Contains(b, "telegram") || strings.Contains(b, "agentPin") {
		t.Errorf("user sees settings: %s", b)
	}
	if w := call(ali, s.settings, "POST", "/api/settings", `{"panelName":"x"}`); w.Code != 403 {
		t.Errorf("user saved settings: %d", w.Code)
	}
	// jump hosts: only the same account's servers
	_ = st.Update(func(s *State) error {
		for _, x := range s.Servers {
			x.Prepared = true
		}
		return nil
	})
	for _, o := range s.app.otherServers("s2") {
		if o.Owner != "ali" {
			t.Errorf("jump host %s (%q) offered for ali's server", o.ID, o.Owner)
		}
	}
}

// The admin manages accounts; a user can't, and can't be deleted while it owns something.
func TestUserAdmin(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	login := func(u, p string) *http.Cookie {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+u+`","password":"`+p+`"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return k
			}
		}
		return nil
	}
	post := func(c *http.Cookie, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(c)
		h(w, r)
		return w
	}
	boss := login("boss", "password1")
	users := s.guard("admin", s.users)
	if w := post(boss, users, `{"Username":"ali","Password":"alipass1","Role":"user"}`); w.Code != 200 {
		t.Fatalf("create user: %d %s", w.Code, w.Body)
	}
	ali := login("ali", "alipass1")
	if ali == nil {
		t.Fatal("new user can't sign in")
	}
	if w := post(ali, users, `{"Username":"eve","Password":"evepass1"}`); w.Code != 403 {
		t.Errorf("user created an account: %d", w.Code)
	}
	if w := post(boss, users, `{"Username":"boss","Role":"user"}`); w.Code != 400 {
		t.Errorf("admin demoted itself: %d", w.Code)
	}
	_ = st.Update(func(s *State) error {
		s.Servers = append(s.Servers, &Server{ID: "s9", Name: "ali-srv", Owner: "ali"})
		return nil
	})
	del := s.guard("admin", s.userDelete)
	if w := post(boss, del, `{"Username":"ali"}`); w.Code != 400 {
		t.Errorf("deleted a user that owns a server: %d", w.Code)
	}
	if w := post(boss, s.guard("admin", s.owner), `{"Kind":"server","ID":"s9","Owner":""}`); w.Code != 200 {
		t.Fatalf("take the server back: %d %s", w.Code, w.Body)
	}
	if w := post(boss, del, `{"Username":"ali"}`); w.Code != 200 {
		t.Errorf("delete user: %d %s", w.Code, w.Body)
	}
	if login("ali", "alipass1") != nil {
		t.Error("deleted user can still sign in")
	}
}
