package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Cached servers listed after uncached ones used to be written into the result map without
// its lock while the waiters wrote it: "fatal error: concurrent map writes" on the IG page.
func TestIgInfosCachedAndRead(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	var list []*Server
	for i := 0; i < 4000; i++ {
		list = append(list, &Server{ID: fmt.Sprintf("s%d", i), Name: "x", IPv4: "198.51.100.1", Igproxy: true})
	}
	app := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	fake := &igFake{name: "f"}
	app.hostFor = func(*Server) Host { return fake }
	app.ig.mu.Lock()
	app.ig.m = map[string]igEntry{}
	for i := 1; i < len(list); i += 2 {
		app.ig.m[list[i].ID] = igEntry{info: map[string]string{"state": "OK"}, at: time.Now()}
	}
	app.ig.mu.Unlock()
	res := app.igInfos(list, false)
	if len(res) != len(list) {
		t.Fatalf("%d results for %d servers", len(res), len(list))
	}
}

// The route's switches belong to the server pair: a user changes them only where both servers
// are their own, not on the admin's servers that carry a tunnel of theirs.
func TestRouteSkipOnlyOwnPair(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s1", Name: "admin-iran", IPv4: "192.0.2.1", Role: "iran"},
			{ID: "s2", Name: "admin-de", IPv4: "192.0.2.2", Role: "foreign"},
			{ID: "u1", Name: "ali-iran", IPv4: "192.0.2.3", Role: "iran", Owner: "ali"},
			{ID: "u2", Name: "ali-de", IPv4: "192.0.2.4", Role: "foreign", Owner: "ali"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "t1", Name: "ali on admin", ServerID: "s1", ForeignID: "s2", Family: "v4", Ports: "443", Index: 1, Owner: "ali"},
			{ID: "t2", Name: "admin hs", ServerID: "s1", ForeignID: "s2", Family: "v4", Ports: "8443", Index: 2},
			{ID: "t3", Name: "ali own", ServerID: "u1", ForeignID: "u2", Family: "v4", Ports: "2053", Index: 3, Owner: "ali"},
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
	post := func(body string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/routes/skip", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(ali)
		s.routeSkip(w, r)
		return w.Code
	}
	if c := post(`{"iran":"s1","foreign":"s2","off":["gre|v4"]}`); c != 404 {
		t.Errorf("a user changing the admin pair's switches: %d, want 404", c)
	}
	if s.app.routeSkipped("s1", "s2", "gre", "v4") {
		t.Error("the admin pair's gre was switched off by a user")
	}
	if c := post(`{"iran":"u1","foreign":"u2","off":["gre|v4"]}`); c != 200 {
		t.Errorf("a user on their own pair: %d, want 200", c)
	}
	if !s.app.routeSkipped("u1", "u2", "gre", "v4") {
		t.Error("the user's own switch did not stick")
	}
}

// A port forwarder as the chosen method of a hot-standby tunnel: single ports, at most 18.
func TestHSMethodOK(t *testing.T) {
	bh, gre := methodByID["backhaul"], methodByID["gre"]
	for _, c := range []struct {
		m     *Method
		ports string
		ok    bool
	}{
		{bh, "443,8443", true},
		{bh, "2000-2010", false},
		{bh, strings.TrimSuffix(strings.Repeat("1,", 0), ","), false},
		{gre, "2000-2010", true},
	} {
		ports := c.ports
		if ports == "" { // 20 single ports
			var ps []string
			for i := 0; i < 20; i++ {
				ps = append(ps, fmt.Sprint(3000+i))
			}
			ports = strings.Join(ps, ",")
		}
		err := hsMethodOK(&Tunnel{Ports: ports, Options: map[string]map[string]string{}}, c.m)
		if (err == nil) != c.ok {
			t.Errorf("%s %s: %v, want ok=%v", c.m.ID, ports, err, c.ok)
		}
	}
}

func TestGemDomIs(t *testing.T) {
	for _, c := range []struct {
		d, want string
		ok      bool
	}{
		{"de", "de", true}, {"com.cy", "cy", true}, {"co.il", "il", true}, {"co.uk", "co.uk", true},
		{"com", "com", true}, {"com.cy", "com", false}, {"ru", "de", false}, {"", "de", false},
	} {
		if gemDomIs(c.d, c.want) != c.ok {
			t.Errorf("gemDomIs(%q, %q) = %v", c.d, c.want, !c.ok)
		}
	}
}

// A key made while building a hot-standby path is kept in its tunnel.
func TestKeepPathSecrets(t *testing.T) {
	parent := &Tunnel{ID: "abc123", Secrets: map[string]string{"old": "1"}}
	st := &State{Tunnels: []*Tunnel{parent}}
	pt := &Tunnel{ID: "abc123x7", Secrets: parent.Secrets}
	tok := pt.secret("bh-token")
	keepPathSecrets(st, pt)
	if parent.Secrets["bh-token"] != tok || parent.Secrets["old"] != "1" {
		t.Fatalf("parent secrets %v, want bh-token=%s and old=1", parent.Secrets, tok)
	}
	if pathTunnel(parent, HSPath{Method: "gre", Family: "v4", Index: 7}).secret("bh-token") != tok {
		t.Error("the next build of the path made a new token")
	}
}

func TestRenderUnitBackslash(t *testing.T) {
	u := renderUnit(Unit{Desc: `Hot standby probe uk\`, ExecStart: "/bin/true"})
	if strings.Contains(u, `\`+"\n") || !strings.Contains(u, "\nAfter=network-online.target\n") {
		t.Errorf("unit:\n%s", u)
	}
}

func TestPortOptionZero(t *testing.T) {
	if err := validateOptions(map[string]map[string]string{"backhaul": {"tunnel_port": "0"}}); err == nil {
		t.Error("port 0 accepted")
	}
	if err := validateOptions(map[string]map[string]string{"backhaul": {"tunnel_port": ""}}); err != nil {
		t.Errorf("blank port refused: %v", err)
	}
}

// emptyHost answers every script with nothing: no port is held.
type emptyHost struct{}

func (emptyHost) Label() string                                             { return "empty" }
func (emptyHost) Run(context.Context, string, func(string)) (string, error) { return "", nil }
func (emptyHost) WriteFile(string, []byte, os.FileMode) error               { return nil }

// Two users' ports never get the same internal port.
func TestFreeInternalPortTaken(t *testing.T) {
	a := &App{}
	tn := &Tunnel{Index: 1}
	q := a.freeInternalPort(context.Background(), emptyHost{}, tn, map[int]int{443: 50020})
	if q != 50021 {
		t.Errorf("got %d, want 50021 (50020 is handed out already)", q)
	}
}
