package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The account form renames the user and/or sets a new password; it needs the current
// password, refuses a bad or taken name, and keeps the changing browser signed in.
func TestAccountRename(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "admin", Hash: string(h)}, {Username: "other", Hash: string(h)}}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs()}, failures: map[string][]time.Time{}}
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
	change := func(c *http.Cookie, body string) (*httptest.ResponseRecorder, *http.Cookie) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/password", strings.NewReader(body))
		r.AddCookie(c)
		s.password(w, r)
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return w, k
			}
		}
		return w, nil
	}
	who := func(c *http.Cookie) string {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.AddCookie(c)
		return s.currentUser(r)
	}
	c := login("admin", "oldpassword")
	for _, bad := range []string{
		`{"Old":"wrong","NewUser":"boss"}`,        // wrong current password
		`{"Old":"oldpassword","NewUser":"other"}`, // taken
		`{"Old":"oldpassword","NewUser":"a b"}`,   // bad characters
		`{"Old":"oldpassword","New":"short"}`,     // too short
		`{"Old":"oldpassword"}`,                   // nothing to change
	} {
		if w, _ := change(c, bad); w.Code != 400 {
			t.Errorf("%s: %d, want 400", bad, w.Code)
		}
	}
	w, nc := change(c, `{"Old":"oldpassword","NewUser":"boss"}`)
	if w.Code != 200 || nc == nil || who(nc) != "boss" {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	if login("boss", "oldpassword") == nil || who(login("boss", "oldpassword")) != "boss" {
		t.Error("the renamed account can't sign in with its password")
	}
	if who(c) != "" {
		t.Error("the session from before the rename still works")
	}
	w, nc = change(nc, `{"Old":"oldpassword","New":"newpassword1","NewUser":"chief"}`)
	if w.Code != 200 || who(nc) != "chief" || who(login("chief", "newpassword1")) != "chief" {
		t.Fatalf("rename + new password: %d %s", w.Code, w.Body)
	}
}

// Backhaul / Premium configs with default options are what the methods always produced;
// the new tuning options reach the configs and bad heartbeats are refused.
func TestBackhaulOptions(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	tun := func(opts map[string]map[string]string) *Tunnel {
		return &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "443", Index: 3, Options: opts, Secrets: map[string]string{}}
	}
	ir, kh, err := buildPlans(methodBackhaul, tun(nil), srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	all := func(p SidePlan) string {
		var b strings.Builder
		for _, f := range p.Files {
			b.Write(f.Content)
		}
		return b.String()
	}
	for _, want := range []string{"keepalive_period = 75", "heartbeat = 40", "channel_size = 4096", "accept_udp = false", `log_level = "info"`} {
		if !strings.Contains(all(ir), want) {
			t.Errorf("backhaul Iran default config lacks %q", want)
		}
	}
	if !strings.Contains(all(kh), "connection_pool = 8") {
		t.Error("backhaul foreign default config lacks connection_pool = 8")
	}
	ir, kh, _ = buildPlans(methodBackhaul, tun(map[string]map[string]string{"backhaul": {"transport": "tcp", "heartbeat": "20", "connection_pool": "24", "log_level": "warn"}}), srv, fsrv, Settings{})
	for _, want := range []string{"heartbeat = 20", "accept_udp = true", `log_level = "warn"`} {
		if !strings.Contains(all(ir), want) {
			t.Errorf("backhaul Iran config lacks %q", want)
		}
	}
	if !strings.Contains(all(kh), "connection_pool = 24") {
		t.Error("backhaul foreign config lacks connection_pool = 24")
	}

	ir, kh, err = buildPlans(methodPremium, tun(map[string]map[string]string{"premium": {"mode": "tcpmux"}}), srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"heartbeat_interval = 10", "heartbeat_timeout = 25", "channel_size = 4096", "mux_concurrency = 8"} {
		if !strings.Contains(all(ir), want) {
			t.Errorf("premium Iran default config lacks %q", want)
		}
	}
	if !strings.Contains(all(kh), "connection_pool = 8") {
		t.Error("premium foreign default config lacks connection_pool = 8")
	}
	ir, _, err = buildPlans(methodPremium, tun(nil), srv, fsrv, Settings{})
	if err != nil || !strings.Contains(all(ir), "heartbeat_interval = 10") || !strings.Contains(all(ir), `encapsulation = "ipx"`) {
		t.Errorf("premium ipx default config: %v", err)
	}
	if _, _, err = buildPlans(methodPremium, tun(map[string]map[string]string{"premium": {"heartbeat_interval": "30", "heartbeat_timeout": "30"}}), srv, fsrv, Settings{}); err == nil {
		t.Error("a heartbeat timeout not longer than the interval was accepted")
	}
	if g := methodByID["premium1"].Group; g != "Backhaul" {
		t.Errorf("premium1 group %q", g)
	}
}
