package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A user's own bot shows only their services and none of the panel-wide actions; the admin's
// bot views one account at a time after 👤 Accounts, and every account again after "Everyone".
func TestBotAccounts(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss"}, {Username: "ali", Role: roleUser}, {Username: "sara", Role: roleUser}}
		s.Servers = []*Server{
			{ID: "ir1", Name: "boss-iran", IPv4: "192.0.2.1"},
			{ID: "kh1", Name: "boss-de", IPv4: "198.51.100.1", Role: "foreign"},
			{ID: "ir2", Name: "ali-iran", IPv4: "192.0.2.2", Owner: "ali"},
			{ID: "ir3", Name: "sara-iran", IPv4: "192.0.2.3", Owner: "sara"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "boss-tunnel", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1},
			{ID: "bbbbbbbbbbbb", Name: "ali-tunnel", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "8443", Index: 2, Owner: "ali"},
			{ID: "cccccccccccc", Name: "sara-tunnel", ServerID: "ir3", ForeignID: "kh1", Family: "v4", Ports: "9443", Index: 3, Owner: "sara"},
		}
		s.Outages = []Outage{
			{ID: "o1", Kind: "tunnel", Target: "cccccccccccc", Name: "sara-tunnel", Reason: "down"},
			{ID: "o2", Kind: "ssh-v4", Target: "ir1/v4", Name: "boss-iran (IPv4)", Reason: "ssh"},
			{ID: "o3", Kind: "panel", Target: "local", Name: "panel host", Reason: "x"},
		}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, healthCache: map[string]string{}}
	f := &fakeTG{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	text := func(from int) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		var sb strings.Builder
		for _, c := range f.calls[from:] {
			sb.WriteString(c.Get("text") + "\n" + c.Get("reply_markup") + "\n")
		}
		return sb.String()
	}
	mark := func() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

	// ali's own bot
	ub := newBot(a, "TOKEN", "77")
	ub.owner, ub.base = "ali", srv.URL
	n := mark()
	ub.onText("77", "/menu")
	ub.onCallback("77", 5, "cb", "home:sv")
	ub.onCallback("77", 5, "cb", "home:out")
	ub.onCallback("77", 5, "cb", "t:cccccccccccc") // sara's tunnel
	ub.onCallback("77", 5, "cb", "sv:ir3")         // sara's server
	ub.onCallback("77", 5, "cb", "svo:ir1")        // shared with ali: read-only
	ub.onCallback("77", 5, "cb", "home:bk")        // the panel's backup
	ub.onCallback("77", 5, "cb", "acc:sara")       // the admin's account switch
	out := text(n)
	for _, want := range []string{"ali-tunnel", "ali-iran", "boss-iran", "boss-de", "boss-iran (IPv4)", "no longer exists"} {
		if !strings.Contains(out, want) {
			t.Errorf("ali's bot: missing %q", want)
		}
	}
	for _, bad := range []string{"boss-tunnel", "sara-tunnel", "sara-iran", "home:bk", "home:rp", "Accounts", "panel host", "Kernel tuning ·"} {
		if strings.Contains(out, bad) {
			t.Errorf("ali's bot shows %q", bad)
		}
	}

	// the admin's bot: everything, then ali's view, then everyone again
	ab := newBot(a, "TOKEN", "42")
	ab.base = srv.URL
	n = mark()
	ab.onText("42", "/menu")
	if out := text(n); !strings.Contains(out, "boss-tunnel") || !strings.Contains(out, "sara-tunnel") || !strings.Contains(out, `"acc"`) {
		t.Errorf("admin's menu: %s", out)
	}
	n = mark()
	ab.onCallback("42", 5, "cb", "acc")
	if out := text(n); !strings.Contains(out, "acc:ali") || !strings.Contains(out, "acc:sara") || strings.Contains(out, "acc:boss") {
		t.Errorf("account picker: %s", out)
	}
	n = mark()
	ab.onCallback("42", 5, "cb", "acc:ali")
	ab.onText("42", "/report")
	out = text(n)
	if !strings.Contains(out, "ali-tunnel") || strings.Contains(out, "boss-tunnel") || strings.Contains(out, "sara-tunnel") || !strings.Contains(out, "👤") {
		t.Errorf("admin viewing as ali: %s", out)
	}
	if ab.scope("43") != "" {
		t.Errorf("another admin chat follows the switch")
	}
	n = mark()
	ab.onCallback("42", 5, "cb", "acc:")
	if out := text(n); !strings.Contains(out, "boss-tunnel") || !strings.Contains(out, "sara-tunnel") {
		t.Errorf("back to everyone: %s", out)
	}
}

// A user sets their own bot: a real-looking token only, never the admin's bot or another
// account's, and the token is never sent back.
func TestMyBot(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	tokA := "111111:" + strings.Repeat("A", 35)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser},
			{Username: "sara", Hash: string(h), Role: roleUser, TelegramTok: "222222:" + strings.Repeat("S", 35)}}
		s.Settings.TelegramTok = tokA
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	var ali *http.Cookie
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"ali","password":"password1"}`)))
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			ali = k
		}
	}
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/mybot", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(ali)
		s.myBot(w, r)
		return w
	}
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"token":"nope","chats":"1"}`, 400},
		{`{"token":"` + tokA + `","chats":"1"}`, 400},                           // the admin's bot
		{`{"token":"222222:` + strings.Repeat("S", 35) + `","chats":"1"}`, 400}, // sara's
		{`{"token":"333333:` + strings.Repeat("Z", 35) + `","chats":"1;2"}`, 400},
		{`{"token":"333333:` + strings.Repeat("Z", 35) + `","chats":"123, -456"}`, 200},
	} {
		if w := post(c.body); w.Code != c.want {
			t.Errorf("%s: %d %s", c.body, w.Code, w.Body.String())
		} else if w.Code == 200 && strings.Contains(w.Body.String(), "ZZZZ") {
			t.Errorf("token sent back: %s", w.Body.String())
		}
	}
	st.View(func(x *State) {
		for _, u := range x.Users {
			if u.Username == "ali" && (u.TelegramChats != "123,-456" || !strings.HasPrefix(u.TelegramTok, "333333:")) {
				t.Errorf("saved: %q %q", u.TelegramTok, u.TelegramChats)
			}
		}
	})
	if w := post(`{"remove":true}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"set":false`) {
		t.Errorf("remove: %d %s", w.Code, w.Body.String())
	}
}
