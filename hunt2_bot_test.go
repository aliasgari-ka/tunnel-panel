package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"tunnelpanel/internal/agentproto"
)

// hunt2Bot is a bot on a fake Telegram, with one admin chat "42".
func hunt2Bot(t *testing.T, setup func(*State)) (*App, *Bot, *fakeTG) {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error { setup(s); return nil })
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}, healthCache: map[string]string{}}
	f := &fakeTG{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	b := newBot(a, "TOKEN", "42")
	b.base = srv.URL
	return a, b, f
}

func (f *fakeTG) texts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if s := c.Get("text"); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Bug 1: a failed sendDocument quoted the URL with the bot token, and the caller sent it to the chat.
func TestHunt2BotSendDocumentHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close() // the connection drops: the client's error quotes the URL
	}))
	defer srv.Close()
	b := newBot(&App{}, "123456:SECRETSECRET", "42")
	b.base = srv.URL
	err := b.sendDocument("42", "x.json", []byte("{}"), "c")
	if err == nil {
		t.Fatal("no error from a dropped connection")
	}
	if strings.Contains(err.Error(), "SECRETSECRET") {
		t.Errorf("the token leaks: %v", err)
	}
	if !strings.Contains(err.Error(), "<token>") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// Bug 2: a user's bot benchmarked a pair the web API refuses (here: to the panel host).
func TestHunt2BotBenchPairGuard(t *testing.T) {
	_, b, f := hunt2Bot(t, func(s *State) {
		s.Users = []User{{Username: "ali", Role: roleUser}}
		s.Servers = []*Server{{ID: "ir1", Name: "ali-ir", IPv4: "192.0.2.1", Owner: "ali", Role: "iran"}}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "to-panel", ServerID: "ir1", ForeignID: "", Family: "v4", Owner: "ali", Index: 1}}
	})
	b.owner = "ali"
	b.onCallback("42", 7, "cb", "bqy:aaaaaaaaaaaa")
	all := strings.Join(f.texts(), "\n")
	if !strings.Contains(all, "Only the admin can benchmark this route") {
		t.Errorf("not refused:\n%s", all)
	}
	if strings.Contains(all, "Benchmarking the route") {
		t.Errorf("the benchmark started:\n%s", all)
	}
}

// Bug 4: after "works again", a new failure within the hour was dropped and never reported;
// "no music country" right after "back in one" waited out its cooldown.
func TestHunt2IGAlertsAfterRecovery(t *testing.T) {
	st := &igAlertState{since: map[string]int64{}, sent: map[string]time.Time{}, pathBad: map[string]bool{}}
	now := time.Now()
	r1 := st.igAlertLines("s1", []string{"user path check failed: Instagram (timeout)"}, now)
	r2 := st.igAlertLines("s1", []string{"user path works again: Instagram"}, now.Add(10*time.Minute))
	r3 := st.igAlertLines("s1", []string{"user path check failed: Instagram (timeout)"}, now.Add(20*time.Minute))
	if len(r1) != 1 || len(r2) != 1 || !strings.Contains(r2[0], "works again") {
		t.Fatalf("rounds: %q %q", r1, r2)
	}
	if len(r3) != 1 || !strings.Contains(r3[0], "broken for the users") {
		t.Errorf("the failure after the recovery wasn't reported: %q", r3)
	}
	// and the one after it is held by its cooldown again (no flood)
	st.igAlertLines("s1", []string{"user path works again: Instagram"}, now.Add(25*time.Minute))
	_ = r3

	p1 := st.igAlertLines("s1", []string{"Instagram: no WARP and no proxy left"}, now)
	p2 := st.igAlertLines("s1", []string{"Instagram: WARP 3 is in a music country again"}, now.Add(10*time.Minute))
	p3 := st.igAlertLines("s1", []string{"Instagram: no WARP and no proxy left"}, now.Add(20*time.Minute))
	p4 := st.igAlertLines("s1", []string{"Instagram: no WARP and no proxy left"}, now.Add(30*time.Minute))
	if len(p1) != 1 || len(p2) != 1 || len(p3) != 1 {
		t.Errorf("igproxy/igback pair: %q %q %q", p1, p2, p3)
	}
	if len(p4) != 0 {
		t.Errorf("a repeat without a recovery between should wait its cooldown: %q", p4)
	}
}

// Bug 5: a message over 4096 characters was refused by Telegram and lost.
func TestHunt2BotSplitMsg(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 400; i++ {
		sb.WriteString("<b>line</b> &amp; 😀 some text that fills the message up\n")
	}
	long := sb.String()
	parts := splitMsg(long, tgChunk)
	if len(parts) < 2 {
		t.Fatalf("not split: %d parts", len(parts))
	}
	for _, p := range parts {
		if n := utf16Len(p); n > tgChunk {
			t.Errorf("part of %d units", n)
		}
		if strings.Count(p, "<b>") != strings.Count(p, "</b>") {
			t.Errorf("a tag was cut across parts")
		}
	}
	if got := strings.Join(parts, "\n"); got != strings.TrimRight(long, "\n") {
		t.Errorf("text changed by the split")
	}
	// one overlong line: cut inside, never in a tag or an entity
	line := strings.Repeat("a&amp;b<i>x</i>", 1000)
	for _, p := range splitMsg(line, 100) {
		if utf16Len(p) > 100 {
			t.Errorf("part of %d units", utf16Len(p))
		}
		if i := strings.LastIndexByte(p, '&'); i >= 0 && !strings.Contains(p[i:], ";") {
			t.Errorf("entity cut: %q", p)
		}
		if i := strings.LastIndexByte(p, '<'); i >= 0 && !strings.Contains(p[i:], ">") {
			t.Errorf("tag cut: %q", p)
		}
	}
	if strings.Join(splitMsg(line, 100), "") != line {
		t.Errorf("hard cut lost text")
	}
	if p := splitMsg("short", tgChunk); len(p) != 1 || p[0] != "short" {
		t.Errorf("short message: %q", p)
	}

	// send, push and pushCh deliver it in parts
	a, b, f := hunt2Bot(t, func(s *State) { s.Settings.TelegramChannel = "-100123" })
	b.send("42", long)
	b.push(strings.Repeat("x & y\n", 2000))
	a.bot = b
	a.pushCh(strings.Repeat("alert <z>\n", 1000))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := 0
		for _, c := range f.calls {
			if c.Get("chat_id") == "-100123" {
				n++
			}
		}
		f.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	per := map[string]int{}
	for _, c := range f.calls {
		if n := utf16Len(c.Get("text")); n > 4096 {
			t.Errorf("a %d-unit message was sent", n)
		}
		per[c.Get("chat_id")]++
	}
	if per["42"] < 4 || per["-100123"] < 2 {
		t.Errorf("parts sent: %v", per)
	}
}

// Bug 6: one failed getMe (network down at boot) ended the bot until the next restart.
func TestHunt2BotRunRetriesGetMe(t *testing.T) {
	old := getMeRetry
	getMeRetry = 10 * time.Millisecond
	defer func() { getMeRetry = old }()
	var getMe, updates atomic.Int32
	h := func(unauthorized bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/getMe"):
				n := getMe.Add(1)
				if unauthorized {
					_, _ = w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
					return
				}
				if n < 3 {
					c, _, _ := w.(http.Hijacker).Hijack()
					c.Close()
					return
				}
				_, _ = w.Write([]byte(`{"ok":true,"result":{"username":"testbot"}}`))
			case strings.HasSuffix(r.URL.Path, "/getUpdates"):
				updates.Add(1)
				time.Sleep(20 * time.Millisecond)
				_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
			default:
				_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
			}
		}
	}
	srv := httptest.NewServer(h(false))
	defer srv.Close()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	b := newBot(&App{store: st}, "TOKEN", "42")
	b.base = srv.URL
	done := make(chan struct{})
	go func() { b.Run(); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for updates.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if updates.Load() == 0 {
		t.Errorf("the bot never got past getMe (%d tries)", getMe.Load())
	}
	if s, _ := b.state.Load().(string); s != "@testbot" {
		t.Errorf("state %q", s)
	}
	b.Stop()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Errorf("Run didn't stop")
	}

	// a token Telegram doesn't know: gives up at once
	getMe.Store(0)
	srv2 := httptest.NewServer(h(true))
	defer srv2.Close()
	b2 := newBot(&App{store: st}, "TOKEN", "42")
	b2.base = srv2.URL
	done2 := make(chan struct{})
	go func() { b2.Run(); close(done2) }()
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		b2.Stop()
		t.Errorf("Run kept retrying an unauthorized token")
	}
	if getMe.Load() != 1 {
		t.Errorf("getMe tried %d times on 401", getMe.Load())
	}
}

// Bug 7: the "➡ path" button carried an index into the running paths, which shifts.
func TestHunt2BotHSPathButton(t *testing.T) {
	a, b, f := hunt2Bot(t, func(s *State) {
		s.Servers = []*Server{{ID: "ir1", Name: "ir", IPv4: "192.0.2.1"}, {ID: "kh1", Name: "de", IPv4: "198.51.100.1", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "hs", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Index: 1,
			Active: "gre", Selected: "gre", HotStandby: true,
			Paths: []HSPath{{Method: "gre", Family: "v4"}, {Method: "bp_reverse", Family: "v4"}}}}
	})
	a.healthCache["aaaaaaaaaaaa"] = ""
	a.hsViews = map[string]*hsView{"aaaaaaaaaaaa": {Active: 0, Paths: []string{"GRE", "BackPack"}, OK: []bool{true, true}, Keys: []string{"gre|v4", "bp_reverse|v4"}}}
	_, kb := b.tunnelPage(a.store.Tunnel("aaaaaaaaaaaa"))
	if !strings.Contains(kb, `"hp:aaaaaaaaaaaa:bp_reverse:v4"`) {
		t.Errorf("button data: %s", kb)
	}
	var m struct {
		Inline [][]ikey `json:"inline_keyboard"`
	}
	_ = json.Unmarshal([]byte(kb), &m)
	for _, r := range m.Inline {
		for _, k := range r {
			if len(k.Data) > 64 {
				t.Errorf("callback data over 64 bytes: %q", k.Data)
			}
		}
	}
	// the path stopped running before the press; an old numeric button: both refused, nothing pinned
	_ = a.store.Update(func(s *State) error { s.Tunnels[0].Paths[1].Failed = "down"; return nil })
	b.onCallback("42", 7, "cb", "hp:aaaaaaaaaaaa:bp_reverse:v4")
	b.onCallback("42", 7, "cb", "hp:aaaaaaaaaaaa:1")
	all := strings.Join(f.texts(), "\n")
	if strings.Count(all, "That path isn't running any more") != 2 {
		t.Errorf("not refused:\n%s", all)
	}
	if strings.Contains(all, "switching") {
		t.Errorf("a switch started:\n%s", all)
	}
}

// Bug 8: /cmd@BotName (how a group sends commands) wasn't understood.
func TestHunt2BotCommandWithBotName(t *testing.T) {
	_, b, f := hunt2Bot(t, func(s *State) {})
	b.onText("42", "/menu@MyPanelBot")
	b.onText("42", "/report@MyPanelBot")
	all := strings.Join(f.texts(), "\n")
	if strings.Contains(all, "Use the buttons below") {
		t.Errorf("command not understood:\n%s", all)
	}
	if !strings.Contains(all, "Tunnel Panel bot") {
		t.Errorf("/menu@bot gave no menu:\n%s", all)
	}
}

// Bug 11: an alert channel saved as @name never matched the channel's numeric id.
func TestHunt2BotMemberChannelByName(t *testing.T) {
	a, b, f := hunt2Bot(t, func(s *State) { s.Settings.TelegramChannel = "@MyAlerts" })
	m := &chatMember{}
	m.Chat.ID, m.Chat.Type, m.Chat.Title, m.Chat.Username = -100777, "channel", "alerts", "myalerts"
	m.From.ID = 42
	m.New.Status = "left"
	b.onMember(m)
	if ch := a.settings().TelegramChannel; ch != "" {
		t.Errorf("channel still %q after the bot left it", ch)
	}
	// made admin again of the same channel saved by name: taken, not "another channel"
	_ = a.store.Update(func(s *State) error { s.Settings.TelegramChannel = "@MyAlerts"; return nil })
	m.New.Status = "administrator"
	b.onMember(m)
	if ch := a.settings().TelegramChannel; ch != "-100777" {
		t.Errorf("channel %q", ch)
	}
	if all := strings.Join(f.texts(), "\n"); strings.Contains(all, "but the alert channel is") {
		t.Errorf("treated as another channel:\n%s", all)
	}
	// the decoder takes the username
	var cm chatMember
	_ = json.Unmarshal([]byte(`{"chat":{"id":-1,"type":"channel","username":"abc"}}`), &cm)
	if cm.Chat.Username != "abc" {
		t.Errorf("username not decoded")
	}
}

// Bug 10: the SOCKS dial to the upstream exit had no deadline for its handshake.
func TestHunt2GemFwdDialTimeout(t *testing.T) {
	old := gemDialTimeout
	gemDialTimeout = 300 * time.Millisecond
	defer func() { gemDialTimeout = old }()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { // an exit that accepts and never answers
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	f := &gemFwdT{up: l.Addr().String(), conns: map[net.Conn]struct{}{}}
	cl, sv := net.Pipe()
	done := make(chan struct{})
	go func() { f.handle(sv); close(done) }()
	go func() {
		_, _ = cl.Write([]byte{5, 1, 0})
		_, _ = io.ReadFull(cl, make([]byte, 2))
		_, _ = cl.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80})
		_, _ = io.Copy(io.Discard, cl)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Errorf("handle still waiting on a silent exit")
	}
	cl.Close()
}

// Suspicion: a server with Role "" (= Iran) passed "foreign servers only" on the IG page.
func TestHunt2IGRoleEmptyIsIran(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	pw, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(pw)}}
		s.Servers = []*Server{{ID: "aaaaaaaaaaaa", Name: "old-ir", IPv4: "192.0.2.1"}, {ID: "bbbbbbbbbbbb", Name: "de", IPv4: "198.51.100.1", Role: "foreign"}}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	lw := httptest.NewRecorder()
	s.login(lw, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"password1"}`)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/igproxy/enable", strings.NewReader(`{"id":"aaaaaaaaaaaa","on":true}`))
	r.Header.Set("Content-Type", "application/json")
	for _, k := range lw.Result().Cookies() {
		r.AddCookie(k)
	}
	s.igEnable(w, r)
	if w.Code != 400 || st.Server("aaaaaaaaaaaa").Igproxy {
		t.Errorf("Role \"\" server enabled: %d %s", w.Code, w.Body.String())
	}
}

// Suspicion: the agent's hello was read up to its newline with no limit.
func TestHunt2AgentHelloLimit(t *testing.T) {
	var ok bytes.Buffer
	_ = agentproto.WriteRequest(&ok, agentproto.Request{Op: "hello"})
	_ = agentproto.WriteFrame(&ok, 'o', []byte("host|arm64|debian"))
	if h, a, o := readHello(&ok); h != "host" || a != "arm64" || o != "debian" {
		t.Errorf("hello: %q %q %q", h, a, o)
	}
	cr := &countReader{r: bufio.NewReader(strings.NewReader(strings.Repeat("x", 1<<20)))}
	if h, _, _ := readHello(cr); h != "" {
		t.Errorf("garbage parsed as %q", h)
	}
	if cr.n > helloMax {
		t.Errorf("read %d bytes of a hello", cr.n)
	}
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
