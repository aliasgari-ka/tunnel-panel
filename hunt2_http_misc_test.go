package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Deleting a server takes what is kept for it along: its cleanups (they held tunnel numbers
// for good), other servers' jump-host pointer, its open outages and the monitor's state.
func TestHunt2ServerDeleteLeftovers(t *testing.T) {
	e := newHunt2Env(t, func(s *State) {
		s.Servers = append(s.Servers, &Server{ID: "gone", Name: "old box", IPv4: "192.0.2.9"}, &Server{ID: "hop", Name: "uses it", Via: "gone"})
		s.Cleanups = []Cleanup{{ServerID: "gone", TunnelID: "tx", Indices: []int{7}}, {ServerID: "s1", TunnelID: "ty", Indices: []int{8}}}
		s.Outages = []Outage{{ID: "o1", Kind: "server", Target: "gone", Start: 1}, {ID: "o2", Kind: "ssh-v6", Target: "gone/v6", Start: 1},
			{ID: "o3", Kind: "server", Target: "s1", Start: 1}}
	})
	e.a.srvMon = &serverMon{state: map[string]*srvState{"gone": {down: true}, "gone/v6": {down: true}, "s1": {down: true}}}
	boss := e.cookie("boss")
	if w := e.call(boss, e.s.serverDelete, "POST", "/api/servers/delete", `{"ID":"gone"}`); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	e.st.View(func(st *State) {
		if len(st.Cleanups) != 1 || st.Cleanups[0].ServerID != "s1" {
			t.Errorf("cleanups: %+v", st.Cleanups)
		}
		for _, x := range st.Servers {
			if x.ID == "hop" && x.Via != "" {
				t.Errorf("jump host still points at the deleted server")
			}
		}
		for _, o := range st.Outages {
			if (o.Target == "gone" || o.Target == "gone/v6") && o.End == 0 {
				t.Errorf("outage %s still open", o.ID)
			}
			if o.Target == "s1" && o.End != 0 {
				t.Errorf("another server's outage was ended")
			}
		}
	})
	if !e.a.serverReachable("gone") || e.a.serverReachable("s1") {
		t.Error("monitor state not dropped (or another server's dropped)")
	}
	if w := e.call(boss, e.s.serverDelete, "POST", "/api/servers/delete", `{"ID":""}`); w.Code != 400 {
		t.Errorf("delete of no id: %d", w.Code)
	}
}

// A user's server can't point the panel at its own host (loopback, link-local, its own
// addresses): the connection test then port-scanned the panel host.
func TestHunt2UserServerHost(t *testing.T) {
	e := newHunt2Env(t, func(s *State) { s.Settings.LocalIPv4 = "203.0.113.77" })
	ali := e.cookie("ali")
	for _, body := range []string{
		`{"name":"x","sshHost":"127.0.0.1","sshPort":8088}`,
		`{"name":"x","sshHost":"localhost"}`,
		`{"name":"x","ipv4":"169.254.169.254"}`,
		`{"name":"x","sshHost":"::1"}`,
		`{"name":"x","sshHost":"0.0.0.0"}`,
		`{"name":"x","sshHost":"203.0.113.77"}`,
		`{"name":"x","ipv4":"192.0.2.50","proxy":"socks5://127.0.0.1:1080"}`,
		`{"id":"s2","name":"x","sshHost":"127.0.0.2"}`,
	} {
		if w := e.call(ali, e.s.servers, "POST", "/api/servers", body); w.Code != 400 {
			t.Errorf("%s: %d, want 400", body, w.Code)
		}
	}
	var host string
	srv := e.st.Server("s2") // outside View: both take the store lock
	e.st.View(func(*State) { host = srv.SSHHost })
	if host != "" {
		t.Fatal("ali's server was changed")
	}
	if err := e.a.userHostsOK(&Server{IPv4: "192.0.2.50", Proxy: "http://198.51.100.1:3128"}); err != nil {
		t.Fatalf("an ordinary address: %v", err)
	}
}

// A user's job log on the admin's servers doesn't show how the panel reaches them, nor the
// names of other admin servers tried as jump hosts; the admin still sees everything.
func TestHunt2JobLogRedacted(t *testing.T) {
	e := newHunt2Env(t, func(s *State) {
		s.Servers[0].SSHHost, s.Servers[0].SSHPort = "203.0.113.9", 2222 // s1: the admin's, carries ali's tunnel
		s.Servers = append(s.Servers, &Server{ID: "s4", Name: "secret-jump", IPv4: "203.0.113.50", Proxy: "socks5://u:pw@203.0.113.60:1080"})
		s.Tunnels = []*Tunnel{{ID: "t9", Name: "ali on admin", ServerID: "s1", ForeignID: "s3", Family: "v4", Ports: "443", Index: 9, Owner: "ali"}}
	})
	j, _ := e.a.jobs.start("t9", "apply")
	j.log("trying direct SSH")
	j.log("  direct SSH failed: dial tcp 203.0.113.9:2222: i/o timeout")
	j.log("trying jump via secret-jump")
	j.log("  jump via secret-jump failed: jump host secret-jump unreachable: dial tcp 203.0.113.50:22: proxy socks5://u:pw@203.0.113.60:1080")
	j.log("[ali-de 198.51.100.3] ok")
	lines := func(who string) string {
		w := e.call(e.cookie(who), e.s.guard("job", e.s.job), "GET", "/api/jobs?id="+j.ID, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d", who, w.Code)
		}
		var v struct{ Lines []string }
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return strings.Join(v.Lines, "\n")
	}
	got := lines("ali")
	for _, leak := range []string{"203.0.113.9", "2222", "secret-jump", "203.0.113.50", "203.0.113.60", "pw@"} {
		if strings.Contains(got, leak) {
			t.Errorf("user's job log shows %q:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "198.51.100.3") {
		t.Errorf("the user's own server's address was hidden:\n%s", got)
	}
	if all := lines("boss"); !strings.Contains(all, "203.0.113.9:2222") || !strings.Contains(all, "secret-jump") {
		t.Errorf("the admin's log was redacted:\n%s", all)
	}
}

// A renamed or deleted account's benchmark jobs don't pass to a new account of that name.
func TestHunt2JobOwnerFollowsRename(t *testing.T) {
	e := newHunt2Env(t, nil)
	j, _ := e.a.jobs.start("", "bench")
	j.Owner = "ali"
	ali := e.cookie("ali")
	if w := e.call(ali, e.s.password, "POST", "/api/password", `{"old":"password1","newUser":"ali2"}`); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	boss := e.cookie("boss")
	if w := e.call(boss, e.s.users, "POST", "/api/users", `{"username":"ali","password":"password1","role":"user"}`); w.Code != 200 {
		t.Fatalf("new ali: %d", w.Code)
	}
	see := func(who string) int {
		return e.call(e.cookie(who), e.s.guard("job", e.s.job), "GET", "/api/jobs?id="+j.ID, "").Code
	}
	if c := see("ali"); c != 404 {
		t.Errorf("the new account of the old name reads the job: %d", c)
	}
	if c := see("ali2"); c != 200 {
		t.Errorf("the renamed account lost its job: %d", c)
	}
	// deleting the account clears the job's owner
	j2, _ := e.a.jobs.start("", "bench")
	j2.Owner = "ali"
	if w := e.call(boss, e.s.userDelete, "POST", "/api/users/delete", `{"username":"ali"}`); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if j2.Owner != "" {
		t.Errorf("deleted account's job still owned by %q", j2.Owner)
	}
}

// The benchmark /api/bench/active shows a user (a route of theirs someone else started) can
// be followed: its job id passes the job guard for that user, not for others.
func TestHunt2BenchActiveJobReadable(t *testing.T) {
	e := newHunt2Env(t, func(s *State) {
		s.Users = append(s.Users, User{Username: "zed", Hash: s.Users[0].Hash, Role: roleUser})
	})
	j, _ := e.a.jobs.start("bench", "bench")
	e.a.benchRun = &benchActive{Job: j.ID, Req: BenchRequest{IranID: "s2", ForeignID: "s3", Family: "v4"}}
	ali, zed := e.cookie("ali"), e.cookie("zed")
	w := e.call(ali, e.s.benchActive, "GET", "/api/bench/active", "")
	if !strings.Contains(w.Body.String(), j.ID) {
		t.Fatalf("bench/active for ali: %s", w.Body)
	}
	if c := e.call(ali, e.s.guard("job", e.s.job), "GET", "/api/jobs?id="+j.ID, "").Code; c != 200 {
		t.Errorf("ali can't read the benchmark job bench/active shows: %d", c)
	}
	if c := e.call(ali, e.s.guard("job", e.s.jobCancel), "POST", "/api/jobs/cancel", `{"ID":"`+j.ID+`"}`).Code; c != 200 {
		t.Errorf("ali can't cancel it: %d", c)
	}
	if c := e.call(zed, e.s.guard("job", e.s.job), "GET", "/api/jobs?id="+j.ID, "").Code; c != 404 {
		t.Errorf("another user reads it: %d", c)
	}
}

// A server's traffic read counts only the tunnels it was asked about.
func TestHunt2TrafficParseAsked(t *testing.T) {
	a := &App{traffic: newTrafficMon()}
	a.trafficParse("ir", []*Tunnel{{ID: "mine"}}, "T mine 10 1 ports\nT admins 999 999 ports\nT hs 5 5\n")
	if a.traffic.tunnels["admins"] != nil || a.traffic.tunnels["hs"] != nil {
		t.Fatal("counters booked for a tunnel the server wasn't asked about")
	}
	if s := a.traffic.tunnels["mine"]; s == nil || s.TotalDown != 10 {
		t.Fatalf("own tunnel: %+v", s)
	}
}

// fakeProxy answers one CONNECT with 200 and, in the same write, the SSH server's banner.
func fakeProxy(t *testing.T, extra string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n" + extra))
		time.Sleep(3 * time.Second)
	}()
	return ln.Addr().String()
}

// What the proxy sends right after its 200 (the SSH banner) reaches the caller; https://
// speaks TLS to the proxy; a proxy without a port gets the scheme's.
func TestHunt2HTTPConnect(t *testing.T) {
	addr := fakeProxy(t, "SSH-2.0-OpenSSH_9.6\r\n")
	c, err := httpConnect(&url.URL{Scheme: "http", Host: addr}, "192.0.2.1:22")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "SSH-2.0-") {
		t.Fatalf("banner after CONNECT: %q %v", line, err)
	}

	// https: the first byte the proxy sees is a TLS handshake record
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	first := make(chan byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		b := make([]byte, 1)
		_, _ = c.Read(b)
		first <- b[0]
		c.Close()
	}()
	_, _ = httpConnect(&url.URL{Scheme: "https", Host: ln.Addr().String()}, "192.0.2.1:22")
	select {
	case b := <-first:
		if b != 0x16 {
			t.Fatalf("https proxy got %q first, not a TLS handshake", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the https proxy")
	}

	for in, want := range map[string]string{"http://p.example": "p.example:80", "https://p.example": "p.example:443",
		"http://[2001:db8::1]": "[2001:db8::1]:80", "http://p.example:3128": "p.example:3128"} {
		u, _ := url.Parse(in)
		if got := proxyAddr(u); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
