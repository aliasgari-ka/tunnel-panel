package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

// fakeSSHD accepts the password "pw", a pty and a shell, and answers each write with
// "echo:<data>" and each window change with "size:<cols>x<rows>"; "exit" ends the shell.
func fakeSSHD(t *testing.T) int {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) != "pw" {
			return nil, fmt.Errorf("bad password")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							switch r.Type {
							case "pty-req", "shell":
								_ = r.Reply(true, nil)
							case "window-change":
								var wc struct{ Cols, Rows, W, H uint32 }
								_ = ssh.Unmarshal(r.Payload, &wc)
								fmt.Fprintf(ch, "size:%dx%d", wc.Cols, wc.Rows)
							default:
								_ = r.Reply(false, nil)
							}
						}
					}()
					go func() {
						buf := make([]byte, 1024)
						for {
							n, err := ch.Read(buf)
							if err != nil {
								return
							}
							if strings.TrimSpace(string(buf[:n])) == "exit" {
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
								ch.Close()
								return
							}
							fmt.Fprintf(ch, "echo:%s", buf[:n])
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// The console opens a shell over the panel's SSH path: keystrokes reach it, its output and a
// resize come back, and "exit" closes the websocket. Another account's server and a page on
// another site get no shell.
func TestConsole(t *testing.T) {
	port := fakeSSHD(t)
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{{ID: "s1", Name: "lab", IPv4: "127.0.0.1", SSHPort: port, Password: "pw", Role: "foreign"}}
		return nil
	})
	app := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	srv := httptest.NewServer(app.routes())
	defer srv.Close()
	login := func(u string) string {
		r, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"username":"`+u+`","password":"password1"}`))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		for _, c := range r.Cookies() {
			if c.Name == "tp_session" {
				return c.Name + "=" + c.Value
			}
		}
		t.Fatalf("no session for %s", u)
		return ""
	}
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/servers/console?id=s1&c=100&r=30"
	dial := func(cookie, origin string) (*websocket.Conn, error) {
		cfg, _ := websocket.NewConfig(wsURL, origin)
		cfg.Header = http.Header{"Cookie": {cookie}}
		return websocket.DialConfig(cfg)
	}
	boss := login("boss")

	if _, err := dial(boss, "https://evil.example"); err == nil {
		t.Fatal("a websocket from another site was accepted")
	}
	if _, err := dial(login("ali"), srv.URL); err == nil {
		t.Fatal("an account opened a console on a server that isn't theirs")
	}

	c, err := dial(boss, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got strings.Builder
	read := func(want string) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for !strings.Contains(got.String(), want) {
			var b []byte
			if err := websocket.Message.Receive(c, &b); err != nil {
				t.Fatalf("waiting for %q: %v (got %q)", want, err, got.String())
			}
			got.Write(b)
		}
	}
	read("connected via direct SSH")
	_ = websocket.Message.Send(c, `{"t":"i","d":"uptime\r"}`)
	read("echo:uptime")
	_ = websocket.Message.Send(c, `{"t":"r","c":132,"r":40}`)
	read("size:132x40")
	_ = websocket.Message.Send(c, `{"t":"i","d":"exit\r"}`)
	read("session closed")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b []byte
	if err := websocket.Message.Receive(c, &b); err == nil {
		t.Fatalf("the websocket stayed open after the shell ended: %q", b)
	}
}
