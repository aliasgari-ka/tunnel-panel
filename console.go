package main

// The web SSH console: a shell on a server in the browser (xterm.js), over one websocket.
// The panel opens the SSH session itself, over the same path it uses for the server
// (agent / direct / IPv6 / jump), so it works where the browser can't reach the server's
// sshd — an Iran server behind its filter included.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

// consoleMsg is what the browser sends: keystrokes, a new window size, or a keepalive
// (Cloudflare drops a websocket idle for 100 s).
type consoleMsg struct {
	T    string `json:"t"` // "i" input, "r" resize, "p" ping
	D    string `json:"d,omitempty"`
	Cols int    `json:"c,omitempty"`
	Rows int    `json:"r,omitempty"`
}

// serverConsole is GET /api/servers/console?id=…&c=…&r=… (a websocket). The server's own
// account or the admin only (guard "server"): a server shared read-only with a user, for a
// tunnel the admin made them, is not theirs to log in to.
func (s *Server2) serverConsole(w http.ResponseWriter, r *http.Request) {
	srv := s.app.store.Server(r.URL.Query().Get("id"))
	if srv == nil {
		httpErr(w, 404, "server not found")
		return
	}
	user, _ := s.who(r)
	ws := websocket.Server{
		// the session cookie rides along on a websocket another site opens: only this
		// panel's own page may open one
		Handshake: func(c *websocket.Config, req *http.Request) error {
			o, err := url.Parse(req.Header.Get("Origin"))
			if err != nil || o.Host == "" || o.Host != req.Host {
				return errors.New("bad origin")
			}
			c.Origin = o
			return nil
		},
		Handler: func(c *websocket.Conn) {
			defer c.Close()
			cols, _ := strconv.Atoi(r.URL.Query().Get("c"))
			rows, _ := strconv.Atoi(r.URL.Query().Get("r"))
			s.app.console(c, srv, user, cols, rows)
		},
	}
	ws.ServeHTTP(w, r)
}

func (a *App) console(c *websocket.Conn, srv *Server, user string, cols, rows int) {
	out := &wsWriter{c: c}
	say := func(f string, x ...any) { _, _ = fmt.Fprintf(out, "\x1b[90m"+f+"\x1b[0m\r\n", x...) }
	say("connecting to %s…", srv.Name)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cli, path, done, err := a.consoleClient(ctx, srv)
	cancel()
	if err != nil {
		say("\x1b[31mcould not reach the server: %v", err)
		return
	}
	defer done()
	sess, err := cli.NewSession()
	if err != nil {
		say("\x1b[31mSSH session: %v", err)
		return
	}
	defer sess.Close()
	if cols <= 0 || rows <= 0 {
		cols, rows = 120, 32
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		say("\x1b[31mterminal: %v", err)
		return
	}
	stdin, _ := sess.StdinPipe()
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Shell(); err != nil {
		say("\x1b[31mshell: %v", err)
		return
	}
	log.Printf("console: %s opened a shell on %s (%s)", orStr(user, "?"), srv.Name, path)
	say("connected via %s", path)

	// browser → shell; the websocket closing ends the shell, the shell ending closes the websocket
	go func() {
		defer sess.Close()
		for {
			var raw string
			if err := websocket.Message.Receive(c, &raw); err != nil {
				return
			}
			var m consoleMsg
			if json.Unmarshal([]byte(raw), &m) != nil {
				continue
			}
			switch m.T {
			case "i":
				if _, err := io.WriteString(stdin, m.D); err != nil {
					return
				}
			case "r":
				if m.Cols > 0 && m.Rows > 0 && m.Cols < 1000 && m.Rows < 1000 {
					_ = sess.WindowChange(m.Rows, m.Cols)
				}
			}
		}
	}()
	_ = sess.Wait()
	say("\r\nsession closed")
	log.Printf("console: %s closed the shell on %s", orStr(user, "?"), srv.Name)
}

// consoleClient returns an SSH client to the server and what to call when done with it.
// Over SSH it shares the panel's open connection (one more session on it); through the
// agent it logs in to the server's own sshd from the agent.
func (a *App) consoleClient(ctx context.Context, srv *Server) (*ssh.Client, string, func(), error) {
	h, path, err := a.reach(ctx, srv, nil)
	if err != nil {
		return nil, "", nil, err
	}
	switch x := h.(type) {
	case *SSHHost:
		cli, err := x.client()
		if err != nil {
			return nil, "", nil, err
		}
		return cli, path, func() {}, nil
	case AgentHost:
		port := srv.SSHPort
		if port == 0 {
			port = 22
		}
		sh := newSSHHost(a.store, srv, func(string) (net.Conn, error) {
			return x.Dial(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		})
		cli, err := sh.client()
		if err != nil {
			return nil, "", nil, fmt.Errorf("SSH through the agent to the server's own sshd: %w", err)
		}
		return cli, path + " → local sshd", sh.Close, nil
	}
	return nil, "", nil, errors.New("no SSH path to this server")
}

// wsWriter sends the shell's output as binary frames (xterm takes the bytes as they are,
// a UTF-8 character split across two reads included). Stdout and stderr write at once.
type wsWriter struct {
	mu sync.Mutex
	c  *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := websocket.Message.Send(w.c, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
