package main

// One cookie jar for the Google test browser. Chromium on the browser host always goes out
// through socks5://127.0.0.1:9278, which gb-tunnel (ssh -R) brings to this panel host; gemFwd
// forwards it to the browser's home exit (that host's own IP relay) or, while a probe holds it,
// to the exit being checked. Switching closes every open connection, so the next request already
// leaves from the new exit. The control port lets the gemini-check command switch it as well.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	gemFwdAddr = "127.0.0.1:9278"       // the test browser's proxy (reached over gb-tunnel -R)
	gemCtlAddr = "127.0.0.1:9279"       // hold / release (this host only)
	// where the test account lives, always: the panel host's own IP (its relay). Google serves
	// Gemini to the account there, and no user's Google leaves from it, so Google has no reason to
	// turn against it (the browser host's own IP, the home before, came to be refused: every user
	// of that server went to Google from it)
	gemHome    = "152.53.86.103:12371"
	gemHoldMax = 3 * time.Minute        // a probe that never releases gives the exit back after this
)

type gemFwdT struct {
	mu    sync.Mutex
	up    string // socks exit "ip:port" now
	token string // the probe holding it ("" = home)
	until time.Time
	conns map[net.Conn]struct{}
}

var gemFwd = &gemFwdT{up: gemHome, conns: map[net.Conn]struct{}{}}

// setLocked sets the exit and hands back the connections through the old one, to be closed
// once the lock is let go. The caller holds f.mu.
func (f *gemFwdT) setLocked(up, token string, until time.Time) map[net.Conn]struct{} {
	f.up, f.token, f.until = up, token, until
	cs := f.conns
	f.conns = map[net.Conn]struct{}{}
	return cs
}

// expireLocked: a hold past its time goes home (a probe that never released it). The caller
// holds f.mu.
func (f *gemFwdT) expireLocked() map[net.Conn]struct{} {
	if f.token != "" && time.Now().After(f.until) {
		return f.setLocked(gemHome, "", time.Time{})
	}
	return nil
}

func closeAll(cs map[net.Conn]struct{}) {
	for c := range cs {
		c.Close()
	}
}

// switchTo sets the exit and closes every connection through the old one.
func (f *gemFwdT) switchTo(up, token string, until time.Time) {
	f.mu.Lock()
	cs := f.setLocked(up, token, until)
	f.mu.Unlock()
	closeAll(cs)
}

// current is the exit for a new connection (an expired hold goes home first, in the same
// locked step, so it can never undo a hold taken meanwhile).
func (f *gemFwdT) current() string {
	f.mu.Lock()
	cs := f.expireLocked()
	up := f.up
	f.mu.Unlock()
	closeAll(cs)
	return up
}

// hold takes the exit for a probe: "" when another probe holds it. Checking and taking are one
// locked step, so two probes can never both get it.
func (f *gemFwdT) hold(to string) string {
	t := make([]byte, 8)
	rand.Read(t)
	tok := hex.EncodeToString(t)
	f.mu.Lock()
	cs := f.expireLocked()
	if f.token != "" {
		f.mu.Unlock()
		closeAll(cs)
		return ""
	}
	old := f.setLocked(to, tok, time.Now().Add(gemHoldMax))
	f.mu.Unlock()
	closeAll(cs)
	closeAll(old)
	return tok
}

// track keeps cs for the next switch; false when the exit changed since up was read.
func (f *gemFwdT) track(up string, cs ...net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.up != up {
		return false
	}
	for _, c := range cs {
		f.conns[c] = struct{}{}
	}
	return true
}

func (f *gemFwdT) untrack(cs ...net.Conn) {
	f.mu.Lock()
	for _, c := range cs {
		delete(f.conns, c)
	}
	f.mu.Unlock()
}

func (f *gemFwdT) serve() {
	go f.control()
	l, err := net.Listen("tcp", gemFwdAddr)
	if err != nil {
		fmt.Println("Google test browser proxy:", err)
		return
	}
	for {
		c, err := l.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		go f.handle(c)
	}
}

// gemDialTimeout bounds the dial through the upstream exit, its SOCKS handshake included.
var gemDialTimeout = 25 * time.Second

// handle: a SOCKS5 CONNECT without auth (what Chromium sends; it passes host names, so the exit
// resolves them).
func (f *gemFwdT) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, 262)
	if _, err := io.ReadFull(c, b[:2]); err != nil || b[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, b[:b[1]]); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, b[:4]); err != nil || b[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch b[3] {
	case 1, 4:
		n := 4
		if b[3] == 4 {
			n = 16
		}
		if _, err := io.ReadFull(c, b[:n]); err != nil {
			return
		}
		host = net.IP(append([]byte(nil), b[:n]...)).String()
	case 3:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return
		}
		n := int(b[0])
		if _, err := io.ReadFull(c, b[:n]); err != nil {
			return
		}
		host = string(b[:n])
	default:
		return
	}
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(b[:2]))))

	up := f.current()
	d, _ := proxy.SOCKS5("tcp", up, nil, &net.Dialer{Timeout: 15 * time.Second})
	// the whole dial under one deadline: the dialer's timeout covers only the TCP connect, and
	// an exit that accepts but never answers the SOCKS handshake held this forever
	ctx, cancel := context.WithTimeout(context.Background(), gemDialTimeout)
	var u net.Conn
	var err error
	if cd, ok := d.(proxy.ContextDialer); ok {
		u, err = cd.DialContext(ctx, "tcp", target)
	} else {
		u, err = d.Dial("tcp", target)
	}
	cancel()
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer u.Close()
	if !f.track(up, c, u) { // switched while dialling: this one belongs to the old exit
		return
	}
	defer f.untrack(c, u)
	c.SetDeadline(time.Time{})
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(u, c); done <- struct{}{} }()
	go func() { io.Copy(c, u); done <- struct{}{} }()
	<-done
}

// control: POST /hold?to=ip:port -> token (409 while another probe holds it); POST /release?t=token.
func (f *gemFwdT) control() {
	mux := http.NewServeMux()
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		if r.Method != http.MethodPost || to == "" {
			http.Error(w, "POST /hold?to=ip:port", 400)
			return
		}
		tok := f.hold(to)
		if tok == "" {
			http.Error(w, "another probe holds the browser", 409)
			return
		}
		io.WriteString(w, tok)
	})
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		var cs map[net.Conn]struct{}
		f.mu.Lock()
		if r.Method == http.MethodPost && f.token != "" && r.URL.Query().Get("t") == f.token {
			cs = f.setLocked(gemHome, "", time.Time{})
		}
		f.mu.Unlock()
		closeAll(cs)
	})
	if err := http.ListenAndServe(gemCtlAddr, mux); err != nil {
		fmt.Println("Google test browser proxy control:", err)
	}
}

// gemHold switches the test browser to the socks exit "ip:port" (waiting while another probe
// holds it); release gives it back to the home exit.
func gemHold(ctx context.Context, to string) (release func(), err error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+gemCtlAddr+"/hold?to="+to, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Google test browser proxy: %w", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			tok := string(b)
			return func() {
				r, _ := http.NewRequest(http.MethodPost, "http://"+gemCtlAddr+"/release?t="+tok, nil)
				if resp, err := hc.Do(r); err == nil {
					resp.Body.Close()
				}
			}, nil
		case 409:
			select {
			case <-ctx.Done():
				return nil, errors.New("the Google test browser stays busy with another probe")
			case <-time.After(3 * time.Second):
			}
		default:
			return nil, fmt.Errorf("Google test browser proxy: %s", b)
		}
	}
}
