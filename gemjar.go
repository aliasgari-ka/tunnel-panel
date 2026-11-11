package main

// One cookie jar, one exit, for the Google test browser. Chromium on the browser host always
// goes out through socks5://127.0.0.1:9278, which gb-tunnel (ssh -R) brings to this panel host;
// gemFwd forwards every connection to the account's home exit (gemHome) and nowhere else.
//
// It used to be switchable ("hold" the browser on the exit being checked, for a signed-in check
// there). Each such visit showed the account to Google from another IP, often another country,
// with captchas on the way; on 2026-11-10, after an evening of them, Google revoked the session
// (the SID cookies were cleared, the profile itself was intact). Exits are checked without the
// account now (gemProbe, a throw-away browser context with its own proxy), so the jar never
// needs to move: there is no switch any more, for any caller.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

const (
	gemFwdAddr = "127.0.0.1:9278" // the test browser's proxy (reached over gb-tunnel -R)
	// where the test account lives, always: the panel host's own IP (its relay). Google serves
	// Gemini to the account there, and no user's Google leaves from it, so Google has no reason to
	// turn against it (the browser host's own IP, the home before, came to be refused: every user
	// of that server went to Google from it)
	gemHome = "152.53.86.103:12371"
)

type gemFwdT struct {
	up string // socks exit "ip:port" (gemHome; a test sets another)
}

var gemFwd = &gemFwdT{up: gemHome}

func (f *gemFwdT) serve() {
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

	d, _ := proxy.SOCKS5("tcp", f.up, nil, &net.Dialer{Timeout: 15 * time.Second})
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
	c.SetDeadline(time.Time{})
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(u, c); done <- struct{}{} }()
	go func() { io.Copy(c, u); done <- struct{}{} }()
	<-done
}
