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
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	gemFwdAddr = "127.0.0.1:9278" // the test browser's proxy (reached over gb-tunnel -R)
	// where the test account lives, always: this panel's own SOCKS (gemOwn), which goes out from
	// the account's own IPv6 address on the panel host (gemhomev6.go) and from nowhere else.
	// Until 2026-11-25 it was the host's IPv4 (relay 12371); Google then stopped placing that IPv4
	// in any country (keyless Gemini "google.com", signed-in "Gemini isn't currently supported in
	// your country"), while the host's IPv6 /64 still read Germany.
	gemHome = "127.0.0.1:9279"
	// gemHomeV4Relay: the host's own IPv4 (its agent relay): only for non-Google sites without
	// IPv6, and for the whole browser on a host without IPv6.
	gemHomeV4Relay = "152.53.86.103:12371"
)

type gemFwdT struct {
	addr string        // where it listens
	up   string        // socks exit "ip:port" (a test sets another)
	src  func() net.IP // gemOwn: dial straight from this IPv6 (nil / nil IP = through up)
}

var gemFwd = &gemFwdT{addr: gemFwdAddr, up: gemHome}

// gemOwn is the account's exit: straight out from its IPv6, the IPv4 relay only as gemOwnVia says.
var gemOwn = &gemFwdT{addr: gemHome, up: gemHomeV4Relay, src: gemHomeV6}

func (f *gemFwdT) serve() {
	l, err := net.Listen("tcp", f.addr)
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

	// the whole dial under one deadline: the dialer's timeout covers only the TCP connect, and
	// an exit that accepts but never answers the SOCKS handshake held this forever
	ctx, cancel := context.WithTimeout(context.Background(), gemDialTimeout)
	u, err := f.dial(ctx, host, target)
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

// dial: through the socks exit, or (gemOwn) straight from the account's IPv6.
func (f *gemFwdT) dial(ctx context.Context, host, target string) (net.Conn, error) {
	var src net.IP
	if f.src != nil {
		src = f.src()
	}
	if src != nil {
		has6 := false
		if ip := net.ParseIP(host); ip != nil {
			has6 = ip.To4() == nil
		} else if ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", host); err == nil && len(ips) > 0 {
			has6 = true
		}
		switch gemOwnVia(host, has6) {
		case "v6":
			d := &net.Dialer{Timeout: 15 * time.Second, LocalAddr: &net.TCPAddr{IP: src}, Control: gemMarkCtl}
			return d.DialContext(ctx, "tcp6", target)
		case "no":
			return nil, fmt.Errorf("%s: no IPv6, and Google never sees the account on the IPv4", host)
		}
	}
	d, _ := proxy.SOCKS5("tcp", f.up, nil, &net.Dialer{Timeout: 15 * time.Second})
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", target)
	}
	return d.Dial("tcp", target)
}

// gemOwnVia: how the account's exit reaches host. "v6" = from the account's IPv6; "v4" = a site
// without IPv6 through the host's IPv4 (no Google site ever: Google does not place that IPv4);
// "no" = refused (a Google name without IPv6, or an IPv4 address).
func gemOwnVia(host string, has6 bool) string {
	if has6 {
		return "v6"
	}
	if net.ParseIP(host) != nil {
		return "no"
	}
	h := "." + strings.ToLower(strings.TrimSuffix(host, "."))
	for _, k := range []string{".google.", "google", "gstatic", "youtube", "ytimg", "ggpht", "gvt1", "gvt2", "gvt3", "doubleclick", "recaptcha", "goo.gl", "app-measurement", "googlevideo"} {
		if strings.Contains(h, k) {
			return "no"
		}
	}
	return "v4"
}
