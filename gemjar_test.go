package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// testSocks is a bare SOCKS5 exit (no auth, CONNECT by host name) that counts its connections.
func testSocks(t *testing.T) (string, *int) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	n := 0
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n++
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 262)
				io.ReadFull(c, b[:2])
				io.ReadFull(c, b[:b[1]])
				c.Write([]byte{5, 0})
				io.ReadFull(c, b[:5])
				h := make([]byte, b[4]+2)
				io.ReadFull(c, h)
				u, err := net.Dial("tcp", net.JoinHostPort(string(h[:b[4]]), strconv.Itoa(int(h[b[4]])<<8|int(h[b[4]+1]))))
				if err != nil {
					return
				}
				defer u.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(u, c)
				io.Copy(c, u)
			}(c)
		}
	}()
	return l.Addr().String(), &n
}

// Every connection of the test browser leaves through its one exit.
func TestGemFwdOneExit(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hi") }))
	defer web.Close()
	a, na := testSocks(t)

	f := &gemFwdT{up: a}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	d, _ := proxy.SOCKS5("tcp", l.Addr().String(), nil, proxy.Direct)
	host := "localhost:" + web.URL[len("http://127.0.0.1:"):]
	for i := 1; i <= 3; i++ {
		c, err := d.Dial("tcp", host)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		r, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		c.Close()
		if string(b) != "hi" || *na != i {
			t.Fatalf("request %d: %q (exit saw %d)", i, b, *na)
		}
	}
	if gemFwd.up != gemHome {
		t.Fatalf("the test browser leaves through %s, not its home %s", gemFwd.up, gemHome)
	}
}

// The account's exit: Google only ever from the account's IPv6; a site without IPv6 may use the
// host's IPv4, a Google one never (Google stopped placing that IPv4, 2026-11-25).
func TestGemOwnVia(t *testing.T) {
	cases := []struct {
		host string
		has6 bool
		want string
	}{
		{"gemini.google.com", true, "v6"},
		{"accounts.google.com", false, "no"},
		{"www.google.de", false, "no"},
		{"fonts.gstatic.com", false, "no"},
		{"i.ytimg.com", false, "no"},
		{"redirector.gvt1.com", false, "no"},
		{"2a00:1450:4001:80b::200e", true, "v6"},
		{"142.250.185.78", false, "no"},
		{"example.org", false, "v4"},
		{"example.org", true, "v6"},
	}
	for _, c := range cases {
		if g := gemOwnVia(c.host, c.has6); g != c.want {
			t.Errorf("%s (ipv6 %v): %s, want %s", c.host, c.has6, g, c.want)
		}
	}
}

func TestGemHomeV6Addr(t *testing.T) {
	a := gemHomeV6Addr(net.ParseIP("2a0a:4cc0:c0:2253:946b:aeff:fef6:1234"))
	if a == nil || a.String() != "2a0a:4cc0:c0:2253:67:6d68:6f6d:6531" {
		t.Fatalf("account address %v", a)
	}
	for _, ip := range []string{"152.53.86.103", "fe80::1", "::1"} {
		if gemHomeV6Addr(net.ParseIP(ip)) != nil {
			t.Errorf("%s gave an address", ip)
		}
	}
}

// gemOwn with an IPv6 source dials straight from it, not through its socks exit.
func TestGemOwnDialsFromV6(t *testing.T) {
	l6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	defer l6.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := l6.Accept()
		if err != nil {
			return
		}
		seen <- c.RemoteAddr().(*net.TCPAddr).IP.String()
		c.Close()
	}()
	f := &gemFwdT{up: "127.0.0.1:1", src: func() net.IP { return net.ParseIP("::1") }}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := f.dial(ctx, "::1", l6.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if ip := <-seen; ip != "::1" {
		t.Errorf("came from %s", ip)
	}
	if _, err := f.dial(ctx, "142.250.185.78", "142.250.185.78:443"); err == nil {
		t.Error("an IPv4 address must not be dialed by the account's exit")
	}
}
