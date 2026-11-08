package main

import (
	"bufio"
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

func TestGemFwdSwitch(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hi") }))
	defer web.Close()
	a, na := testSocks(t)
	b, nb := testSocks(t)

	f := &gemFwdT{up: a, conns: map[net.Conn]struct{}{}}
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
	get := func(c net.Conn) string {
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		r, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "ERR " + err.Error()
		}
		defer r.Body.Close()
		s, _ := io.ReadAll(r.Body)
		return string(s)
	}

	c1, err := d.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	if got := get(c1); got != "hi" || *na != 1 {
		t.Fatalf("through a: %q (a=%d)", got, *na)
	}
	f.switchTo(b, "tok", time.Now().Add(time.Minute))
	c1.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection through the old exit stayed open")
	}
	c2, err := d.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	if got := get(c2); got != "hi" || *nb != 1 || *na != 1 {
		t.Fatalf("after the switch: %q (a=%d b=%d)", got, *na, *nb)
	}
	f.until = time.Now().Add(-time.Second) // an expired hold goes home
	if f.current() != gemHome || f.token != "" {
		t.Fatalf("expired hold: up=%s token=%q", f.up, f.token)
	}
}
