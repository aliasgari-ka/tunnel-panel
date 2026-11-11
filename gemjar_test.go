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
