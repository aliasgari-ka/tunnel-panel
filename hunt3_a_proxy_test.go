package main

import (
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

// BUG (a proxy that accepts but never answers hangs the dial forever): httpConnect (and the
// SOCKS5 handshake in proxyDial) set no deadline past the TCP connect, so SSHHost.client()
// blocks in h.dial with h.mu held for good. reach() gives up when its ctx ends (clientCtx),
// but the dialling goroutine and its TCP connection stay forever — one more per monitor
// round, health check or apply against that server (SSH itself is bounded: 20 s handshake).
func TestHunt3A_ProxyDialNeverTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c) // accept, read nothing, answer nothing
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	}()
	limit := 25 * time.Second // the connect timeout is 15 s, the SSH handshake 20 s
	var wg sync.WaitGroup
	for _, scheme := range []string{"http", "socks5"} {
		wg.Add(1)
		go func(scheme string) {
			defer wg.Done()
			u := scheme + "://" + ln.Addr().String()
			dial := proxyDial(u)
			if scheme == "http" {
				pu, _ := url.Parse(u)
				dial = func(addr string) (net.Conn, error) { return httpConnect(pu, addr) }
			}
			done := make(chan error, 1)
			go func() {
				c, err := dial("192.0.2.1:22")
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			select {
			case <-done:
			case <-time.After(limit):
				t.Errorf("%s proxy: the dial through a proxy that never answers is still blocked after %s (no deadline after the TCP connect)", scheme, limit)
			}
		}(scheme)
	}
	wg.Wait()
}
