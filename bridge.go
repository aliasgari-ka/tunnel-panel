package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Bridge exposes an Iran server's sshd on a local panel port by proxying each
// connection through whatever path reaches that server (agent, jump or direct).
// It lets the admin `ssh -p <port> root@<panel>` even when Iran blocks inbound SSH.
type Bridge struct {
	ServerID string
	Port     int
	Bind     string
	ln       net.Listener
	app      *App
	expires  time.Time
	mu       sync.Mutex
}

type bridgeMgr struct {
	mu sync.Mutex
	m  map[string]*Bridge // serverID -> bridge
}

var bridges = &bridgeMgr{m: map[string]*Bridge{}}

// OpenBridge starts (or refreshes) a bridge to a server's sshd. bindPublic controls
// whether it listens on all interfaces (reachable from outside) or just localhost.
func (a *App) OpenBridge(srv *Server, bindPublic bool, ttl time.Duration) (*Bridge, error) {
	bridges.mu.Lock()
	defer bridges.mu.Unlock()
	if b := bridges.m[srv.ID]; b != nil {
		b.mu.Lock()
		b.expires = time.Now().Add(ttl)
		b.mu.Unlock()
		return b, nil
	}
	bind := "127.0.0.1"
	if bindPublic {
		bind = "0.0.0.0"
	}
	ln, err := net.Listen("tcp", bind+":0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	b := &Bridge{ServerID: srv.ID, Port: port, Bind: bind, ln: ln, app: a, expires: time.Now().Add(ttl)}
	bridges.m[srv.ID] = b
	go b.serve(srv)
	go b.reaper()
	return b, nil
}

func (b *Bridge) serve(srv *Server) {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(srv, c)
	}
}

func (b *Bridge) handle(srv *Server, down net.Conn) {
	defer down.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host, _, err := b.app.reach(ctx, srv, nil)
	if err != nil {
		return
	}
	target := srv.sshAddr()
	var up net.Conn
	switch h := host.(type) {
	case AgentHost:
		up, err = h.Dial(target)
	case *SSHHost:
		up, err = h.Dial(target)
	case labeled:
		if d, ok := h.Host.(interface {
			Dial(string) (net.Conn, error)
		}); ok {
			up, err = d.Dial(target)
		} else {
			err = fmt.Errorf("path has no dialer")
		}
	default:
		err = fmt.Errorf("unsupported path for bridge")
	}
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, down); done <- struct{}{} }()
	go func() { io.Copy(down, up); done <- struct{}{} }()
	<-done
}

func (b *Bridge) reaper() {
	for {
		time.Sleep(30 * time.Second)
		b.mu.Lock()
		exp := b.expires
		b.mu.Unlock()
		if time.Now().After(exp) {
			b.Close()
			return
		}
	}
}

func (b *Bridge) Close() {
	bridges.mu.Lock()
	delete(bridges.m, b.ServerID)
	bridges.mu.Unlock()
	b.ln.Close()
}
