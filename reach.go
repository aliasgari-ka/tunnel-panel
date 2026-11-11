package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// reachCache holds live Hosts keyed by "serverID|path".
var reachCache = struct {
	sync.Mutex
	m map[string]Host
}{m: map[string]Host{}}

// reachDial holds one dial slot per server id (see sshReach).
var reachDial = struct {
	sync.Mutex
	m map[string]chan struct{}
}{m: map[string]chan struct{}{}}

// reachDialLock takes srv's dial slot, or gives up when ctx ends first.
func reachDialLock(ctx context.Context, serverID string) (func(), error) {
	reachDial.Lock()
	c := reachDial.m[serverID]
	if c == nil {
		c = make(chan struct{}, 1)
		reachDial.m[serverID] = c
	}
	reachDial.Unlock()
	select {
	case c <- struct{}{}:
		return func() { <-c }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func dropHost(serverID string) {
	reachCache.Lock()
	for k, h := range reachCache.m {
		if strings.HasPrefix(k, serverID+"|") {
			if c, ok := h.(interface{ Close() }); ok {
				c.Close()
			}
			delete(reachCache.m, k)
		}
	}
	reachCache.Unlock()
}

// dropKey closes and forgets one cached connection (one path to one server).
func dropKey(key string) {
	reachCache.Lock()
	if c, ok := reachCache.m[key].(interface{ Close() }); ok {
		c.Close()
	}
	delete(reachCache.m, key)
	reachCache.Unlock()
}

// pooledSSH asks the SSH connections the panel keeps open to a server whether they still
// answer: v4/v6 for a direct connection over that family, any for one over whatever path
// (a proxy, a jump host). Nothing is connected: a server without one yields false, false, false.
func (a *App) pooledSSH(serverID string) (v4, v6, any bool) {
	type entry struct {
		path string
		sh   *SSHHost
	}
	var hs []entry
	reachCache.Lock()
	for k, h := range reachCache.m {
		if sh, ok := h.(*SSHHost); ok && strings.HasPrefix(k, serverID+"|") {
			hs = append(hs, entry{strings.TrimPrefix(k, serverID+"|"), sh})
		}
	}
	reachCache.Unlock()
	for _, e := range hs {
		if !e.sh.alive() {
			continue
		}
		any = true
		switch e.path { // the paths sshReach caches under
		case "direct SSH":
			v4 = true
		case "direct SSH over IPv6":
			v6 = true
		}
	}
	return v4, v6, any
}

// reach returns a working Host for a server plus a human description of the path used.
// Order: live agent → direct SSH (optionally via proxy) → SSH through a jump server.
// j may be nil (used by status probes); then it logs nothing.
func (a *App) reach(ctx context.Context, srv *Server, j *Job) (Host, string, error) {
	logf := func(f string, x ...any) {
		if j != nil {
			j.log(f, x...)
		}
	}
	if a.hostFor != nil {
		if h := a.hostFor(srv); h != nil {
			return h, "test host", nil
		}
	}
	// 1. agent
	if a.agents != nil && a.agents.online(srv.ID) != nil {
		h := AgentHost{hub: a.agents, serverID: srv.ID}
		a.recordPath(srv, "agent")
		return h, "agent (dial-back)", nil
	}
	// 2 & 3: SSH over some dialer
	host, path, err := a.sshReach(ctx, srv, logf)
	if err != nil {
		return nil, "", err
	}
	a.recordPath(srv, path)
	return host, path, nil
}

func (a *App) recordPath(srv *Server, path string) {
	var same bool
	a.store.View(func(*State) { same = srv.LastPath == path })
	if same { // no rewrite of the whole state file on every reach (twice a tunnel a minute)
		return
	}
	_ = a.store.Update(func(*State) error { srv.LastPath = path; return nil })
}

func (a *App) sshReach(ctx context.Context, srv *Server, logf func(string, ...any)) (Host, string, error) {
	type cand struct {
		path string
		dial dialFunc
		v6   bool
	}
	var cands []cand

	// explicit proxy first (if configured), then plain direct
	if srv.Proxy != "" {
		cands = append(cands, cand{"SSH via proxy", proxyDial(srv.Proxy), false})
	}
	cands = append(cands, cand{"direct SSH", directDial, false})
	// the same server over IPv6, for when its IPv4 path (or SSH over it) is disrupted
	if v6 := srv.sshAddr6(); v6 != "" && v6 != srv.sshAddr() {
		cands = append(cands, cand{"direct SSH over IPv6", directDial, true})
	}
	// explicit jump
	if srv.Via != "" {
		if via := a.store.Server(srv.Via); via != nil {
			cands = append(cands, cand{"jump via " + via.Name, a.jumpDial(ctx, via), false})
		}
	} else {
		// auto: try every other server as a jump host — not the ones the server monitor
		// sees down right now (each would cost a full connect timeout)
		for _, other := range a.otherServers(srv.ID) {
			if !a.serverReachable(other.ID) {
				continue
			}
			cands = append(cands, cand{"jump via " + other.Name, a.jumpDial(ctx, other), false})
		}
	}

	// a connection already open on any path first: dialling the earlier ones anew (a
	// filtered direct address: 15-35 s each) before reaching it made checks time out
	pooled := func() (Host, string) {
		for _, c := range cands {
			key := srv.ID + "|" + c.path
			reachCache.Lock()
			cached := reachCache.m[key]
			reachCache.Unlock()
			if sh, ok := cached.(*SSHHost); ok {
				if _, err := sh.client(); err == nil {
					return sh, c.path
				}
				dropKey(key)
			}
		}
		return nil, ""
	}
	if h, path := pooled(); h != nil {
		return h, path, nil
	}
	// one dial per server at a time: concurrent callers (the monitor, a status page, a job)
	// each dialled their own connection and overwrote the cached one, which stayed open
	// with nothing left to close it; the ones that waited take the connection just made
	unlock, err := reachDialLock(ctx, srv.ID)
	if err != nil {
		return nil, "", err
	}
	defer unlock()
	if h, path := pooled(); h != nil {
		return h, path, nil
	}
	var lastErr, firstErr error
	tried := 0
	for _, c := range cands {
		if err := ctx.Err(); err != nil { // the caller gave up (a status page, the bot): stop trying
			if lastErr != nil {
				return nil, "", fmt.Errorf("%w (then gave up: %v)", lastErr, err)
			}
			return nil, "", err
		}
		key := srv.ID + "|" + c.path
		logf("trying %s", c.path)
		sh := newSSHHost(a.store, srv, c.dial)
		sh.v6 = c.v6
		if err := clientCtx(ctx, sh); err != nil {
			lastErr = fmt.Errorf("%s: %w", c.path, err)
			if firstErr == nil {
				firstErr = lastErr
			}
			tried++
			logf("  %s failed: %v", c.path, err)
			continue
		}
		// one cached while this dialled (stored past the dial slot): keep that one if it
		// answers and close this one, never leave one open that nothing knows about
		reachCache.Lock()
		old, _ := reachCache.m[key].(*SSHHost)
		reachCache.Unlock()
		if old != nil && old != sh && old.alive() {
			sh.Close()
			return old, c.path, nil
		}
		reachCache.Lock()
		if prev, ok := reachCache.m[key].(*SSHHost); ok && prev != sh {
			prev.Close()
		}
		reachCache.m[key] = sh
		reachCache.Unlock()
		return sh, c.path, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no SSH path available")
	}
	// the first path (proxy / direct SSH) says most about why; the last alone (a jump host
	// without a login) hid it
	if tried > 1 {
		mid := ""
		if tried > 2 {
			mid = fmt.Sprintf(" … %d more failed … ", tried-2)
		} else {
			mid = "; "
		}
		lastErr = fmt.Errorf("%v%s%w", firstErr, mid, lastErr)
	}
	return nil, "", lastErr
}

// clientCtx connects sh but gives up when ctx ends (a connect + handshake can take 35 s);
// a connection that completes later is closed.
func clientCtx(ctx context.Context, sh *SSHHost) error {
	done := make(chan error, 1)
	go func() {
		_, err := sh.client()
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		go func() {
			if <-done == nil {
				sh.Close()
			}
		}()
		return ctx.Err()
	}
}

// otherServers returns servers that could act as jump hosts (reachable, not the target).
func (a *App) otherServers(exclude string) []*Server {
	var out []*Server
	a.store.View(func(st *State) {
		owner := ownerOfLocked(st, exclude) // only servers of the same account are jump hosts
		for _, s := range st.Servers {
			if s.ID != exclude && s.Owner == owner && (s.Prepared || (a.agents != nil && a.agents.online(s.ID) != nil)) {
				out = append(out, s)
			}
		}
	})
	return out
}

// jumpDial dials the target through another server (its agent or a direct SSH to it).
func (a *App) jumpDial(ctx context.Context, via *Server) dialFunc {
	return func(addr string) (net.Conn, error) {
		// agent jump
		if a.agents != nil && a.agents.online(via.ID) != nil {
			return AgentHost{hub: a.agents, serverID: via.ID}.Dial(addr)
		}
		// direct SSH to the jump host, then Dial onward
		dial := dialFunc(directDial)
		if via.Proxy != "" {
			dial = proxyDial(via.Proxy)
		}
		sh := newSSHHost(a.store, via, dial)
		if _, err := sh.client(); err != nil {
			// IPv4 to the jump host is down: over its IPv6, as reach does for a server
			// itself (seen live: "jump via IRAN-USA … 81.12.32.18:2005: i/o timeout")
			if via.Proxy == "" && via.sshAddr6() != "" && via.sshAddr6() != via.sshAddr() {
				sh6 := newSSHHost(a.store, via, directDial)
				sh6.v6 = true
				if _, err6 := sh6.client(); err6 == nil {
					return jumpOnward(sh6, addr)
				}
			}
			return nil, fmt.Errorf("jump host %s unreachable: %w", via.Name, err)
		}
		return jumpOnward(sh, addr)
	}
}

// jumpOnward dials addr through the jump host's SSH connection, which then lives exactly as
// long as the returned conn. It used to stay open for good: every jump (each monitor round,
// each connection test) left one more sshd session on the jump host — seen live, 1300 on
// one server and 1600 on another, eating its RAM/CPU until sshd stopped answering.
func jumpOnward(via *SSHHost, addr string) (net.Conn, error) {
	c, err := via.Dial(addr)
	if err != nil {
		via.Close()
		return nil, err
	}
	return &jumpConn{Conn: c, via: via}, nil
}

type jumpConn struct {
	net.Conn
	via  *SSHHost
	once sync.Once
}

func (c *jumpConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.via.Close)
	return err
}

// ---- dialers ----

func directDial(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 15*time.Second)
}

// proxyTimeout bounds a proxy's handshake (SOCKS5, or HTTP CONNECT after the TCP dial).
var proxyTimeout = 20 * time.Second

// proxyDial returns a dialFunc routing through a socks5:// or http(s):// (CONNECT) proxy.
func proxyDial(proxyURL string) dialFunc {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return func(string) (net.Conn, error) { return nil, fmt.Errorf("bad proxy url: %w", err) }
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		return func(addr string) (net.Conn, error) {
			d, err := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 15 * time.Second})
			if err != nil {
				return nil, err
			}
			// the whole SOCKS handshake has a time limit: a proxy that takes the connection
			// and never answers held the SSH dial (and the host's lock) forever
			ctx, cancel := context.WithTimeout(context.Background(), proxyTimeout)
			defer cancel()
			if cd, ok := d.(xproxy.ContextDialer); ok {
				return cd.DialContext(ctx, "tcp", addr)
			}
			return d.Dial("tcp", addr)
		}
	case "http", "https":
		return func(addr string) (net.Conn, error) { return httpConnect(u, addr) }
	default:
		return func(string) (net.Conn, error) { return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme) }
	}
}

// httpConnect opens a tunnel to addr through an HTTP CONNECT proxy: http:// in the clear,
// https:// over TLS to the proxy (it was dialled in the clear, so the handshake failed or
// the proxy login went out unencrypted). A proxy without a port is on 80 / 443.
func httpConnect(u *url.URL, addr string) (net.Conn, error) {
	tlsProxy := strings.EqualFold(u.Scheme, "https")
	c, err := net.DialTimeout("tcp", proxyAddr(u), 15*time.Second)
	if err != nil {
		return nil, err
	}
	if tlsProxy {
		tc := tls.Client(c, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, fmt.Errorf("proxy TLS: %w", err)
		}
		c = tc
	}
	// and so does the CONNECT exchange (an http:// proxy had no deadline at all)
	_ = c.SetDeadline(time.Now().Add(proxyTimeout))
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), pw)
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	// what the reader already took past the proxy's answer (the SSH server's banner, sent
	// at once) is the tunnel's first bytes: read from the conn alone, they were lost
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

// proxyAddr is the HTTP proxy's host:port (80 / 443 when the URL has no port).
func proxyAddr(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "80"
	if strings.EqualFold(u.Scheme, "https") {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// bufConn reads what a bufio.Reader holds before the rest of the connection.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
