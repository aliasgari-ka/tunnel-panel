package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
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

// sshCand is one way to reach a server over SSH, in the order sshReach tries them.
type sshCand struct {
	path string
	dial dialFunc
	v6   bool
}

// sshCands lists the SSH paths to srv: a proxy, direct, direct over IPv6, then jump hosts.
func (a *App) sshCands(ctx context.Context, srv *Server) []sshCand {
	type cand = sshCand
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

	return cands
}

func (a *App) sshReach(ctx context.Context, srv *Server, logf func(string, ...any)) (Host, string, error) {
	cands := a.sshCands(ctx, srv)
	// a connection already open on any path first: dialling the earlier ones anew (a
	// filtered direct address: 15-35 s each) before reaching it made checks time out
	pooled := func() (Host, string) {
		for _, c := range cands {
			key := srv.ID + "|" + c.path
			reachCache.Lock()
			cached := reachCache.m[key]
			reachCache.Unlock()
			if sh, ok := cached.(*SSHHost); ok {
				// asked only whether it still answers — client() on one that doesn't dialled
				// the same address anew right here (15 s + a 20 s handshake, deaf to ctx),
				// and a check ran out of time before the path that works was tried
				if sh.answers(10 * time.Second) {
					return sh, c.path
				}
				dropKey(key)
			}
		}
		return nil, ""
	}
	if h, path := pooled(); h != nil {
		a.maybeBetterPath(srv, path)
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
	for i, c := range cands {
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
		// a path with others after it gets half of the time that is left, no more: a direct
		// address that accepts and then says nothing (ir-xe101-100's IPv4, 2026-11-20) took
		// a health check's whole 40 s, IPv6 was never tried and the tunnels were reported
		// "Iran server unreachable" while the server answered over IPv6
		dctx, dcancel, share := dialShare(ctx, len(cands)-i-1, time.Now())
		err := clientCtx(dctx, sh)
		dcancel()
		if err != nil && share > 0 && ctx.Err() == nil && dctx.Err() != nil {
			err = fmt.Errorf("no answer in %s", share.Round(time.Second))
		}
		if err != nil {
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

// dialShare bounds one path's connect when the caller has a deadline and after paths are
// still to be tried: half of the time left. share is 0 when ctx is used as it is.
func dialShare(ctx context.Context, after int, now time.Time) (context.Context, context.CancelFunc, time.Duration) {
	dl, ok := ctx.Deadline()
	if !ok || after <= 0 {
		return ctx, func() {}, 0
	}
	share := dl.Sub(now) / 2
	if share <= 0 {
		return ctx, func() {}, 0
	}
	dctx, cancel := context.WithTimeout(ctx, share)
	return dctx, cancel, share
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

// A server reached over a fallback path (direct SSH over IPv6, a jump host) stayed on it:
// the cached connection is used first while it answers a keepalive, also long after the
// direct path works again. Seen 2026-11-13 on usa-kharej: during a short SSH lock-out the
// panel fell back to "jump via xe108 iran"; once direct SSH worked again it kept the jump,
// whose Iran->foreign leg let keepalives through but stalled every script (MSS down to 64,
// cwnd 1), so the server page showed "traffic: EOF" / "live load unavailable".
// So every betterPathEvery the panel tries the better paths in the background and, when
// one connects, uses it from then on; the fallback connection is closed a minute later
// (scripts running on it can finish).
//
// A better path that does not last (an IPv4 address that flaps: it connects, the working
// IPv6 connection is retired, IPv4 dies again — 22 times in 5 hours on ir-xe101-100) is tried
// later and later: the wait doubles each time the panel is on the fallback again within
// betterPathHeld of going back, up to betterPathMax, and starts over once a return lasts.
var betterPath = struct {
	sync.Mutex
	last map[string]time.Time
	back map[string]time.Time     // when the panel last went back to a better path
	wait map[string]time.Duration // between tries (absent: betterPathEvery)
}{last: map[string]time.Time{}, back: map[string]time.Time{}, wait: map[string]time.Duration{}}

const (
	betterPathEvery = 2 * time.Minute
	betterPathMax   = 30 * time.Minute
	betterPathHeld  = 15 * time.Minute
)

// betterPathWanted: path is a fallback worth leaving (not the preferred direct / proxy path).
func betterPathWanted(path string) bool {
	return strings.HasPrefix(path, "jump via ") || path == "direct SSH over IPv6"
}

// betterPathDue says whether srv may try its better paths now, and marks the try.
func betterPathDue(serverID string, now time.Time) bool {
	betterPath.Lock()
	defer betterPath.Unlock()
	every := betterPath.wait[serverID]
	if every == 0 {
		every = betterPathEvery
	}
	// asked only while on a fallback: after a return, this is the return having ended
	if b, ok := betterPath.back[serverID]; ok {
		delete(betterPath.back, serverID)
		if now.Sub(b) < betterPathHeld {
			if every *= 2; every > betterPathMax {
				every = betterPathMax
			}
		} else {
			every = betterPathEvery
		}
		betterPath.wait[serverID] = every
	}
	if t, ok := betterPath.last[serverID]; ok && now.Sub(t) < every {
		return false
	}
	betterPath.last[serverID] = now
	return true
}

// betterPathBack notes that the panel went back to a better path of the server just now.
func betterPathBack(serverID string, now time.Time) {
	betterPath.Lock()
	betterPath.back[serverID] = now
	betterPath.Unlock()
}

// maybeBetterPath starts a background try of srv's better paths when it is on a fallback.
func (a *App) maybeBetterPath(srv *Server, path string) {
	if srv == nil || !betterPathWanted(path) || !betterPathDue(srv.ID, time.Now()) {
		return
	}
	go a.tryBetterPath(srv, path)
}

// tryBetterPath dials the paths sshReach prefers to cur (never another jump host) and, on
// the first that connects, caches it and retires cur's connection.
func (a *App) tryBetterPath(srv *Server, cur string) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	unlock, err := reachDialLock(ctx, srv.ID)
	if err != nil {
		return
	}
	defer unlock()
	for _, c := range a.sshCands(ctx, srv) {
		if c.path == cur || strings.HasPrefix(c.path, "jump via ") {
			return // nothing better than what is in use
		}
		key := srv.ID + "|" + c.path
		reachCache.Lock()
		old, _ := reachCache.m[key].(*SSHHost)
		reachCache.Unlock()
		if old != nil && old.alive() {
			retireKey(srv.ID + "|" + cur)
			return
		}
		sh := newSSHHost(a.store, srv, c.dial)
		sh.v6 = c.v6
		dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
		err := clientCtx(dctx, sh)
		dcancel()
		if err != nil {
			continue
		}
		reachCache.Lock()
		if prev, ok := reachCache.m[key].(*SSHHost); ok && prev != sh {
			prev.Close()
		}
		reachCache.m[key] = sh
		reachCache.Unlock()
		retireKey(srv.ID + "|" + cur)
		betterPathBack(srv.ID, time.Now())
		a.recordPath(srv, c.path)
		log.Printf("ssh %s: back on %s (was %s)", srv.Name, c.path, cur)
		return
	}
}

// retireKey forgets one cached connection now and closes it a minute later.
func retireKey(key string) {
	reachCache.Lock()
	h := reachCache.m[key]
	delete(reachCache.m, key)
	reachCache.Unlock()
	if c, ok := h.(interface{ Close() }); ok {
		time.AfterFunc(time.Minute, c.Close)
	}
}
