package main

import (
	"bufio"
	"context"
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

	var lastErr error
	for _, c := range cands {
		if err := ctx.Err(); err != nil { // the caller gave up (a status page, the bot): stop trying
			if lastErr != nil {
				return nil, "", fmt.Errorf("%w (then gave up: %v)", lastErr, err)
			}
			return nil, "", err
		}
		key := srv.ID + "|" + c.path
		reachCache.Lock()
		cached := reachCache.m[key]
		reachCache.Unlock()
		if sh, ok := cached.(*SSHHost); ok {
			if _, err := sh.client(); err == nil {
				return sh, c.path, nil
			}
			dropHost(srv.ID)
		}
		logf("trying %s", c.path)
		sh := newSSHHost(a.store, srv, c.dial)
		sh.v6 = c.v6
		if err := clientCtx(ctx, sh); err != nil {
			lastErr = fmt.Errorf("%s: %w", c.path, err)
			logf("  %s failed: %v", c.path, err)
			continue
		}
		reachCache.Lock()
		reachCache.m[key] = sh
		reachCache.Unlock()
		return sh, c.path, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no SSH path available")
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
		for _, s := range st.Servers {
			if s.ID != exclude && (s.Prepared || (a.agents != nil && a.agents.online(s.ID) != nil)) {
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
			return nil, fmt.Errorf("jump host %s unreachable: %w", via.Name, err)
		}
		return sh.Dial(addr)
	}
}

// ---- dialers ----

func directDial(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 15*time.Second)
}

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
			return d.Dial("tcp", addr)
		}
	case "http", "https":
		return func(addr string) (net.Conn, error) { return httpConnect(u, addr) }
	default:
		return func(string) (net.Conn, error) { return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme) }
	}
}

func httpConnect(u *url.URL, addr string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", u.Host, 15*time.Second)
	if err != nil {
		return nil, err
	}
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
	return c, nil
}
