package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// syncAgentTokens refreshes the hub's token→server map from the store.
func (a *App) syncAgentTokens() {
	var servers []*Server
	a.store.View(func(st *State) { servers = append(servers, st.Servers...) })
	if a.agents != nil {
		a.agents.setTokens(servers)
	}
}

// agentConnect is the host:port Iran agents dial back to.
func (a *App) agentConnect() string {
	set := a.settings()
	if set.AgentConnect != "" {
		return set.AgentConnect
	}
	if set.LocalIPv4 != "" {
		return fmt.Sprintf("%s:%d", set.LocalIPv4, a.agentPort)
	}
	if set.LocalIPv6 != "" {
		return fmt.Sprintf("[%s]:%d", set.LocalIPv6, a.agentPort)
	}
	return ""
}

// PathResult is one reachability path and whether it works.
type PathResult struct {
	Path string `json:"path"`
	OK   bool   `json:"ok"`
	Info string `json:"info"`
	ms   int64
}

// TestResult is the outcome of probing every path to a server.
type TestResult struct {
	OK    bool         `json:"ok"`
	Best  string       `json:"best"`
	Arch  string       `json:"arch,omitempty"`
	OS    string       `json:"os,omitempty"`
	Paths []PathResult `json:"paths"`
}

// TestServer probes agent + SSH paths and records which works, fastest first. The paths
// are probed at once and a path still pending when ctx ends counts as timed out: an SSH
// dial through a jump host doesn't follow ctx and can hang for minutes on a blocked route.
func (a *App) TestServer(ctx context.Context, srv *Server) TestResult {
	type cand struct {
		name string
		h    Host
	}
	var cands []cand
	if a.agents != nil && a.agents.online(srv.ID) != nil {
		cands = append(cands, cand{"agent (dial-back)", AgentHost{hub: a.agents, serverID: srv.ID}})
	}
	// SSH paths
	if srv.Proxy != "" {
		cands = append(cands, cand{"SSH via proxy", newSSHHost(a.store, srv, proxyDial(srv.Proxy))})
	}
	cands = append(cands, cand{"direct SSH", newSSHHost(a.store, srv, directDial)})
	for _, via := range a.otherServers(srv.ID) {
		cands = append(cands, cand{"jump via " + via.Name, newSSHHost(a.store, srv, a.jumpDial(ctx, via))})
	}

	type probed struct {
		i        int
		pr       PathResult
		arch, os string
	}
	ch := make(chan probed, len(cands))
	for i, c := range cands {
		go func(i int, c cand) {
			r := probed{i: i, pr: PathResult{Path: c.name}}
			start := time.Now()
			out, err := c.h.Run(ctx, "echo ok; uname -m; . /etc/os-release 2>/dev/null; echo ID=$ID", nil)
			r.pr.ms = time.Since(start).Milliseconds()
			if err != nil {
				r.pr.Info = err.Error()
			} else {
				r.pr.OK = true
				r.pr.Info = fmt.Sprintf("%dms", r.pr.ms)
				for _, l := range strings.Split(out, "\n") {
					l = strings.TrimSpace(l)
					if l != "" && l != "ok" && r.arch == "" && !strings.HasPrefix(l, "ID=") {
						r.arch = l
					}
					if strings.HasPrefix(l, "ID=") {
						r.os = strings.TrimPrefix(l, "ID=")
					}
				}
			}
			ch <- r
		}(i, c)
	}
	got := make([]*probed, len(cands))
wait:
	for n := 0; n < len(cands); n++ {
		select {
		case r := <-ch:
			got[r.i] = &r
		case <-ctx.Done():
			break wait
		}
	}

	var res TestResult
	var okHost Host
	for i, c := range cands {
		r := got[i]
		if r == nil {
			res.Paths = append(res.Paths, PathResult{Path: c.name, Info: "timed out"})
			continue
		}
		if r.pr.OK && okHost == nil {
			okHost, res.Arch, res.OS = c.h, r.arch, r.os
		}
		res.Paths = append(res.Paths, r.pr)
	}

	for _, p := range res.Paths {
		if p.OK {
			res.OK = true
			if res.Best == "" {
				res.Best = p.Path
			}
		}
	}
	if res.OK {
		_ = a.store.Update(func(st *State) error {
			if x := a.store.serverLocked(st, srv.ID); x != nil {
				x.Prepared, x.Arch, x.OS, x.LastPath = true, res.Arch, res.OS, res.Best
			}
			return nil
		})
		// missing IPs are read from the server itself; first contact also pre-installs binaries
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		a.autoSetup(sctx, srv, okHost)
	}
	return res
}

// restartBot (re)starts the Telegram bot to match current settings.
func (a *App) restartBot() {
	a.botMu.Lock()
	defer a.botMu.Unlock()
	if a.bot != nil {
		a.bot.Stop()
		a.bot = nil
	}
	set := a.settings()
	a.startUserBotsLocked(set.TelegramTok)
	if set.TelegramTok == "" {
		return
	}
	a.bot = newBot(a, set.TelegramTok, set.TelegramAdmin)
	go a.bot.Run()
}

// addrScript reports the host's own addresses: the source it uses for the default
// routes, plus (only when that IPv4 is private/NATed) what the internet sees.
const addrScript = `v4=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
v6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | sed -n 's/.* src \([0-9a-fA-F:]*\).*/\1/p' | head -1)
# an address without a default IPv6 route can't carry a tunnel: report none
if [ -n "$(ip -6 route show default 2>/dev/null)" ]; then
  [ -n "$v6" ] || v6=$(ip -6 -o addr show scope global 2>/dev/null | grep -v -e temporary -e deprecated | awk '{print $4}' | cut -d/ -f1 | grep -iv '^f[cd]' | head -1)
  [ -n "$v6" ] || v6=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep : | grep -iv '^f[cde]' | head -1)
else
  v6=""
fi
[ -n "$v4" ] || v4=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v : | head -1)
echo "V4=$v4"
echo "V6=$v6"
case "$v4" in 10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|"")
  echo "PUB4=$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || curl -4 -fsS --max-time 4 https://ifconfig.me 2>/dev/null)";;
esac
`

// detectAddrs returns the public IPv4/IPv6 a host uses (empty when it has none).
func detectAddrs(ctx context.Context, h Host) (v4, v6 string) {
	out, _ := h.Run(ctx, addrScript, nil)
	var pub4 string
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(v))
		switch k {
		case "V4":
			if ip != nil && ip.To4() != nil && isPublic(ip) {
				v4 = ip.String()
			}
		case "V6":
			if ip != nil && ip.To4() == nil && isPublic(ip) {
				v6 = ip.String()
			}
		case "PUB4":
			if ip != nil && ip.To4() != nil && isPublic(ip) {
				pub4 = ip.String()
			}
		}
	}
	if v4 == "" {
		v4 = pub4
	}
	return v4, v6
}

func isPublic(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() { // IsPrivate covers 10/8, 172.16/12, 192.168/16, fc00::/7
		return false
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return !cgnat.Contains(ip)
}

// autoSetup fills in a server's missing addresses from the server itself, then
// pre-installs every method's binaries once (see Prepare).
func (a *App) autoSetup(ctx context.Context, srv *Server, h Host) {
	if srv.IPv4 == "" || srv.IPv6 == "" {
		v4, v6 := detectAddrs(ctx, h)
		_ = a.store.Update(func(st *State) error {
			if x := a.store.serverLocked(st, srv.ID); x != nil {
				if x.IPv4 == "" && v4 != "" {
					x.IPv4 = v4
				}
				if x.IPv6 == "" && v6 != "" {
					x.IPv6 = v6
				}
			}
			return nil
		})
	}
	if cur := a.store.Server(srv.ID); cur != nil {
		_ = a.fixIPv6(ctx, h, srv.ID, cur.IPv6)
	}
	if cur := a.store.Server(srv.ID); cur != nil && cur.Provisioned == 0 {
		_, _ = a.Prepare(cur)
	}
}

// autoSetupLocal fills the panel host's own addresses in Settings when blank and
// pre-installs the foreign-side binaries on it.
func (a *App) autoSetupLocal() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	set := a.settings()
	if set.LocalIPv4 == "" || set.LocalIPv6 == "" {
		v4, v6 := detectAddrs(ctx, LocalHost{})
		_ = a.store.Update(func(st *State) error {
			if st.Settings.LocalIPv4 == "" {
				st.Settings.LocalIPv4 = v4
			}
			if st.Settings.LocalIPv6 == "" {
				st.Settings.LocalIPv6 = v6
			}
			return nil
		})
	}
	_, _ = a.Prepare(nil)
}

// fixIPv6 corrects a saved IPv6 that the server doesn't actually have (a typo, or an
// address the provider changed): kernel tunnels and IPsec can only use the server's own
// address, and the peer must be told the right one. srvID "" is the panel host (Settings).
// Returns a note for the log when it changed something.
func (a *App) fixIPv6(ctx context.Context, h Host, srvID, saved string) string {
	if saved == "" {
		return ""
	}
	out, err := h.Run(ctx, "ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1", nil)
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(out) {
		if ip := net.ParseIP(f); ip != nil && ip.String() == saved {
			return ""
		}
	}
	_, v6 := detectAddrs(ctx, h)
	if v6 == "" || v6 == saved {
		return ""
	}
	_ = a.store.Update(func(st *State) error {
		if srvID == "" {
			st.Settings.LocalIPv6 = v6
		} else if x := a.store.serverLocked(st, srvID); x != nil {
			x.IPv6 = v6
		}
		return nil
	})
	return fmt.Sprintf("the saved IPv6 %s is not on this server — it has %s; corrected", saved, v6)
}
