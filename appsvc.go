package main

import (
	"context"
	"fmt"
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

// TestServer probes agent + SSH paths and records which works, fastest first.
func (a *App) TestServer(ctx context.Context, srv *Server) TestResult {
	var res TestResult
	probe := func(name string, h Host) {
		pr := PathResult{Path: name}
		start := time.Now()
		out, err := h.Run(ctx, "echo ok; uname -m; . /etc/os-release 2>/dev/null; echo ID=$ID", nil)
		pr.ms = time.Since(start).Milliseconds()
		if err != nil {
			pr.Info = err.Error()
		} else {
			pr.OK = true
			pr.Info = fmt.Sprintf("%dms", pr.ms)
			arch, os2 := "", ""
			for _, l := range strings.Split(out, "\n") {
				l = strings.TrimSpace(l)
				if l != "" && l != "ok" && arch == "" && !strings.HasPrefix(l, "ID=") {
					arch = l
				}
				if strings.HasPrefix(l, "ID=") {
					os2 = strings.TrimPrefix(l, "ID=")
				}
			}
			if res.Arch == "" {
				res.Arch, res.OS = arch, os2
			}
		}
		res.Paths = append(res.Paths, pr)
	}

	if a.agents != nil && a.agents.online(srv.ID) != nil {
		probe("agent (dial-back)", AgentHost{hub: a.agents, serverID: srv.ID})
	}
	// SSH paths
	if srv.Proxy != "" {
		probe("SSH via proxy", newSSHHost(a.store, srv, proxyDial(srv.Proxy)))
	}
	probe("direct SSH", newSSHHost(a.store, srv, directDial))
	for _, via := range a.otherServers(srv.ID) {
		probe("jump via "+via.Name, newSSHHost(a.store, srv, a.jumpDial(ctx, via)))
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
	if set.TelegramTok == "" {
		return
	}
	a.bot = newBot(a, set.TelegramTok, set.TelegramAdmin)
	go a.bot.Run()
}
