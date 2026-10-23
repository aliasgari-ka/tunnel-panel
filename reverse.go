package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// In every reverse method the FOREIGN server dials the IRAN server's tunnel port. When
// that connection is dropped on the path — Iranian datacenters often accept only common
// ports from abroad, and some providers (OVH's Edge Network Firewall / anti-DDoS among
// them) filter unusual flows — the units start fine and the tunnel silently never comes
// up. reversePreflight tests the path before deploying and moves the tunnel to a port
// that actually connects, or stops with a clear explanation.

// reverseTCPPort returns the option key that holds the Iran tunnel port when m (with
// t's options) is a reverse method whose foreign side dials Iran over TCP.
func reverseTCPPort(m *Method, t *Tunnel) (key string, ok bool) {
	get, _ := resolveOptions(m, t.Options[m.ID])
	switch m.ID {
	case "backhaul", "premium1":
		return "tunnel_port", get("transport") != "udp"
	case "bp_reverse":
		switch get("transport") {
		case "tcp", "tcpmux", "stealth", "ws", "wsmux", "wss", "wssmux":
			return "tunnel_port", true
		}
	case "frp":
		p := get("protocol")
		return "bind_port", p == "tcp" || p == "websocket"
	case "premium":
		return "port", get("mode") != "ipx"
	}
	return "", false
}

// candidate tunnel ports, the panel's own default first
// (then ports datacenters that let only some ports in from abroad usually leave open)
var reverseCandidates = []int{443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880,
	21, 25, 53, 110, 143, 465, 587, 993, 995, 1194, 1723, 3389, 5222, 8000, 8081, 8888, 9000, 9443, 10000, 2052, 2082, 2086, 2095}

// reversePreflight returns true when it changed the tunnel's port (plans must be rebuilt).
func (a *App) reversePreflight(ctx context.Context, j *Job, t *Tunnel, m *Method, irHost, khHost Host) (bool, error) {
	key, ok := reverseTCPPort(m, t)
	if !ok {
		return false, nil
	}
	srv, fsrv := a.store.Server(t.ServerID), a.store.Server(t.ForeignID)
	d := deriveFor(t, srv, fsrv, a.settings())
	get, _ := resolveOptions(m, t.Options[m.ID])
	pinned := get(key)
	var cands []int
	if pinned != "" {
		p, _ := strconv.Atoi(pinned)
		cands = []int{p}
	} else {
		cands = append([]int{d.BasePort}, reverseCandidates...)
	}
	// skip ports users connect to and ports something else already holds on Iran
	busy := map[int]bool{}
	for _, p := range splitPorts(withProbePort(m, t)) {
		l := p.listen
		if i := strings.LastIndex(l, ":"); i >= 0 && !strings.Contains(l, "-") {
			l = l[i+1:] // "127.0.0.1:443" binds
		}
		lo, hi := portRange(l)
		for x := lo; x <= hi && x-lo < 4096; x++ {
			busy[x] = true
		}
	}
	// and ports other tunnels on this Iran server use, even while they are stopped
	a.store.View(func(st *State) {
		for _, o := range st.Tunnels {
			if o.ID != t.ID && o.ServerID == t.ServerID {
				for p := range iranPorts(o, "") {
					busy[p] = true
				}
			}
		}
	})
	out, _ := irHost.Run(ctx, `ss -Htln 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un`, nil)
	for _, l := range strings.Fields(out) {
		if p, err := strconv.Atoi(l); err == nil {
			busy[p] = true
		}
	}
	var try []int
	for _, p := range cands {
		if p > 0 && (!busy[p] || pinned != "") {
			try = append(try, p)
		}
	}
	if len(try) == 0 {
		return false, nil
	}
	if err := pushArtifacts(ctx, j, "IR", irHost, []Artifact{probeArt}); err != nil {
		return false, nil // can't test; deploy as before
	}
	if err := pushArtifacts(ctx, j, "KH", khHost, []Artifact{probeArt}); err != nil {
		return false, nil
	}
	j.log("checking that the foreign server can reach Iran (%s) for the reverse connection — ports %s", d.IRPub, joinInts(try))
	ipt := "iptables"
	if strings.Contains(d.KHPub, ":") {
		ipt = "ip6tables"
	}
	// the probe ports are opened to everyone for the test (the foreign server may leave
	// from another address than the one saved for it), and SYNs reaching Iran are counted
	// so a failure can say where the connections get lost
	var up, down strings.Builder
	// multiport rules, 15 ports each: one rule per port took too long to remove
	for i := 0; i < len(try); i += 15 {
		chunk := try[i:min(i+15, len(try))]
		ports := joinInts(chunk)
		ports = strings.ReplaceAll(ports, " ", "")
		for _, r := range []string{
			fmt.Sprintf("INPUT -p tcp -m multiport --dports %s -j ACCEPT -m comment --comment tp-preflight", ports),
			fmt.Sprintf("PREROUTING -t mangle -p tcp --syn -m multiport --dports %s -m comment --comment tp-preflight-syn", ports),
		} {
			fmt.Fprintf(&up, "%s -w -I %s 2>/dev/null\n", ipt, r)
			fmt.Fprintf(&down, "while %s -w -D %s 2>/dev/null; do :; done\n", ipt, r)
		}
	}
	for _, p := range try {
		fmt.Fprintf(&up, "setsid nohup %s probe serve -listen :%d -life 45 >/dev/null 2>&1 </dev/null &\n", probeBin, p)
		fmt.Fprintf(&down, "pkill -f -- '-listen :%d -life 45' 2>/dev/null\n", p)
	}
	up.WriteString("sleep 0.7\n")
	down.WriteString("true\n")
	_, _ = irHost.Run(ctx, up.String(), nil)
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, _ = irHost.Run(cctx, down.String(), nil)
	}()
	// all ports in parallel from the foreign side
	var test strings.Builder
	for _, p := range try {
		fmt.Fprintf(&test, "( timeout 7 %s probe rtt -addr %s:%d -n 2 >/dev/null 2>&1 && echo OK %d ) &\n", probeBin, bracket(d.IRPub), p, p)
	}
	test.WriteString("wait\n")
	res, _ := khHost.Run(ctx, test.String(), nil)
	synOut, _ := irHost.Run(ctx, ipt+" -w -t mangle -nvxL PREROUTING 2>/dev/null | awk '/tp-preflight-syn/ {s+=$1} END {print s+0}'", nil)
	syns, _ := strconv.Atoi(strings.TrimSpace(lastLine(synOut)))
	src, _ := khHost.Run(ctx, "ip -o route get "+d.IRPub+" 2>/dev/null | sed -n 's/.* src \\([^ ]*\\).*/\\1/p' | head -1", nil)
	src = strings.TrimSpace(src)
	okPorts := map[int]bool{}
	for _, l := range strings.Split(res, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "OK" {
			if p, err := strconv.Atoi(f[1]); err == nil {
				okPorts[p] = true
			}
		}
	}
	for _, p := range try {
		if okPorts[p] {
			if p == try[0] {
				j.log("✓ foreign → Iran:%d works", p)
				return false, nil
			}
			j.log("✕ foreign → Iran:%d is blocked on the path; ✓ port %d works — using it as the tunnel port", try[0], p)
			_ = a.store.Update(func(*State) error {
				t.setOption(m.ID, key, strconv.Itoa(p))
				return nil
			})
			return true, nil
		}
	}
	if pinned != "" {
		j.log("WARNING: the foreign server cannot reach Iran:%s (the tunnel port you set) — the tunnel will not connect; clear the option to let the panel find a working port", pinned)
		return false, nil
	}
	where := fmt.Sprintf("none of its connection attempts reached the Iran server (0 SYNs counted there) — they are dropped on the way: the foreign provider's firewall/anti-DDoS for outgoing traffic (e.g. OVH Network Firewall) or Iran's filtering of connections from abroad to %s", d.IRPub)
	if syns > 0 {
		where = fmt.Sprintf("%d connection attempts DID reach the Iran server but got no answer — something on the Iran server drops them before the panel's rules (nftables/firewalld/a cloud firewall in front of it), or the answers are filtered on the way back", syns)
	}
	// the Iran server's SSH port answering from abroad means its datacenter lets only
	// some ports in, rather than blocking everything
	if srv != nil && syns == 0 {
		sp := srv.SSHPort
		if sp == 0 {
			sp = 22
		}
		if o, _ := khHost.Run(ctx, fmt.Sprintf("timeout 5 bash -c '</dev/tcp/%s/%d' 2>/dev/null && echo open", d.IRPub, sp), nil); strings.TrimSpace(lastLine(o)) == "open" {
			where = fmt.Sprintf("none of its attempts reached Iran (0 SYNs), yet the Iran server's SSH port %d IS reachable from the foreign server — so Iran's datacenter lets only certain ports in from abroad. Ask the datacenter which ports are open inbound and set that port as this method's \"Tunnel port\" (Options), or use a method where Iran dials out", sp)
		}
	}
	if src != "" && src != d.KHPub {
		where += fmt.Sprintf(" (note: the foreign server leaves from %s, not its saved %s)", src, d.KHPub)
	}
	return false, fmt.Errorf("the foreign server cannot open any TCP connection to Iran %s (tried ports %s): %s. "+
		"A reverse method needs the foreign server to dial Iran, so it cannot work on this route as it is. "+
		"Use a method where Iran dials out instead: BackPack L3 (default direction), Plain GRE, Golden-GRE or IPsec",
		d.IRPub, joinInts(try), where)
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ", ")
}

// iranPorts lists the Iran-side TCP/UDP ports tunnel t holds: the ports users connect to,
// and — for a reverse method — the tunnel port the foreign server dials. mid is the method
// to judge it by ("" = the running one, else the selected one).
func iranPorts(t *Tunnel, mid string) map[int]string {
	out := map[int]string{}
	for _, p := range splitPorts(t.Ports) {
		l := p.listen
		if i := strings.LastIndex(l, ":"); i >= 0 && !strings.Contains(l, "-") {
			l = l[i+1:]
		}
		lo, hi := portRange(l)
		for x := lo; x > 0 && x <= hi && x-lo < 4096; x++ {
			out[x] = "forwarded port"
		}
	}
	if mid == "" {
		mid = t.Active
	}
	if mid == "" {
		mid = t.Selected
	}
	if m := methodByID[mid]; m != nil {
		if key, ok := reverseTCPPort(m, t); ok {
			get, _ := resolveOptions(m, t.Options[m.ID])
			if p, err := strconv.Atoi(portOr(get(key), 40000+t.Index*4)); err == nil {
				out[p] = m.Title + " tunnel port"
			}
		}
	}
	return out
}

// portClash finds another tunnel on the same Iran server that holds one of the ports t
// would use: two DNAT rules or listeners on one port means only one tunnel gets the traffic.
func portClash(st *State, t *Tunnel, mid string) error {
	mine := iranPorts(t, mid)
	for _, o := range st.Tunnels {
		// a hot-standby path (ID "<tunnel>x<index>") of o is o itself: its first path takes
		// o's own tunnel port, which used to be refused as a clash with o — and so the
		// tunnel's own (often best) method never became a hot-standby path
		if o.ID == t.ID || o.ServerID != t.ServerID || strings.HasPrefix(t.ID, o.ID+"x") {
			continue
		}
		for p, what := range iranPorts(o, "") {
			if mw, ok := mine[p]; ok {
				hint := "give this tunnel another Iran port and map it to the service, e.g. " + strconv.Itoa(p+1) + "=" + strconv.Itoa(p) + " (users connect to Iran " + strconv.Itoa(p+1) + ", it reaches port " + strconv.Itoa(p) + " on the foreign server)"
				if strings.Contains(mw, "tunnel port") || strings.Contains(what, "tunnel port") {
					hint = "clear the tunnel-port option of one of them (the panel then picks a free one) or set a different one"
				}
				return fmt.Errorf("Iran port %d is already used by tunnel %q (%s) on this Iran server — two tunnels can't share one Iran port, only one of them would get the traffic; %s", p, o.Name, what, hint)
			}
		}
	}
	return nil
}

// portHolder is a process listening on one of a tunnel's Iran ports.
type portHolder struct {
	port, pid       int
	unit, name, cmd string
}

// heldPorts lists who listens (TCP or UDP) on the given ports of a host.
func heldPorts(ctx context.Context, h Host, ports []int) []portHolder {
	if len(ports) == 0 {
		return nil
	}
	var ps []string
	for _, p := range ports {
		ps = append(ps, strconv.Itoa(p))
	}
	out, _ := h.Run(ctx, `for p in `+strings.Join(ps, " ")+`; do
  ss -Hltunp "( sport = :$p )" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u | while read pid; do
    u=$(grep -o 'tp-[0-9a-z-]*\.service' /proc/$pid/cgroup 2>/dev/null | head -1)
    echo "HELD $p $pid ${u:-none} $(cat /proc/$pid/comm 2>/dev/null) $(tr '\0' ' ' </proc/$pid/cmdline 2>/dev/null | cut -c1-200)"
  done
done`, nil)
	var res []portHolder
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || f[0] != "HELD" {
			continue
		}
		p, _ := strconv.Atoi(f[1])
		pid, _ := strconv.Atoi(f[2])
		res = append(res, portHolder{p, pid, f[3], f[4], strings.Join(f[5:], " ")})
	}
	return res
}

// userspaceIran: the method's own daemon binds the users' ports on Iran (the kernel
// tunnels DNAT them instead, so another listener there doesn't take their traffic).
func userspaceIran(m *Method, t *Tunnel) bool {
	switch m.ID {
	case "gre", "direct6", "ipsec6", "golden", "spoof", "bp_l3":
		return false
	case "premium": // ipx forwards with its own iptables rules
		get, _ := resolveOptions(m, t.Options[m.ID])
		return get("mode") != "ipx"
	}
	return true
}

// freeIranPorts runs after the old method was stopped: a panel process left over on one
// of the tunnel's ports is stopped; anything else holding a port the method must bind is
// an error naming the program, instead of a daemon that starts and never forwards.
func (a *App) freeIranPorts(ctx context.Context, j *Job, h Host, t *Tunnel, m *Method) (map[int]int, error) {
	want := iranPorts(t, m.ID)
	if userspaceIran(m, t) && !benchIsL3(m, t.Options[m.ID]) {
		want[probePortFor(t)] = "speed-test port"
	}
	var ports []int
	for p := range want {
		ports = append(ports, p)
	}
	redir := map[int]int{}
	for _, hp := range heldPorts(ctx, h, ports) {
		switch {
		case userspaceIran(m, t) && want[hp.port] == "forwarded port" && hp.unit == "none" && !strings.Contains(hp.cmd, "/etc/tunnel-panel/t/"):
			// another program (haproxy, xray…) has the users' port: listen on a free
			// internal port and REDIRECT the outside traffic there, like the DNAT methods
			q := a.freeInternalPort(ctx, h, t, len(redir))
			if q == 0 {
				return nil, fmt.Errorf("Iran port %d is used by %s (pid %d) and no free internal port was found for a redirect", hp.port, hp.name, hp.pid)
			}
			redir[hp.port] = q
			j.log("[IR] port %d is held by %s (pid %d): %s will listen on %d and outside traffic to %d is redirected there — %s keeps %d only for connections made on the Iran server itself", hp.port, hp.name, hp.pid, m.Title, q, hp.port, hp.name, hp.port)
		case hp.unit == unitName(t) || strings.Contains(hp.cmd, tunnelDir(t)+"/") || strings.Contains(hp.cmd, "probe serve -listen :"+strconv.Itoa(hp.port)+" "):
			j.log("[IR] port %d was still held by a leftover %s (pid %d) — stopping it", hp.port, hp.name, hp.pid)
			_, _ = h.Run(ctx, fmt.Sprintf("kill %d 2>/dev/null; sleep 1; kill -9 %d 2>/dev/null; true", hp.pid, hp.pid), nil)
		case strings.HasPrefix(hp.unit, "tp-"):
			other := strings.TrimSuffix(strings.TrimPrefix(hp.unit, "tp-"), ".service")
			name := other
			if o := a.store.Tunnel(other); o != nil {
				name = o.Name
			}
			return nil, fmt.Errorf("Iran port %d (%s) is held by tunnel %q on this Iran server — give one of them another port", hp.port, want[hp.port], name)
		case userspaceIran(m, t):
			return nil, fmt.Errorf("Iran port %d (%s) is already used on the Iran server by %s (pid %d: %s) — %s must listen on it itself. Stop that program, or give this tunnel another Iran port mapped to the service (e.g. %d=%d)",
				hp.port, want[hp.port], hp.name, hp.pid, hp.cmd, m.Title, hp.port+1, hp.port)
		default:
			j.log("[IR] note: %s (pid %d) also listens on port %d on Iran; users from outside still reach the tunnel (DNAT), only connections made on the Iran server itself go to that program", hp.name, hp.pid, hp.port)
		}
	}
	return redir, nil
}

// freeInternalPort picks the k-th per-tunnel internal port (50000+index*20+k…) that
// nothing listens on.
func (a *App) freeInternalPort(ctx context.Context, h Host, t *Tunnel, k int) int {
	for ; k < 20; k++ {
		q := 50000 + t.Index*20 + k
		if len(heldPorts(ctx, h, []int{q})) == 0 {
			return q
		}
	}
	return 0
}
