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
	case "backhaul":
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
var reverseCandidates = []int{443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880}

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
	var up, down strings.Builder
	fmt.Fprintf(&up, "%[1]s -w -I INPUT -s %[2]s -j ACCEPT -m comment --comment tp-preflight 2>/dev/null\n", ipt, d.KHPub)
	for _, p := range try {
		fmt.Fprintf(&up, "setsid nohup %s probe serve -listen :%d -life 45 >/dev/null 2>&1 </dev/null &\n", probeBin, p)
		fmt.Fprintf(&down, "pkill -f -- '-listen :%d -life 45' 2>/dev/null\n", p)
	}
	up.WriteString("sleep 0.7\n")
	fmt.Fprintf(&down, "while %[1]s -w -D INPUT -s %[2]s -j ACCEPT -m comment --comment tp-preflight 2>/dev/null; do :; done\ntrue\n", ipt, d.KHPub)
	_, _ = irHost.Run(ctx, up.String(), nil)
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	return false, fmt.Errorf("the foreign server cannot open any TCP connection to Iran %s (tried ports %s). "+
		"A reverse method needs the foreign server to dial Iran, so it cannot work on this route — something drops those connections "+
		"(Iran datacenter filtering from abroad, or the foreign provider's firewall, e.g. OVH's Network Firewall/anti-DDoS). "+
		"Use a method where Iran dials out instead: BackPack L3 (default direction), Plain GRE, Golden-GRE or IPsec",
		d.IRPub, joinInts(try))
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ", ")
}
