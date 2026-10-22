package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Diagnose walks a running tunnel hop by hop and says, in plain words, where traffic
// stops: units, tunnel link, path MTU in both directions, Iran forwarding/DNAT, the
// service on the foreign side, and an end-to-end connect through the tunnel.
func (a *App) Diagnose(t *Tunnel) (*Job, error) {
	if t.Active == "" {
		return nil, fmt.Errorf("start the tunnel first")
	}
	m := methodByID[t.Active]
	if m == nil {
		return nil, fmt.Errorf("unknown method")
	}
	j, err := a.jobs.start(t.ID, "diagnose")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(4 * time.Minute)
		defer cancel()
		problems := 0
		ok := func(f string, x ...any) { j.log("  ✓ "+f, x...) }
		bad := func(f string, x ...any) { problems++; j.log("  ✕ "+f, x...) }
		hint := func(f string, x ...any) { j.log("    → "+f, x...) }

		srv := a.store.Server(t.ServerID)
		if srv == nil {
			j.log("ERROR: Iran server not found")
			j.finish("error")
			return
		}
		ir, _, err := a.reach(ctx, srv, nil)
		if err != nil {
			j.log("ERROR: cannot reach Iran: %v", err)
			j.finish("error")
			return
		}
		kh, _, err := a.foreignHost(ctx, t, nil)
		if err != nil {
			j.log("ERROR: cannot reach foreign: %v", err)
			j.finish("error")
			return
		}
		d := deriveFor(t, srv, a.store.Server(t.ForeignID), a.settings())
		l3 := benchIsL3(m, t.Options[m.ID])
		unit := unitName(t)
		run := func(h Host, sh string) string { out, _ := h.Run(ctx, sh, nil); return strings.TrimSpace(out) }

		j.log("Diagnosing %s — %s (%s)", t.Name, m.Title, map[bool]string{true: "L3 tunnel", false: "port forwarder"}[l3])

		// 1. units
		j.log("1. services")
		for _, side := range []struct {
			n string
			h Host
		}{{"Iran", ir}, {"foreign", kh}} {
			st := lastLine(run(side.h, "systemctl is-active "+unit+" 2>/dev/null || true"))
			if st == "active" {
				ok("%s: %s active", side.n, unit)
			} else {
				bad("%s: %s is %s", side.n, unit, st)
				for _, l := range strings.Split(run(side.h, "journalctl -u "+unit+" -n 6 --no-pager -o cat 2>/dev/null"), "\n") {
					hint("%s", l)
				}
			}
			if errs := run(side.h, "journalctl -u "+unit+" --since -10min --no-pager -o cat 2>/dev/null | grep -iE 'error|fatal|fail|denied|refused|timeout' | tail -3"); errs != "" {
				j.log("  ! recent errors on %s:", side.n)
				for _, l := range strings.Split(errs, "\n") {
					hint("%s", l)
				}
			}
		}

		// 1b. the underlay: do the two servers reach each other over this family at all?
		fam := map[string]string{"v4": "IPv4", "v6": "IPv6"}[t.Family]
		j.log("1b. %s between the servers (%s → %s)", fam, d.IRPub, d.KHPub)
		under := run(ir, fmt.Sprintf("ping -n -c 3 -i 0.3 -W 2 %s >/dev/null 2>&1 && echo ping", d.KHPub))
		if under != "ping" {
			sshp := "22"
			if f := a.store.Server(t.ForeignID); f != nil && f.SSHPort > 0 {
				sshp = strconv.Itoa(f.SSHPort)
			}
			under = run(ir, tcpReach(d.KHPub, sshp))
		}
		switch under {
		case "ping", "open", "refused":
			ok("Iran reaches the foreign server over %s", fam)
		default:
			// only a warning: ping may be filtered and SSH open to some IPs only, while the
			// tunnel itself (often dialled from the foreign side) still works — the steps below decide
			j.log("  ⚠ Iran gets no ping or TCP answer from %s over %s", d.KHPub, fam)
			if t.Family == "v6" {
				hint("if the checks below fail too, IPv6 between these servers is the problem (common with Iranian datacenters' IPv6 transit) — switch the tunnel to IPv4 in Manage")
			} else {
				hint("if the checks below fail too, check the public IPs and both providers' firewalls")
			}
		}

		// 2. tunnel link + path MTU (L3 only)
		if l3 {
			ifc := trafficIface(t)
			j.log("2. tunnel link (%s, %s ⇄ %s)", ifc, d.IRv4, d.KHv4)
			if run(ir, "[ -d /sys/class/net/"+ifc+" ] && echo yes") == "yes" {
				ok("interface %s exists on Iran (mtu %s)", ifc, run(ir, "cat /sys/class/net/"+ifc+"/mtu"))
			} else {
				bad("interface %s is missing on Iran", ifc)
			}
			pingOK := false
			if _, _, loss, err := parsePing(run(ir, fmt.Sprintf("ping -n -c 4 -i 0.3 -W 2 %s 2>/dev/null | tail -3", d.KHv4))); err == nil && loss < 100 {
				ok("ping through the tunnel works (loss %.0f%%)", loss)
				pingOK = true
			}
			tcp := run(ir, tcpReach(d.KHv4, probePortOf(t)))
			switch {
			case pingOK:
			case tcp == "open" || tcp == "refused":
				// the link works; only ICMP doesn't — say why instead of flagging the tunnel
				why := "ICMP is blocked on the path or by a firewall"
				if run(ir, "command -v ping >/dev/null && echo y") != "y" {
					why = "ping isn't installed on the Iran server (apt install iputils-ping)"
				} else if run(kh, "cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null") == "1" {
					why = "the foreign server ignores pings (net.ipv4.icmp_echo_ignore_all = 1)"
				}
				ok("the tunnel carries traffic (TCP to %s:%s %s)", d.KHv4, probePortOf(t), map[string]string{"open": "connects", "refused": "is answered"}[tcp])
				j.log("  ⚠ ping doesn't answer: %s — harmless, but the path MTU can't be measured", why)
			default:
				bad("nothing passes through the tunnel (no ping reply, TCP to %s:%s times out)", d.KHv4, probePortOf(t))
				gget, _ := resolveOptions(m, t.Options[m.ID])
				switch {
				case m.ID == "direct6" && gget("carrier") != "udp":
					hint("GRE (protocol 47) is probably dropped on the IPv6 path or by a provider firewall — open Options, set Carrier = udp and Re-apply (GRE inside UDP), or use IPsec / BackPack / Backhaul over IPv6")
				case m.ID == "bp_l3":
					bget, _ := resolveOptions(m, t.Options[m.ID])
					who, port := "Iran dials the foreign server", portOr(bget("port"), d.BasePort)
					if bget("dialer") == "foreign" {
						who = "the foreign server dials Iran"
					}
					hint("the BackPack link isn't up: %s on %s port %s — a provider/cloud firewall blocking that port is the usual cause; try Carrier = quic or sni, or switch \"Who connects\"", who, map[string]string{"udp": "UDP", "quic": "UDP (QUIC)"}[bget("carrier")]+orStr(map[string]string{"pck": "raw", "sni": "TCP", "xdi": "raw"}[bget("carrier")], ""), port)
				case m.ID == "gre":
					hint("GRE (protocol 47) is probably dropped on the path or by a provider/cloud firewall — allow GRE there, or use %s", map[string]string{"v6": "Direct v6 with Carrier = udp, IPsec, BackPack or Backhaul", "v4": "Golden-GRE (looks like DNS), IPsec, BackPack or Backhaul"}[t.Family])
				}
			}
			mtu, _ := strconv.Atoi(run(ir, "cat /sys/class/net/"+ifc+"/mtu 2>/dev/null"))
			if mtu > 0 && pingOK {
				up := pmtu(run, ir, d.KHv4, mtu)
				down := pmtu(run, kh, d.IRv4, mtu)
				j.log("  path MTU through the tunnel: Iran→foreign %s, foreign→Iran %s (interface MTU %d)", mtuStr(up), mtuStr(down), mtu)
				if up < mtu || down < mtu {
					bad("full-size packets (%d) are dropped inside the tunnel", mtu)
					lo := up
					if down < lo {
						lo = down
					}
					if lo > 0 && m.ID == "premium" {
						hint("set the method option \"TUN MTU\" to %d (or lower) and Re-apply", lo-20)
					} else if lo > 0 {
						hint("lower the method's MTU option to %d and Re-apply", lo-20)
					} else {
						hint("only small packets pass — lower the MTU option and Re-apply")
					}
				} else {
					ok("full-size packets pass both ways")
				}
			}
		}

		// 3. Iran side: how users get in
		j.log("3. Iran entry (ports %s)", t.Ports)
		dnat := l3 && m.ID != "bp_l3" // BackPack L3 forwards ports with a userspace listener
		if dnat {
			if v := run(ir, "cat /proc/sys/net/ipv4/ip_forward"); v == "1" {
				ok("ip_forward = 1")
			} else {
				bad("ip_forward = %s (must be 1)", v)
				hint("run on Iran: sysctl -w net.ipv4.ip_forward=1")
			}
			pol := run(ir, "iptables -w -S FORWARD 2>/dev/null | head -1")
			if strings.Contains(pol, "DROP") {
				if run(ir, "iptables -w -S FORWARD 2>/dev/null | grep -c -e '-j TPF_' -e 'ACCEPT'") != "0" {
					ok("FORWARD policy is DROP but the tunnel's accept rules are in place")
				} else {
					bad("FORWARD policy is DROP and nothing accepts the tunnel traffic")
					hint("Re-apply the tunnel (this version adds the accept rules)")
				}
			} else {
				ok("FORWARD policy: %s", strings.TrimPrefix(pol, "-P FORWARD "))
			}
		}
		for _, p := range firstPorts(t.Ports, 3) {
			if dnat {
				if run(ir, "iptables -w -t nat -S 2>/dev/null | grep -c -- '--dport "+p.listen+" '") != "0" {
					ok("DNAT rule for port %s present", p.listen)
				} else {
					bad("no DNAT rule for port %s on Iran — users hitting it go nowhere", p.listen)
				}
			} else if pn, _ := strconv.Atoi(p.listen); pn > 0 && len(heldPorts(ctx, ir, []int{pn})) > 0 {
				// listening is not enough: it must be this tunnel's daemon
				hp := heldPorts(ctx, ir, []int{pn})[0]
				if hp.unit == unitName(t) {
					ok("Iran listens on port %s (%s, this tunnel)", p.listen, hp.name)
				} else {
					bad("Iran port %s is held by %s (pid %d: %s), not by this tunnel — users reach that program instead", p.listen, hp.name, hp.pid, hp.cmd)
					hint("stop that program or give this tunnel another Iran port (e.g. %d=%s), then Re-apply", pn+1, p.listen)
				}
			} else {
				bad("nothing listens on Iran port %s", p.listen)
			}
		}

		// 3b. reverse methods: can the foreign server reach Iran's tunnel port at all?
		if key, isRev := reverseTCPPort(m, t); isRev {
			get, _ := resolveOptions(m, t.Options[m.ID])
			tp := portOr(get(key), d.BasePort)
			if run(kh, fmt.Sprintf("timeout 6 bash -c '</dev/tcp/%s/%s' 2>/dev/null && echo open", d.IRPub, tp)) == "open" {
				ok("foreign → Iran %s:%s (the reverse connection) is reachable", d.IRPub, tp)
			} else {
				bad("the foreign server cannot connect to Iran %s:%s — the reverse connection is dropped on the path", d.IRPub, tp)
				hint("Re-apply with the method's tunnel port left blank: the panel then tests 443, 8443, 2053… and picks one that gets through")
				hint("if no port works (provider firewall such as OVH's, or Iran filtering), use BackPack L3, GRE, Golden-GRE or IPsec — there Iran dials out")
			}
		}

		// 4. foreign side: is there a service to deliver to?
		j.log("4. foreign service")
		for _, p := range firstPorts(t.Ports, 3) {
			dst := p.dst
			if i := strings.LastIndex(dst, ":"); i >= 0 {
				dst = dst[i+1:]
			}
			ls := run(kh, "ss -Hltn 'sport = :"+dst+"' 2>/dev/null | awk '{print $4}' | sort -u | tr '\\n' ' '")
			lsu := run(kh, "ss -Hlun 'sport = :"+dst+"' 2>/dev/null | awk '{print $4}' | sort -u | tr '\\n' ' '")
			anyAddr := strings.Contains(ls, "0.0.0.0:") || strings.Contains(ls, "*:") || strings.Contains(ls, "[::]:")
			switch {
			case ls == "" && lsu != "":
				if l3 {
					ok("foreign UDP service on port %s (%s)", dst, strings.TrimSpace(lsu))
				} else {
					bad("the foreign service on port %s is UDP-only (%s), but this tunnel forwards TCP", dst, strings.TrimSpace(lsu))
					hint("enable the method's \"forward UDP\" option and Re-apply, or pick an L3 method (GRE, BackPack L3, Golden-GRE) that carries UDP")
				}
			case ls == "":
				bad("nothing listens on foreign port %s", dst)
				hint("the tunnel only carries traffic to a service — start your xray/v2ray/… inbound on port %s on the foreign server", dst)
			case !l3 && !anyAddr && !strings.Contains(ls, "127.0.0.1:") && !strings.Contains(ls, "[::1]:"):
				bad("foreign port %s listens only on %s", dst, strings.TrimSpace(ls))
				hint("%s delivers to 127.0.0.1:%s on the foreign server — make the service listen on 0.0.0.0 (or 127.0.0.1)", m.Title, dst)
			case l3 && !strings.Contains(ls, "0.0.0.0:") && !strings.Contains(ls, "*:") && !strings.Contains(ls, "[::]:") && !strings.Contains(ls, d.KHv4+":"):
				bad("foreign port %s listens only on %s", dst, ls)
				hint("L3 tunnels deliver to %s:%s — make the service listen on 0.0.0.0, or use a port-forward method (Backhaul/FRP)", d.KHv4, dst)
			default:
				ok("foreign service on port %s (%s)", dst, strings.TrimSpace(ls))
			}
			if !l3 && ls != "" {
				// a reverse tunnel accepts on Iran before it knows the backend works, so test
				// the hop it actually makes on the foreign side
				if run(kh, fmt.Sprintf("timeout 4 bash -c '</dev/tcp/127.0.0.1/%s' 2>/dev/null && echo open", dst)) == "open" {
					ok("foreign 127.0.0.1:%s accepts connections (where the tunnel delivers)", dst)
				} else {
					bad("foreign 127.0.0.1:%s refuses connections — the tunnel delivers there", dst)
				}
			}
		}

		// 5. end to end from Iran
		j.log("5. end to end")
		for _, p := range firstPorts(t.Ports, 3) {
			host, port := "127.0.0.1", p.listen
			if l3 {
				host, port = d.KHv4, p.dst
				if i := strings.LastIndex(port, ":"); i >= 0 {
					port = port[i+1:]
				}
			}
			if run(ir, fmt.Sprintf("timeout 6 bash -c '</dev/tcp/%s/%s' 2>/dev/null && echo open", host, port)) == "open" {
				ok("TCP connect from Iran to %s:%s through the tunnel works", host, port)
			} else {
				bad("TCP connect from Iran to %s:%s through the tunnel fails", host, port)
			}
		}

		// 6. what the counters say right now
		if st := a.Traffic().Tunnels[t.ID]; st != nil && st.Error == "" {
			j.log("6. traffic: ↓ %s ↑ %s now, total ↓ %s ↑ %s", fmtRate(st.Down), fmtRate(st.Up), fmtBytes(st.TotalDown), fmtBytes(st.TotalUp))
		}
		if problems == 0 {
			j.log("DONE — no problem found. If clients still fail, check the client config points at the Iran IP and port %s.", firstPort(t.Ports))
		} else {
			j.log("DONE — %d problem(s) found, see ✕ above", problems)
		}
		j.finish("ok")
	}()
	return j, nil
}

// pmtu finds the largest packet (IP size) that crosses to dst unfragmented, between 576 and max.
func pmtu(run func(Host, string) string, h Host, dst string, max int) int {
	try := func(size int) bool {
		return run(h, fmt.Sprintf("ping -n -c 2 -i 0.3 -W 2 -M do -s %d %s >/dev/null 2>&1 && echo y", size-28, dst)) == "y"
	}
	if try(max) {
		return max
	}
	lo, hi := 576, max
	if !try(lo) {
		return 0
	}
	for hi-lo > 8 {
		mid := (lo + hi) / 2
		if try(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

func mtuStr(v int) string {
	if v == 0 {
		return "fails"
	}
	return strconv.Itoa(v)
}

// firstPorts returns up to n single ports (ranges contribute their first port).
func firstPorts(ports string, n int) []portSpec {
	var out []portSpec
	for _, p := range splitPorts(ports) {
		cut := func(s string) string {
			if i := strings.IndexAny(s, "-"); i > 0 {
				return s[:i]
			}
			return s
		}
		l := cut(p.listen)
		if i := strings.LastIndex(l, ":"); i >= 0 {
			l = l[i+1:]
		}
		out = append(out, portSpec{listen: l, dst: cut(p.dst)})
		if len(out) == n {
			break
		}
	}
	return out
}

// tcpReach prints open / refused / timeout for host:port. "refused" still proves the
// path carries packets both ways (the RST came back); only "timeout" means no path.
func tcpReach(host, port string) string {
	return fmt.Sprintf(`r=$(timeout 4 bash -c 'exec 3<>/dev/tcp/%s/%s' 2>&1); rc=$?
if [ $rc = 0 ]; then echo open; elif echo "$r" | grep -qi refused; then echo refused; else echo timeout; fi`, host, port)
}

// probePortOf is a port to test reachability through a tunnel: the first forwarded
// target port (a service usually listens there), else SSH.
func probePortOf(t *Tunnel) string {
	if ps := firstPorts(t.Ports, 1); len(ps) > 0 {
		d := ps[0].dst
		if i := strings.LastIndex(d, ":"); i >= 0 {
			d = d[i+1:]
		}
		return d
	}
	return "22"
}
