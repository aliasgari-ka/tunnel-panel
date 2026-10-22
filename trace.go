package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Trace watches a running tunnel while the user connects a client (e.g. Xray) and says
// where the connection stops: does the client reach Iran's forwarded port, does anything
// arrive at the service on the foreign server, and does the service answer or drop it.
// It counts with temporary mangle-table rules (no target, they only count), samples every
// 3 s, then reads the service's own log (xray / x-ui / marzban / sing-box, journal, files
// or docker) for the rejection reason.

const traceTag = "tp-trace"

// traceRules adds or removes the counting rules: SYNs and bytes towards the port, and
// (foreign only) bytes the service sends back.
func traceRules(add bool, ports []string, replies bool) string {
	op := "-D"
	if add {
		op = "-I"
	}
	var b strings.Builder
	for _, ipt := range []string{"iptables", "ip6tables"} {
		fmt.Fprintf(&b, "if command -v %s >/dev/null 2>&1; then\n", ipt)
		for _, p := range ports {
			for _, r := range []string{
				fmt.Sprintf("PREROUTING -p tcp --dport %s --syn -m comment --comment %s-syn-%s", p, traceTag, p),
				fmt.Sprintf("PREROUTING -p tcp --dport %s -m comment --comment %s-in-%s", p, traceTag, p),
				fmt.Sprintf("PREROUTING -p udp --dport %s -m comment --comment %s-udp-%s", p, traceTag, p),
			} {
				if add {
					fmt.Fprintf(&b, "%s -w -t mangle %s %s 2>/dev/null\n", ipt, op, r)
				} else {
					fmt.Fprintf(&b, "while %s -w -t mangle %s %s 2>/dev/null; do :; done\n", ipt, op, r)
				}
			}
			if replies {
				r := fmt.Sprintf("OUTPUT -p tcp --sport %s -m comment --comment %s-out-%s", p, traceTag, p)
				if add {
					fmt.Fprintf(&b, "%s -w -t mangle %s %s 2>/dev/null\n", ipt, op, r)
				} else {
					fmt.Fprintf(&b, "while %s -w -t mangle %s %s 2>/dev/null; do :; done\n", ipt, op, r)
				}
			}
		}
		b.WriteString("fi\n")
	}
	b.WriteString("true\n")
	return b.String()
}

// traceRead prints "<kind> <port> <pkts> <bytes>" summed over both families.
const traceRead = `{ iptables -w -t mangle -nvxL 2>/dev/null; ip6tables -w -t mangle -nvxL 2>/dev/null; } |
awk '/tp-trace-/ { for (i=1;i<=NF;i++) if ($i ~ /^tp-trace-/) { split($i,a,"-"); k=a[3]" "a[4]; p[k]+=$1; by[k]+=$2 } }
     END { for (k in p) print k, p[k], by[k] }'`

type traceCount struct{ syn, inB, udp, outB int64 }

func parseTrace(out string) map[string]*traceCount {
	m := map[string]*traceCount{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 4 {
			continue
		}
		pk, _ := strconv.ParseInt(f[2], 10, 64)
		by, _ := strconv.ParseInt(f[3], 10, 64)
		c := m[f[1]]
		if c == nil {
			c = &traceCount{}
			m[f[1]] = c
		}
		switch f[0] {
		case "syn":
			c.syn += pk
		case "in":
			c.inB += by
		case "udp":
			c.udp += pk
		case "out":
			c.outB += by
		}
	}
	return m
}

// serviceLogScript finds where the proxy on the foreign server logs and prints recent
// interesting lines (since epoch).
func serviceLogScript(since int64, port string) string {
	return fmt.Sprintf(`pat='reject|invalid|fail|error|REALITY|tls|timeout|refused|proxy protocol|not found|denied|:%[2]s'
found=0
for u in xray x-ui 3x-ui marzban sing-box hiddify-xray v2ray s-ui; do
  if systemctl is-active --quiet $u 2>/dev/null; then
    found=1; echo "== journal of $u"; journalctl -u $u --since @%[1]d --no-pager -o cat 2>/dev/null | grep -iE "$pat" | tail -12
  fi
done
for f in /var/log/xray/error.log /var/log/xray/access.log /usr/local/x-ui/error.log /usr/local/x-ui/access.log /usr/local/x-ui/bin/access.log /var/lib/marzban/xray-error.log /var/log/sing-box.log; do
  if [ -f "$f" ] && [ $(( $(date +%%s) - $(stat -c %%Y "$f") )) -lt 300 ]; then
    found=1; echo "== $f"; tail -n 300 "$f" | grep -iE "$pat" | tail -12
  fi
done
if command -v docker >/dev/null 2>&1; then
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'xray|marzban|x-ui|3x-ui|hiddify|sing|v2ray'); do
    found=1; echo "== docker logs $c"; docker logs --since %[3]ds "$c" 2>&1 | grep -iE "$pat" | tail -12
  done
fi
[ $found = 1 ] || echo "== no xray/x-ui/marzban/sing-box log found"
`, since, port, time.Now().Unix()-since+5)
}

// Trace runs for secs seconds; connect your client during that window.
func (a *App) Trace(t *Tunnel, secs int) (*Job, error) {
	if t.Active == "" {
		return nil, fmt.Errorf("start the tunnel first")
	}
	m := methodByID[t.Active]
	if m == nil {
		return nil, fmt.Errorf("unknown method")
	}
	if secs < 10 || secs > 180 {
		secs = 30
	}
	j, err := a.jobs.start(t.ID, "trace")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(time.Duration(secs+120) * time.Second)
		defer cancel()
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
		ps := firstPorts(t.Ports, 3)
		var irPorts, khPorts []string
		for _, p := range ps {
			irPorts = append(irPorts, p.listen)
			dst := p.dst
			if i := strings.LastIndex(dst, ":"); i >= 0 {
				dst = dst[i+1:]
			}
			khPorts = append(khPorts, dst)
		}
		run := func(h Host, s string) string { out, _ := h.Run(ctx, s, nil); return strings.TrimSpace(out) }

		// who serves the port on the foreign side?
		for _, p := range khPorts {
			owner := run(kh, "ss -Hltnp 'sport = :"+p+"' 2>/dev/null | grep -o 'users:((\"[^\"]*' | head -1 | sed 's/users:((\"//'")
			bind := run(kh, "ss -Hltn 'sport = :"+p+"' 2>/dev/null | awk '{print $4}' | sort -u | tr '\\n' ' '")
			if bind == "" {
				j.log("✕ nothing listens on foreign port %s — start your xray inbound on that port first", p)
			} else {
				j.log("foreign port %s is served by %s (listening on %s)", p, orStr(owner, "a process"), strings.TrimSpace(bind))
			}
		}
		via := "127.0.0.1 (the tunnel's forwarder)"
		if l3 {
			via = d.IRv4 + " (the Iran end of the tunnel)"
		}
		j.log("tracing for %ds — connect your client to %s:%s now", secs, d.IRPub, strings.Join(irPorts, ","))
		if srv.IPv4 != "" && d.IRPub != srv.IPv4 {
			j.log("(clients normally use the Iran IPv4 %s)", srv.IPv4)
		}

		start := time.Now().Unix()
		_, _ = ir.Run(ctx, traceRules(true, irPorts, false), nil)
		_, _ = kh.Run(ctx, traceRules(true, khPorts, true), nil)
		defer func() {
			cctx, c2 := context.WithTimeout(context.Background(), 30*time.Second)
			defer c2()
			_, _ = ir.Run(cctx, traceRules(false, irPorts, false), nil)
			_, _ = kh.Run(cctx, traceRules(false, khPorts, true), nil)
		}()

		var irT, khT *traceCount
		sum := func(mm map[string]*traceCount) *traceCount {
			s := &traceCount{}
			for _, c := range mm {
				s.syn += c.syn
				s.inB += c.inB
				s.udp += c.udp
				s.outB += c.outB
			}
			return s
		}
		deadline := time.Now().Add(time.Duration(secs) * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			time.Sleep(3 * time.Second)
			irT = sum(parseTrace(run(ir, traceRead)))
			khT = sum(parseTrace(run(kh, traceRead)))
			j.log("  clients → Iran: %d TCP conn%s, %s in%s   |   arriving at the foreign service: %d conn%s, %s in, %s answered",
				irT.syn, plural(irT.syn), fmtBytes(uint64(irT.inB)), udpNote(irT.udp),
				khT.syn, plural(khT.syn), fmtBytes(uint64(khT.inB)), fmtBytes(uint64(khT.outB)))
		}
		if irT == nil || khT == nil {
			j.finish("cancelled")
			return
		}

		j.log("── result ──")
		switch {
		case irT.syn == 0 && irT.udp == 0:
			j.log("✕ No client reached Iran %s:%s during the trace.", d.IRPub, strings.Join(irPorts, ","))
			j.log("    → check the client's address (the Iran server's IP) and port; if they are right, the client's network/ISP or Iran's datacenter blocks it")
		case khT.syn == 0 && khT.udp == 0:
			j.log("✕ Clients reach Iran (%d connections) but nothing arrives at the foreign service — the tunnel is not forwarding them.", irT.syn)
			j.log("    → run Diagnose on this tunnel")
		case khT.outB < 1500*max64(khT.syn, 1):
			j.log("✕ Connections arrive at the foreign service (%d) but it answers almost nothing (%s) — the service rejects the client.", khT.syn, fmtBytes(uint64(khT.outB)))
			j.log("    → the client config must match the inbound exactly: UUID/password, transport (tcp/ws/grpc) and path, TLS/REALITY public key, shortId and SNI")
			j.log("    → through this tunnel the service sees clients coming from %s; if the inbound expects PROXY protocol (acceptProxyProtocol / xver) or allows only certain source IPs, change that", via)
		default:
			j.log("✓ The service accepts connections and answers (%s sent back) — the tunnel and the inbound work.", fmtBytes(uint64(khT.outB)))
			j.log("    → if the client still fails after connecting, look at the service's outbound/routing (can the foreign server reach the internet?) or the client's DNS settings")
		}
		j.log("── service log (since the trace started) ──")
		for _, l := range strings.Split(run(kh, serviceLogScript(start, khPorts[0])), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				if len(l) > 220 {
					l = l[:220] + "…"
				}
				j.log("  %s", l)
			}
		}
		j.log("  (Xray logs rejections like \"invalid request user id\" or \"REALITY: processed invalid connection\" at loglevel info/debug — raise it temporarily if nothing shows)")
		j.log("DONE — trace finished")
		j.finish("ok")
	}()
	return j, nil
}

func plural(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func udpNote(n int64) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d UDP pkts", n)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
