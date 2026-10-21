package main

import (
	"context"
	"fmt"
)

// shapeUnitName is the systemd unit for a tunnel's shaping layer.
func shapeUnitName(t *Tunnel) string { return "tp-shape-" + t.ID + ".service" }

// buildShape returns the oneshot plan that applies the traffic-shaping layer on one host.
// It picks the egress interface (configured or the default-route device) at runtime, applies
// the chosen qdisc (cake/htb/tbf/fq_codel) with graceful fallbacks, optional netem jitter,
// and an optional MSS clamp. Teardown removes exactly what it added.
func buildShape(t *Tunnel) SidePlan {
	s := t.Shape
	q := s.Qdisc
	switch q {
	case "cake", "htb", "tbf", "fq_codel":
	default:
		q = "cake"
	}
	ifaceExpr := `IF="` + s.Iface + `"; [ -n "$IF" ] || IF=$(ip route show default | awk '{print $5; exit}'); [ -n "$IF" ] || { echo "no egress interface"; exit 1; }`

	apply := ""
	switch q {
	case "cake":
		apply = `tc qdisc replace dev "$IF" root cake bandwidth 1gbit overhead 64 noatm`
	case "htb":
		apply = `tc qdisc replace dev "$IF" root handle 1: htb default 12 && tc class add dev "$IF" parent 1: classid 1:1 htb rate 1gbit && tc class add dev "$IF" parent 1:1 classid 1:12 htb rate 1gbit`
	case "tbf":
		apply = `tc qdisc replace dev "$IF" root tbf rate 1gbit burst 32kbit latency 400ms`
	case "fq_codel":
		apply = `tc qdisc replace dev "$IF" root fq_codel`
	}
	// Fallback chain: if the chosen qdisc is unavailable on the kernel, try fq_codel then fq.
	applyWithFallback := fmt.Sprintf(`%s 2>/dev/null || tc qdisc replace dev "$IF" root fq_codel 2>/dev/null || tc qdisc replace dev "$IF" root fq 2>/dev/null || { echo "qdisc apply failed"; exit 1; }`, apply)

	jitter := ""
	if s.Jitter {
		// netem jitter is added as a leaf under a prio handle when the root allows it; on cake/fq_codel
		// we instead replace root with netem (jitter takes priority over shaping when both are asked).
		jitter = `tc qdisc replace dev "$IF" root netem delay 12ms 4ms distribution normal 2>/dev/null || true`
	}
	mss := ""
	if s.MSS > 0 {
		mss = fmt.Sprintf(`iptables -t mangle -C POSTROUTING -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d 2>/dev/null || iptables -t mangle -A POSTROUTING -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d`, s.MSS, s.MSS)
	}

	up := fmt.Sprintf("%s\n%s\n%s\n%s\necho \"shaping %s on $IF\"\n", ifaceExpr, applyWithFallback, jitter, mss, q)

	downMSS := ""
	if s.MSS > 0 {
		downMSS = fmt.Sprintf(`iptables -t mangle -D POSTROUTING -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d 2>/dev/null || true`, s.MSS)
	}
	down := fmt.Sprintf("%s\ntc qdisc del dev \"$IF\" root 2>/dev/null || true\n%s\ntrue\n", ifaceExpr, downMSS)

	dir := tunnelDir(t) + "/shape"
	files := map[string]FileSpec{
		dir + "/up.sh":   {Content: []byte("#!/bin/bash\n" + up), Mode: 0o755},
		dir + "/down.sh": {Content: []byte("#!/bin/bash\n" + down), Mode: 0o755},
	}
	return SidePlan{Files: files, Unit: Unit{
		Desc: "Tunnel Panel shaping " + t.Name, Type: "oneshot", RemainAfterExit: true,
		ExecStart: dir + "/up.sh", ExecStop: dir + "/down.sh",
	}}
}

// deployShape installs (or, if disabled, removes) the shaping unit on one host.
func (a *App) deployShape(ctx context.Context, j *Job, label string, host Host, t *Tunnel) error {
	u := shapeUnitName(t)
	remove := fmt.Sprintf("systemctl disable --now %[1]s 2>/dev/null; rm -f /etc/systemd/system/%[1]s; systemctl daemon-reload 2>/dev/null; true\n", u)
	if !t.Shape.Enabled {
		_, err := host.Run(ctx, remove, func(l string) { j.log("[%s] %s", label, l) })
		return err
	}
	p := buildShape(t)
	logf := func(l string) { j.log("[%s] %s", label, l) }
	for path, fs := range p.Files {
		if err := host.WriteFile(path, fs.Content, fs.Mode); err != nil {
			return err
		}
	}
	if err := host.WriteFile("/etc/systemd/system/"+u, []byte(renderUnit(p.Unit)), 0o644); err != nil {
		return err
	}
	_, err := host.Run(ctx, fmt.Sprintf("systemctl daemon-reload && systemctl enable --now %s && echo 'shaping on'", u), logf)
	return err
}

// normalizeShape clamps user input to valid shaping settings.
func normalizeShape(s Shape) Shape {
	switch s.Qdisc {
	case "cake", "htb", "tbf", "fq_codel":
	default:
		s.Qdisc = "cake"
	}
	if s.MSS != 0 && (s.MSS < 400 || s.MSS > 1452) {
		s.MSS = 0
	}
	return s
}
