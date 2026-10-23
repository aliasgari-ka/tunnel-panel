package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// FileSpec is a file to drop on a host before running the Up script.
type FileSpec struct {
	Content []byte
	Mode    os.FileMode
	// Asset, when set, names an embedded asset to upload instead of Content.
	Asset string
}

// Unit is the systemd service a method runs on one host. Every method gets exactly
// one unit per tunnel (named unitName(t)), so it survives reboots, is supervised,
// and status is a plain `systemctl is-active`.
type Unit struct {
	Desc            string
	Type            string // simple (default) | oneshot
	RemainAfterExit bool
	ExecStartPre    string
	ExecStart       string
	ExecStop        string
	ExecStopPost    string
	// ExtraPre/ExtraPost are more ExecStartPre=/ExecStopPost= lines (run after the
	// main ones), used for per-tunnel firewall openings that every method gets.
	ExtraPre  []string
	ExtraPost []string
}

// SidePlan is everything to do on one host for a method.
type SidePlan struct {
	Files     map[string]FileSpec
	Artifacts []Artifact // binaries fetched by the panel and uploaded to this host
	Setup     string     // one-time preparation (packages, certs) run before the unit starts
	Unit      Unit
}

func unitName(t *Tunnel) string { return "tp-" + t.ID + ".service" }

// tunnelDir holds the per-tunnel scripts and configs on each host.
func tunnelDir(t *Tunnel) string { return "/etc/tunnel-panel/t/" + t.ID }

func renderUnit(u Unit) string {
	typ := u.Type
	if typ == "" {
		typ = "simple"
	}
	var b strings.Builder
	// (no control characters: a newline in a name would add a line to the unit)
	desc := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, u.Desc)
	fmt.Fprintf(&b, "[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=%s\n", desc, typ)
	if u.RemainAfterExit {
		b.WriteString("RemainAfterExit=yes\n")
	}
	if u.ExecStartPre != "" {
		b.WriteString("ExecStartPre=" + u.ExecStartPre + "\n")
	}
	for _, x := range u.ExtraPre {
		b.WriteString("ExecStartPre=" + x + "\n")
	}
	b.WriteString("ExecStart=" + u.ExecStart + "\n")
	if u.ExecStop != "" {
		b.WriteString("ExecStop=" + u.ExecStop + "\n")
	}
	if u.ExecStopPost != "" {
		b.WriteString("ExecStopPost=" + u.ExecStopPost + "\n")
	}
	for _, x := range u.ExtraPost {
		b.WriteString("ExecStopPost=" + x + "\n")
	}
	if typ == "simple" {
		b.WriteString("Restart=always\nRestartSec=3\n")
	}
	b.WriteString("LimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

// scriptPair returns up/down shell scripts as files plus a oneshot unit running them.
func scriptPair(t *Tunnel, desc, up, down string) (map[string]FileSpec, Unit) {
	dir := tunnelDir(t)
	files := map[string]FileSpec{
		dir + "/up.sh":   {Content: []byte("#!/bin/bash\n" + up), Mode: 0o755},
		dir + "/down.sh": {Content: []byte("#!/bin/bash\n" + down), Mode: 0o755},
	}
	return files, Unit{Desc: desc, Type: "oneshot", RemainAfterExit: true,
		ExecStart: dir + "/up.sh", ExecStop: dir + "/down.sh"}
}

func mergeFiles(ms ...map[string]FileSpec) map[string]FileSpec {
	out := map[string]FileSpec{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// Field describes one configurable option shown in the UI.
type Field struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"` // text | number | bool | select | password
	Default string   `json:"default"`
	Help    string   `json:"help"`
	Options []string `json:"options,omitempty"`
}

// Method is one tunnelling technique.
type Method struct {
	ID       string                                         `json:"id"`
	Title    string                                         `json:"title"`
	Desc     string                                         `json:"desc"`
	Families []string                                       `json:"families"` // v4, v6
	Encrypt  string                                         `json:"encrypt"`  // short note shown as a badge
	Fields   []Field                                        `json:"fields"`
	Helper   string                                         `json:"helper,omitempty"` // embedded/uploaded binary "<helper>-<arch>" both hosts need
	Build    func(c *buildCtx) (ir, kh SidePlan, err error) `json:"-"`
	// Alts are other option sets (carriers) to try, in order, when the defaults pass no
	// traffic on a route — Iran's IPv4 filtering often drops UDP or hand-made packets that a
	// different carrier gets through. The benchmark finds the one that works; apply and hot
	// standby then use it (see routeOpts).
	Alts func(family string) []map[string]string `json:"-"`
}

// altLabel names an alternative option set for logs and titles ("carrier sni").
func altLabel(alt map[string]string) string {
	var parts []string
	for k, v := range alt {
		parts = append(parts, k+" "+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// buildCtx carries derived values into a method's Build function.
type buildCtx struct {
	T    *Tunnel
	Srv  *Server
	Set  Settings
	Opt  func(key string) string // resolved option (with defaults)
	OptB func(key string) bool
	D    derived
}

// derived holds per-tunnel addressing derived from Index so two tunnels never collide.
type derived struct {
	Idx      int
	V4Net    string // 10.10.IDX.0/30
	IRv4     string // 10.10.IDX.1
	KHv4     string // 10.10.IDX.2
	V6ULA    string // fd42:IDX::/64
	IRv6     string // fd42:IDX::1
	KHv6     string // fd42:IDX::2
	Iface    string // tp<idx>
	GREKey   int
	IfID     int    // xfrm if_id for ipsec
	BasePort int    // method base port (unique per tunnel)
	IRPub    string // Iran public address for the chosen family
	KHPub    string // foreign public address for the chosen family
}

// deriveFor computes addressing; fsrv is the foreign server (nil = this panel host).
func deriveFor(t *Tunnel, srv, fsrv *Server, set Settings) derived {
	i := t.Index
	d := derived{
		Idx:      i,
		V4Net:    fmt.Sprintf("10.10.%d.0/30", i),
		IRv4:     fmt.Sprintf("10.10.%d.1", i),
		KHv4:     fmt.Sprintf("10.10.%d.2", i),
		V6ULA:    fmt.Sprintf("fd42:%x::/64", i),
		IRv6:     fmt.Sprintf("fd42:%x::1", i),
		KHv6:     fmt.Sprintf("fd42:%x::2", i),
		Iface:    fmt.Sprintf("tp%d", i),
		GREKey:   1000 + i,
		IfID:     42000 + i,
		BasePort: 40000 + i*4,
	}
	kh4, kh6 := set.LocalIPv4, set.LocalIPv6
	if fsrv != nil {
		kh4, kh6 = fsrv.IPv4, fsrv.IPv6
	}
	if t.Family == "v6" {
		d.IRPub, d.KHPub = srv.IPv6, kh6
	} else {
		d.IRPub, d.KHPub = srv.IPv4, kh4
	}
	return d
}

var methods []*Method
var methodByID = map[string]*Method{}

func register(m *Method) {
	methods = append(methods, m)
	methodByID[m.ID] = m
}

func methodField(m *Method, key string) *Field {
	for i := range m.Fields {
		if m.Fields[i].Key == key {
			return &m.Fields[i]
		}
	}
	return nil
}

// resolveOptions returns a getter that falls back to field defaults.
func resolveOptions(m *Method, saved map[string]string) (func(string) string, func(string) bool) {
	get := func(key string) string {
		if saved != nil {
			if v, ok := saved[key]; ok && v != "" {
				return v
			}
		}
		if f := methodField(m, key); f != nil {
			return f.Default
		}
		return ""
	}
	getB := func(key string) bool {
		v := strings.ToLower(get(key))
		return v == "1" || v == "true" || v == "on" || v == "yes"
	}
	return get, getB
}

func buildPlans(m *Method, t *Tunnel, srv, fsrv *Server, set Settings) (SidePlan, SidePlan, error) {
	return buildPlansRedirect(m, t, srv, fsrv, set, nil)
}

// buildPlansRedirect: redir maps users' ports on Iran that another program holds to the
// internal port the forwarder listens on instead (an iptables REDIRECT sends the outside
// traffic there; see freeIranPorts).
func buildPlansRedirect(m *Method, t *Tunnel, srv, fsrv *Server, set Settings, redir map[int]int) (SidePlan, SidePlan, error) {
	get, getB := resolveOptions(m, t.Options[m.ID])
	d := deriveFor(t, srv, fsrv, set)
	if d.IRPub == "" || d.KHPub == "" {
		which := "Iran"
		if d.KHPub == "" {
			which = "foreign"
		}
		return SidePlan{}, SidePlan{}, fmt.Errorf("the %s server has no public %s address set", which, map[string]string{"v4": "IPv4", "v6": "IPv6"}[t.Family])
	}
	if !supportsFamily(m, t.Family) {
		return SidePlan{}, SidePlan{}, fmt.Errorf("%s does not support %s", m.Title, t.Family)
	}
	// port forwarders also map the speed-test port to the foreign side (see SpeedTest);
	// the copy shares Secrets with t, so secrets created while building are kept
	if t.Secrets == nil {
		t.Secrets = map[string]string{}
	}
	tc := *t
	tc.Ports = withProbePort(m, t)
	var redirUp, redirDown strings.Builder
	var redirPorts []string
	if len(redir) > 0 {
		var specs []string
		for _, p := range splitPorts(tc.Ports) {
			if n, err := strconv.Atoi(p.listen); err == nil && redir[n] > 0 {
				q := redir[n]
				specs = append(specs, fmt.Sprintf("%d=%s", q, p.dst))
				redirPorts = append(redirPorts, strconv.Itoa(q))
				for _, proto := range []string{"tcp", "udp"} {
					rule := fmt.Sprintf("PREROUTING -p %s --dport %d -m addrtype --dst-type LOCAL -m comment --comment tpr-%s -j REDIRECT --to-ports %d", proto, n, t.ID, q)
					fmt.Fprintf(&redirUp, "iptables -w -t nat -C %[1]s 2>/dev/null || iptables -w -t nat -I %[1]s\n", rule)
					fmt.Fprintf(&redirDown, "while iptables -w -t nat -D %s 2>/dev/null; do :; done\n", rule)
				}
				continue
			}
			if p.dst == p.listen {
				specs = append(specs, p.listen)
			} else {
				specs = append(specs, p.listen+"="+p.dst)
			}
		}
		tc.Ports = strings.Join(specs, ",")
	}
	c := &buildCtx{T: &tc, Srv: srv, Set: set, Opt: get, OptB: getB, D: d}
	ir, kh, err := m.Build(c)
	if err != nil {
		return ir, kh, err
	}
	if redirUp.Len() > 0 {
		dir := tunnelDir(t)
		if ir.Files == nil {
			ir.Files = map[string]FileSpec{}
		}
		ir.Files[dir+"/redir-up.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + redirUp.String() + "exit 0\n"), Mode: 0o755}
		ir.Files[dir+"/redir-down.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + redirDown.String() + "exit 0\n"), Mode: 0o755}
		ir.Unit.ExtraPre = append(ir.Unit.ExtraPre, "-"+dir+"/redir-up.sh")
		ir.Unit.ExtraPost = append(ir.Unit.ExtraPost, "-"+dir+"/redir-down.sh")
	}
	ifc := l3Iface(m, t)
	// the side that listens for the other's tunnel connection also opens that port to
	// everyone (the token/handshake guards it): the dialer may leave from an address other
	// than the one saved for it (several IPs, NAT), and the peer-only rule would drop it
	irL, khL := tunnelListenPort(m, t, get, d)
	// users still arrive on the original ports (INPUT sees the redirected one too)
	irPorts, khPorts := strings.TrimPrefix(withProbePort(m, t)+","+strings.Join(redirPorts, ","), ","), khL
	if len(redirPorts) == 0 {
		irPorts = tc.Ports
	}
	if irL != "" {
		irPorts = strings.TrimPrefix(irPorts+","+irL, ",")
	}
	addInbound(&ir, t, d.KHPub, irPorts, ifc)
	addInbound(&kh, t, d.IRPub, khPorts, ifc)
	return ir, kh, nil
}

// tunnelListenPort is the port each side listens on for the tunnel itself ("" = none).
func tunnelListenPort(m *Method, t *Tunnel, get func(string) string, d derived) (ir, kh string) {
	switch m.ID {
	case "backhaul", "bp_reverse", "premium1":
		return portOr(get("tunnel_port"), d.BasePort), ""
	case "frp":
		return portOr(get("bind_port"), d.BasePort), ""
	case "premium":
		if get("mode") != "ipx" {
			return portOr(get("port"), d.BasePort), ""
		}
	case "bp_l3":
		p := portOr(get("port"), d.BasePort)
		if get("dialer") == "foreign" {
			return p, ""
		}
		return "", p
	}
	return "", ""
}

// l3Iface is the interface an L3 method's packets cross ("" for port forwarders).
func l3Iface(m *Method, t *Tunnel) string {
	if !benchIsL3(m, t.Options[m.ID]) {
		return ""
	}
	if m.ID == "premium" {
		return fmt.Sprintf("bhp%d", t.Index)
	}
	return fmt.Sprintf("tp%d", t.Index)
}

// addInbound opens the host firewall for this tunnel: everything from the peer server
// (carrier/tunnel ports, GRE, ESP, raw ipx — whatever the method speaks), the forwarded
// ports users connect to (Iran), and the tunnel interface (L3). Rules live in a
// per-tunnel chain TPI_<id> inserted at the top of INPUT, so a DROP policy or ufw can't
// block the tunnel; firewalld gets runtime rules. Re-added on every unit start (so they
// survive reboots) and removed on stop.
func addInbound(p *SidePlan, t *Tunnel, peer, ports, iface string) {
	up, down := inboundRules(t, peer, ports, iface)
	if p.Files == nil {
		p.Files = map[string]FileSpec{}
	}
	dir := tunnelDir(t)
	p.Files[dir+"/fw-in-up.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + up), Mode: 0o755}
	p.Files[dir+"/fw-in-down.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + down), Mode: 0o755}
	p.Unit.ExtraPre = append(p.Unit.ExtraPre, "-"+dir+"/fw-in-up.sh")
	p.Unit.ExtraPost = append(p.Unit.ExtraPost, "-"+dir+"/fw-in-down.sh")
}

func inboundChain(t *Tunnel) string { return "TPI_" + t.ID }

func inboundRules(t *Tunnel, peer, ports, iface string) (up, down string) {
	ch := inboundChain(t)
	peerIpt, fam := "iptables", "ipv4"
	if strings.Contains(peer, ":") {
		peerIpt, fam = "ip6tables", "ipv6"
	}
	var b, fw strings.Builder
	// the chain exists in both families: the peer arrives over the underlay family, but
	// users reach the forwarded ports over IPv4 or IPv6 regardless of the underlay
	for _, ipt := range []string{"iptables", "ip6tables"} {
		fmt.Fprintf(&b, "if command -v %[1]s >/dev/null 2>&1; then\n%[1]s -w -N %[2]s 2>/dev/null || %[1]s -w -F %[2]s\n", ipt, ch)
		if peer != "" && ipt == peerIpt {
			fmt.Fprintf(&b, "%s -w -A %s -s %s -j ACCEPT\n", ipt, ch, peer)
		}
		for _, p := range splitPorts(ports) {
			port := p.listen
			if i := strings.LastIndex(port, ":"); i >= 0 && !strings.Contains(port, "-") {
				port = port[i+1:] // "127.0.0.1:443" style binds
			}
			if _, err := strconv.Atoi(strings.SplitN(port, "-", 2)[0]); err != nil {
				continue
			}
			for _, proto := range []string{"tcp", "udp"} {
				fmt.Fprintf(&b, "%s -w -A %s -p %s --dport %s -j ACCEPT\n", ipt, ch, proto, strings.ReplaceAll(port, "-", ":"))
				if ipt == "iptables" {
					fmt.Fprintf(&fw, "firewall-cmd -q --add-port=%s/%s 2>/dev/null\n", port, proto)
				}
			}
		}
		fmt.Fprintf(&b, "%[1]s -w -C INPUT -j %[2]s 2>/dev/null || %[1]s -w -I INPUT -j %[2]s\nfi\n", ipt, ch)
	}
	if peer != "" {
		fmt.Fprintf(&fw, "firewall-cmd -q --add-rich-rule='rule family=%s source address=%s accept' 2>/dev/null\n", fam, peer)
	}
	if iface != "" {
		// the inner traffic is IPv4 (10.10.N.x) and fd42:N::/64, whatever the outer family is
		fmt.Fprintf(&b, "iptables -w -C INPUT -i %[1]s -j ACCEPT 2>/dev/null || iptables -w -I INPUT -i %[1]s -j ACCEPT\n", iface)
		fmt.Fprintf(&b, "ip6tables -w -C INPUT -i %[1]s -j ACCEPT 2>/dev/null || ip6tables -w -I INPUT -i %[1]s -j ACCEPT 2>/dev/null\n", iface)
		fmt.Fprintf(&fw, "firewall-cmd -q --zone=trusted --add-interface=%s 2>/dev/null\n", iface)
	}
	if fw.Len() > 0 {
		b.WriteString("if firewall-cmd --state >/dev/null 2>&1; then\n" + fw.String() + "fi\n")
	}
	b.WriteString("exit 0\n")

	var d strings.Builder
	for _, ipt := range []string{"iptables", "ip6tables"} {
		fmt.Fprintf(&d, "while %[1]s -w -D INPUT -j %[2]s 2>/dev/null; do :; done\n%[1]s -w -F %[2]s 2>/dev/null; %[1]s -w -X %[2]s 2>/dev/null\n", ipt, ch)
		if iface != "" {
			fmt.Fprintf(&d, "%s -w -D INPUT -i %s -j ACCEPT 2>/dev/null\n", ipt, iface)
		}
	}
	if fw.Len() > 0 {
		d.WriteString("if firewall-cmd --state >/dev/null 2>&1; then\n" + strings.ReplaceAll(fw.String(), "--add-", "--remove-") + "fi\n")
	}
	d.WriteString("exit 0\n")
	return b.String(), d.String()
}

func supportsFamily(m *Method, fam string) bool {
	for _, f := range m.Families {
		if f == fam {
			return true
		}
	}
	return false
}

func methodsForFamily(fam string) []*Method {
	var out []*Method
	for _, m := range methods {
		for _, f := range m.Families {
			if f == fam {
				out = append(out, m)
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

// common helpers used by method scripts -------------------------------------

// sysctlBBR is a portable snippet enabling IPv4 forwarding + BBR, idempotent. The tunnels
// carry IPv4 inside, so IPv6 forwarding stays as the server had it (see ipv6RAFix).
const sysctlBBR = `
cat >/etc/sysctl.d/98-tunnel-panel.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
SYSCTL
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/98-tunnel-panel.conf >/dev/null 2>&1 || true
` + ipv6RAFix

// ipv6RAFix repairs what earlier versions did: they turned IPv6 forwarding on, and with
// forwarding on Linux ignores router advertisements, so a server that learns its IPv6
// default route from them lost IPv6 once that route expired. The setting is dropped from
// the panel's files; while forwarding is still on (until a reboot, or because something
// else wants it), accept_ra=2 keeps the interfaces taking RAs anyway.
const ipv6RAFix = `if [ -f /etc/sysctl.d/99-tunnel-panel-optz.conf ]; then sed -i '/^net\.ipv6\.conf\.all\.forwarding=1$/d' /etc/sysctl.d/99-tunnel-panel-optz.conf 2>/dev/null || true; fi
if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" = 1 ]; then
  for f in /proc/sys/net/ipv6/conf/*/accept_ra; do
    i=${f%/accept_ra}; i=${i##*/}
    case $i in all|default|lo) continue;; esac
    if [ "$(cat "$f" 2>/dev/null)" = 1 ]; then echo 2 > "$f" 2>/dev/null || true; fi
  done
fi
`

// portForwardV4 builds iptables rules on the Iran side that DNAT public ports to the
// foreign tunnel address. Every rule lives in per-tunnel chains (TP_<tag>, TP_<tag>_P,
// TPF_<tag>, TPM_<tag>) so teardown removes exactly what was added and nothing else.
// ports spec: "443,8080=80,2000-2010".
func portForwardV4(ports, targetIP, iface, tag string) string {
	var b strings.Builder
	nat, post, fwd, mss := "TP_"+tag, "TP_"+tag+"_P", "TPF_"+tag, "TPM_"+tag
	fmt.Fprintf(&b, "iptables -t nat -N %[1]s 2>/dev/null || iptables -t nat -F %[1]s\n", nat)
	fmt.Fprintf(&b, "iptables -t nat -N %[1]s 2>/dev/null || iptables -t nat -F %[1]s\n", post)
	fmt.Fprintf(&b, "iptables -N %[1]s 2>/dev/null || iptables -F %[1]s\n", fwd)
	fmt.Fprintf(&b, "iptables -t mangle -N %[1]s 2>/dev/null || iptables -t mangle -F %[1]s\n", mss)
	for _, spec := range splitPorts(ports) {
		dport := strings.ReplaceAll(spec.listen, "-", ":")
		dst := targetIP
		if spec.dst != spec.listen {
			dst = targetIP + ":" + spec.dst
		}
		fmt.Fprintf(&b, "for proto in tcp udp; do iptables -t nat -A %s -m addrtype --dst-type LOCAL -p $proto --dport %s -j DNAT --to-destination %s; done\n", nat, dport, dst)
	}
	fmt.Fprintf(&b, "iptables -t nat -A %s -o %s -j MASQUERADE\n", post, iface)
	fmt.Fprintf(&b, "iptables -A %s -o %s -j ACCEPT\niptables -A %s -i %s -j ACCEPT\n", fwd, iface, fwd, iface)
	fmt.Fprintf(&b, "iptables -t mangle -A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", mss, iface)
	// hooks (idempotent)
	fmt.Fprintf(&b, "iptables -t nat -C PREROUTING -j %[1]s 2>/dev/null || iptables -t nat -A PREROUTING -j %[1]s\n", nat)
	fmt.Fprintf(&b, "iptables -t nat -C POSTROUTING -j %[1]s 2>/dev/null || iptables -t nat -A POSTROUTING -j %[1]s\n", post)
	fmt.Fprintf(&b, "iptables -C FORWARD -j %[1]s 2>/dev/null || iptables -I FORWARD -j %[1]s\n", fwd)
	fmt.Fprintf(&b, "iptables -t mangle -C FORWARD -j %[1]s 2>/dev/null || iptables -t mangle -A FORWARD -j %[1]s\n", mss)
	return b.String()
}

// tunFwdRules accepts forwarded traffic on a daemon-made TUN and clamps the TCP MSS to
// its MTU, in per-tunnel chains (the interface may not exist yet; iptables matches by name).
func tunFwdRules(iface, tag string) (up, down string) {
	fwd, mss := "TPF_"+tag, "TPM_"+tag
	up = fmt.Sprintf(`iptables -w -N %[1]s 2>/dev/null || iptables -w -F %[1]s
iptables -w -A %[1]s -o %[3]s -j ACCEPT
iptables -w -A %[1]s -i %[3]s -j ACCEPT
iptables -w -C FORWARD -j %[1]s 2>/dev/null || iptables -w -I FORWARD -j %[1]s
iptables -w -t mangle -N %[2]s 2>/dev/null || iptables -w -t mangle -F %[2]s
iptables -w -t mangle -A %[2]s -o %[3]s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -w -t mangle -A %[2]s -i %[3]s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -w -t mangle -C FORWARD -j %[2]s 2>/dev/null || iptables -w -t mangle -I FORWARD -j %[2]s
iptables -w -t mangle -C OUTPUT -o %[3]s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -w -t mangle -A OUTPUT -o %[3]s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
exit 0
`, fwd, mss, iface)
	down = fmt.Sprintf(`iptables -w -D FORWARD -j %[1]s 2>/dev/null; iptables -w -F %[1]s 2>/dev/null; iptables -w -X %[1]s 2>/dev/null
iptables -w -t mangle -D FORWARD -j %[2]s 2>/dev/null; iptables -w -t mangle -F %[2]s 2>/dev/null; iptables -w -t mangle -X %[2]s 2>/dev/null
iptables -w -t mangle -D OUTPUT -o %[3]s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
exit 0
`, fwd, mss, iface)
	return up, down
}

func portForwardDownV4(tag string) string {
	nat, post, fwd, mss := "TP_"+tag, "TP_"+tag+"_P", "TPF_"+tag, "TPM_"+tag
	return fmt.Sprintf(`iptables -t nat -D PREROUTING -j %[1]s 2>/dev/null; iptables -t nat -F %[1]s 2>/dev/null; iptables -t nat -X %[1]s 2>/dev/null
iptables -t nat -D POSTROUTING -j %[2]s 2>/dev/null; iptables -t nat -F %[2]s 2>/dev/null; iptables -t nat -X %[2]s 2>/dev/null
iptables -D FORWARD -j %[3]s 2>/dev/null; iptables -F %[3]s 2>/dev/null; iptables -X %[3]s 2>/dev/null
iptables -t mangle -D FORWARD -j %[4]s 2>/dev/null; iptables -t mangle -F %[4]s 2>/dev/null; iptables -t mangle -X %[4]s 2>/dev/null
true
`, nat, post, fwd, mss)
}

type portSpec struct{ listen, dst string }

func splitPorts(ports string) []portSpec {
	var out []portSpec
	for _, raw := range strings.Split(ports, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if i := strings.Index(raw, "="); i >= 0 {
			out = append(out, portSpec{listen: strings.TrimSpace(raw[:i]), dst: strings.TrimSpace(raw[i+1:])})
		} else {
			out = append(out, portSpec{listen: raw, dst: raw})
		}
	}
	return out
}

// firstPort returns the first listen port for use as a tunnel service port fallback.
func firstPort(ports string) string {
	ps := splitPorts(ports)
	if len(ps) == 0 {
		return "443"
	}
	p := ps[0].listen
	if i := strings.IndexAny(p, "-:"); i >= 0 {
		p = p[:i]
	}
	return p
}

// bracket wraps an IPv6 literal in [] for host:port usage.
func bracket(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// portOr returns v, or a per-tunnel unique port derived from base when v is blank.
func portOr(v string, base int) string {
	if v != "" {
		return v
	}
	return fmt.Sprintf("%d", base)
}
