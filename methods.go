package main

import (
	"fmt"
	"os"
	"sort"
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
	fmt.Fprintf(&b, "[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=%s\n", u.Desc, typ)
	if u.RemainAfterExit {
		b.WriteString("RemainAfterExit=yes\n")
	}
	if u.ExecStartPre != "" {
		b.WriteString("ExecStartPre=" + u.ExecStartPre + "\n")
	}
	b.WriteString("ExecStart=" + u.ExecStart + "\n")
	if u.ExecStop != "" {
		b.WriteString("ExecStop=" + u.ExecStop + "\n")
	}
	if u.ExecStopPost != "" {
		b.WriteString("ExecStopPost=" + u.ExecStopPost + "\n")
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
	Build    func(c *buildCtx) (ir, kh SidePlan, err error) `json:"-"`
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
	c := &buildCtx{T: t, Srv: srv, Set: set, Opt: get, OptB: getB, D: d}
	return m.Build(c)
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

// sysctlBBR is a portable snippet enabling forwarding + BBR, idempotent.
const sysctlBBR = `
cat >/etc/sysctl.d/98-tunnel-panel.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
SYSCTL
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/98-tunnel-panel.conf >/dev/null 2>&1 || true
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
