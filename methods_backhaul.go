package main

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	register(methodBackhaul)
	register(methodPremiumV1)
	register(methodFRP)
}

var methodBackhaul = &Method{
	ID:       "backhaul",
	Title:    "Backhaul (reverse)",
	Desc:     "Open-source Musixal/Backhaul reverse tunnel. Iran listens, foreign dials in. Good all-rounder.",
	Families: []string{"v4", "v6"},
	Encrypt:  "token / wss",
	Fields: []Field{
		{Key: "transport", Label: "Transport", Type: "select", Default: "tcpmux",
			Options: []string{"tcp", "tcpmux", "ws", "wss", "wsmux", "wssmux", "udp"}},
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "", Help: "control/data port on Iran (blank = auto, unique per tunnel)"},
		{Key: "mux_con", Label: "Mux concurrency", Type: "number", Default: "8"},
		{Key: "nodelay", Label: "TCP nodelay", Type: "bool", Default: "true"},
		{Key: "sniffer", Label: "Traffic sniffer", Type: "bool", Default: "false"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		return backhaulPlans(c, "/opt/backhaul/backhaul", artBackhaul(c.Set), "Backhaul", "/opt/backhaul")
	},
}

// Backhaul Premium v1.0.2: the vendor's only arm64 build. Same config format as open
// Backhaul, but it doesn't talk to the v2 core, so it runs on both ends: natively on arm64,
// and the same static binary under qemu-aarch64 on amd64 (see v1Emulated).
var methodPremiumV1 = &Method{
	ID:       "premium1",
	Title:    "Backhaul Premium v1 (legacy)",
	Desc:     "Backhaul Premium v1.0.2 — the vendor's arm64 build (shipped with the panel, WTFPL). Native on arm64, emulated on amd64; both servers run v1 (it can't talk to the v2 core). tcp/tcpmux/ws/wss/wsmux/wssmux/udp.",
	Families: []string{"v4", "v6"},
	Encrypt:  "token / wss",
	Fields:   methodBackhaul.Fields,
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		art := Artifact{Name: "backhaul_premium_v1", Asset: "backhaul_premium_v1", Dest: "/opt/backhaul-premium-v1/backhaul_premium", Mode: 0o755}
		ir, kh, err = backhaulPlans(c, art.Dest, art, "Backhaul Premium v1", "/opt/backhaul-premium-v1")
		for _, p := range []*SidePlan{&ir, &kh} {
			p.Check, p.Unit.RestartSec = premiumLicenseCheck, premiumRestartSec // the v1 core checks its license too
		}
		return ir, kh, err
	},
}

// backhaulPlans: open Backhaul's [server]/[client] format, shared with Premium v1.
func backhaulPlans(c *buildCtx, bin string, art Artifact, title, certDir string) (ir, kh SidePlan, err error) {
	{
		d := c.D
		tr := c.Opt("transport")
		tp := portOr(c.Opt("tunnel_port"), c.D.BasePort)
		tok := c.T.secret("bh-token")
		bind := bracket(ipAny(c.T.Family)) + ":" + tp
		isMux := tr == "tcpmux" || tr == "wsmux" || tr == "wssmux"
		isTLS := tr == "wss" || tr == "wssmux"
		muxBlock := ""
		if isMux {
			muxBlock = fmt.Sprintf("mux_con = %s\nmux_version = 2\nmux_framesize = 32768\nmux_recievebuffer = 4194304\nmux_streambuffer = 65536\n", c.Opt("mux_con"))
		}
		tlsSrv := ""
		if isTLS {
			tlsSrv = "tls_cert = \"" + certDir + "/server.crt\"\ntls_key = \"" + certDir + "/server.key\"\n"
		}
		// server (Iran): exposes mapped ports; targets default to foreign 127.0.0.1
		irToml := fmt.Sprintf(`[server]
bind_addr = "%s"
transport = "%s"
token = "%s"
nodelay = %s
keepalive_period = 75
heartbeat = 40
channel_size = 4096
accept_udp = %v
sniffer = %s
log_level = "info"
%s%sports = [%s]
`, bind, tr, tok, c.Opt("nodelay"), tr == "tcp", c.Opt("sniffer"), muxBlock, tlsSrv, portsTOML(c.T.Ports))

		khToml := fmt.Sprintf(`[client]
remote_addr = "%s:%s"
transport = "%s"
token = "%s"
connection_pool = 8
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = %s
log_level = "info"
%s`, bracket(d.IRPub), tp, tr, tok, c.Opt("nodelay"), muxBlock)

		dir := tunnelDir(c.T)
		irCfg, khCfg := dir+"/backhaul.toml", dir+"/backhaul.toml"
		certGen := ""
		if isTLS {
			certGen = fmt.Sprintf("mkdir -p %[1]s; [ -f %[1]s/server.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj \"/CN=cdn.example.com\" -keyout %[1]s/server.key -out %[1]s/server.crt\n", certDir)
		}
		ir = SidePlan{Files: map[string]FileSpec{irCfg: {Content: []byte(irToml), Mode: 0o600}}, Setup: certGen, Artifacts: []Artifact{art},
			Unit: Unit{Desc: title + " Iran " + c.T.Name, ExecStart: bin + " -c " + irCfg}}
		kh = SidePlan{Files: map[string]FileSpec{khCfg: {Content: []byte(khToml), Mode: 0o600}}, Artifacts: []Artifact{art},
			Unit: Unit{Desc: title + " foreign " + c.T.Name, ExecStart: bin + " -c " + khCfg}}
		return ir, kh, nil
	}
}

func ipAny(fam string) string {
	if fam == "v6" {
		return "::"
	}
	return "0.0.0.0"
}

func portsTOML(ports string) string {
	var out string
	for i, p := range splitPorts(ports) {
		if i > 0 {
			out += ", "
		}
		spec := p.listen
		if p.dst != p.listen {
			spec = p.listen + "=" + p.dst
		}
		out += "\"" + spec + "\""
	}
	return out
}

// ---- FRP (fatedier/frp) reverse ----

var methodFRP = &Method{
	ID:       "frp",
	Title:    "FRP (reverse)",
	Desc:     "fatedier/frp reverse tunnel. Iran runs frps, foreign runs frpc. TCP/WS/QUIC/KCP transports.",
	Families: []string{"v4", "v6"},
	Encrypt:  "token (+TLS)",
	Fields: []Field{
		{Key: "protocol", Label: "Protocol", Type: "select", Default: "tcp", Options: []string{"tcp", "websocket", "quic", "kcp"}},
		{Key: "bind_port", Label: "Bind port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "tls", Label: "TLS", Type: "bool", Default: "true"},
		{Key: "udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "adds a udp proxy per port (Hysteria, WireGuard, QUIC)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		proto := c.Opt("protocol")
		bp := portOr(c.Opt("bind_port"), c.D.BasePort)
		tok := c.T.secret("frp-token")
		extra := ""
		switch proto {
		case "quic":
			extra = "quicBindPort = " + bp + "\n"
		case "kcp":
			extra = "kcpBindPort = " + bp + "\n"
		}
		irToml := fmt.Sprintf(`bindAddr = "%s"
bindPort = %s
%stransport.heartbeatTimeout = 90
transport.maxPoolCount = 65535
auth.method = "token"
auth.token = "%s"
`, ipAny(c.T.Family), bp, extra, tok)

		var proxies string
		pairs, perr := expandPortPairs(c.T.Ports, 512)
		if perr != nil {
			return ir, kh, perr
		}
		// with TLS on, frp's own per-proxy encryption only encrypts everything a second time
		enc := !c.OptB("tls")
		for _, p := range pairs {
			lp, rp, host := p.dst, p.listen, p.host
			proxies += fmt.Sprintf("\n[[proxies]]\nname = \"p-%s\"\ntype = \"tcp\"\nlocalIP = \"%s\"\nlocalPort = %s\nremotePort = %s\ntransport.useEncryption = %v\ntransport.useCompression = false\n", rp, host, lp, rp, enc)
			if c.OptB("udp") {
				proxies += fmt.Sprintf("\n[[proxies]]\nname = \"u-%s\"\ntype = \"udp\"\nlocalIP = \"%s\"\nlocalPort = %s\nremotePort = %s\n", rp, host, lp, rp)
			}
		}
		khToml := fmt.Sprintf(`serverAddr = "%s"
serverPort = %s
loginFailExit = false
auth.method = "token"
auth.token = "%s"
transport.protocol = "%s"
transport.tls.enable = %s
transport.poolCount = 32
transport.dialServerKeepalive = 120
%s`, d.IRPub, bp, tok, proto, c.Opt("tls"), proxies)

		dir := tunnelDir(c.T)
		irCfg, khCfg := dir+"/frps.toml", dir+"/frpc.toml"
		ir = SidePlan{Files: map[string]FileSpec{irCfg: {Content: []byte(irToml), Mode: 0o600}},
			Artifacts: []Artifact{artFRP(c.Set, "frps")},
			Unit:      Unit{Desc: "FRP server " + c.T.Name, ExecStart: "/opt/frp/frps -c " + irCfg}}
		kh = SidePlan{Files: map[string]FileSpec{khCfg: {Content: []byte(khToml), Mode: 0o600}},
			Artifacts: []Artifact{artFRP(c.Set, "frpc")},
			Unit:      Unit{Desc: "FRP client " + c.T.Name, ExecStart: "/opt/frp/frpc -c " + khCfg}}
		return ir, kh, nil
	},
}

// expandPortPairs turns "443,8080=80,2000-2010,3000-3002=4000-4002" into single
// listen→dst pairs (a range maps with its offset; a range onto one port maps every port to it).
// A target host ("443=10.0.0.5:443") is kept in host; it defaults to 127.0.0.1.
type portPair struct{ listen, dst, host string }

func expandPortPairs(spec string, max int) ([]portPair, error) {
	var out []portPair
	for _, p := range splitPorts(spec) {
		l := p.listen
		if i := strings.LastIndex(l, ":"); i >= 0 {
			l = l[i+1:]
		}
		d, host := p.dst, "127.0.0.1"
		if i := strings.LastIndex(d, ":"); i >= 0 {
			host, d = strings.Trim(d[:i], "[]"), d[i+1:]
		}
		llo, lhi := portRange(l)
		dlo, dhi := portRange(d)
		if llo <= 0 || lhi < llo {
			return nil, fmt.Errorf("bad port entry %q", p.listen)
		}
		for x := llo; x <= lhi; x++ {
			dst := dlo
			if dhi > dlo {
				dst = dlo + (x - llo)
			}
			out = append(out, portPair{listen: strconv.Itoa(x), dst: strconv.Itoa(dst), host: host})
			if len(out) > max {
				return nil, fmt.Errorf("FRP supports at most %d forwarded ports per tunnel", max)
			}
		}
	}
	return out, nil
}
