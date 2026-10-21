package main

import "fmt"

func init() {
	register(methodBackhaul)
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
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "3080", Help: "control/data port on Iran"},
		{Key: "mux_con", Label: "Mux concurrency", Type: "number", Default: "8"},
		{Key: "nodelay", Label: "TCP nodelay", Type: "bool", Default: "true"},
		{Key: "sniffer", Label: "Traffic sniffer", Type: "bool", Default: "false"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		tr := c.Opt("transport")
		tp := c.Opt("tunnel_port")
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
			tlsSrv = "tls_cert = \"/opt/backhaul/server.crt\"\ntls_key = \"/opt/backhaul/server.key\"\n"
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
			certGen = "[ -f /opt/backhaul/server.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj \"/CN=cdn.example.com\" -keyout /opt/backhaul/server.key -out /opt/backhaul/server.crt\n"
		}
		ir = SidePlan{Files: map[string]FileSpec{irCfg: {Content: []byte(irToml), Mode: 0o600}}, Setup: certGen, Artifacts: []Artifact{artBackhaul(c.Set)},
			Unit: Unit{Desc: "Backhaul Iran " + c.T.Name, ExecStart: "/opt/backhaul/backhaul -c " + irCfg}}
		kh = SidePlan{Files: map[string]FileSpec{khCfg: {Content: []byte(khToml), Mode: 0o600}}, Artifacts: []Artifact{artBackhaul(c.Set)},
			Unit: Unit{Desc: "Backhaul foreign " + c.T.Name, ExecStart: "/opt/backhaul/backhaul -c " + khCfg}}
		return ir, kh, nil
	},
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
		{Key: "bind_port", Label: "Bind port", Type: "number", Default: "7000"},
		{Key: "tls", Label: "TLS", Type: "bool", Default: "true"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		proto := c.Opt("protocol")
		bp := c.Opt("bind_port")
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
		for _, p := range splitPorts(c.T.Ports) {
			lp := p.dst
			rp := p.listen
			proxies += fmt.Sprintf("\n[[proxies]]\nname = \"p-%s\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %s\nremotePort = %s\ntransport.useEncryption = true\ntransport.useCompression = false\n", rp, lp, rp)
		}
		khToml := fmt.Sprintf(`serverAddr = "%s"
serverPort = %s
loginFailExit = false
auth.method = "token"
auth.token = "%s"
transport.protocol = "%s"
transport.tls.enable = %s
transport.poolCount = 10
transport.dialServerKeepalive = 120
%s`, d.IRPub, bp, tok, proto, c.Opt("tls"), proxies)

		dir := tunnelDir(c.T)
		irCfg, khCfg := dir+"/frps.toml", dir+"/frpc.toml"
		ir = SidePlan{Files: map[string]FileSpec{irCfg: {Content: []byte(irToml), Mode: 0o600}},
			Artifacts: []Artifact{artFRP(c.Set, "frps")},
			Unit:  Unit{Desc: "FRP server " + c.T.Name, ExecStart: "/opt/frp/frps -c " + irCfg}}
		kh = SidePlan{Files: map[string]FileSpec{khCfg: {Content: []byte(khToml), Mode: 0o600}},
			Artifacts: []Artifact{artFRP(c.Set, "frpc")},
			Unit:  Unit{Desc: "FRP client " + c.T.Name, ExecStart: "/opt/frp/frpc -c " + khCfg}}
		return ir, kh, nil
	},
}
