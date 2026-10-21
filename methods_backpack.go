package main

import "fmt"

func init() {
	register(methodBackpackReverse)
	register(methodBackpackL3)
}

var methodBackpackReverse = &Method{
	ID:       "bp_reverse",
	Title:    "BackPack reverse",
	Desc:     "AminMGMT/BackPack reverse tunnel. 12 transports incl. stealth (Noise). Iran listens, foreign dials.",
	Families: []string{"v4", "v6"},
	Encrypt:  "stealth/TLS/token",
	Fields: []Field{
		{Key: "transport", Label: "Transport", Type: "select", Default: "stealth",
			Options: []string{"tcp", "tcpmux", "stealth", "pck", "udp", "kcp", "quic", "ws", "wsmux", "wss", "wssmux", "xdi"}},
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "3080"},
		{Key: "preset", Label: "Preset", Type: "select", Default: "turbo", Options: []string{"balance", "turbo", "aggressive", "throughput"}},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		tr := c.Opt("transport")
		tp := c.Opt("tunnel_port")
		tok := c.T.secret("bp-token")
		bind := bracket(ipAny(c.T.Family)) + ":" + tp
		irToml := fmt.Sprintf(`[server]
bind_addr = "%s"
transport = "%s"
token = "%s"
nodelay = true
keepalive_period = 75
heartbeat = 40
channel_size = 4096
preset = "%s"
log_level = "info"
ports = [%s]
`, bind, tr, tok, c.Opt("preset"), portsTOML(c.T.Ports))
		khToml := fmt.Sprintf(`[client]
remote_addr = "%s:%s"
transport = "%s"
token = "%s"
connection_pool = 8
retry_interval = 3
dial_timeout = 10
nodelay = true
preset = "%s"
log_level = "info"
`, bracket(d.IRPub), tp, tr, tok, c.Opt("preset"))

		return backpackPlans(c, irToml, khToml)
	},
}

var methodBackpackL3 = &Method{
	ID:       "bp_l3",
	Title:    "BackPack L3 (TUN)",
	Desc:     "BackPack direct L3 TUN tunnel. GRE inside Noise (encrypted). Iran dials out, so it works when Iran has no open inbound port.",
	Families: []string{"v4", "v6"},
	Encrypt:  "Noise (AEAD)",
	Fields: []Field{
		{Key: "carrier", Label: "Carrier", Type: "select", Default: "udp", Options: []string{"udp", "quic", "pck", "sni", "xdi"}},
		{Key: "port", Label: "Carrier port", Type: "number", Default: "9000"},
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1400"},
		{Key: "sni_domain", Label: "SNI domain (sni carrier)", Type: "text", Default: "mci.ir"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		carrier := c.Opt("carrier")
		port := c.Opt("port")
		tok := c.T.secret("bp-l3-token")
		sni := ""
		if carrier == "sni" {
			sni = "sni_domain = \"" + c.Opt("sni_domain") + "\"\n"
		}
		// Iran dials the foreign listener.
		irToml := fmt.Sprintf(`[l3]
mode = "dial"
addr = "%s:%s"
token = "%s"
carrier = "%s"
local_ip = "%s/30"
peer_ip = "%s"
iface = "%s"
mtu = %s
%sports = [%s]
accept_udp = true
`, bracket(d.KHPub), port, tok, carrier, d.IRv4, d.KHv4, d.Iface, c.Opt("mtu"), sni, portsTOML(c.T.Ports))
		khToml := fmt.Sprintf(`[l3]
mode = "listen"
addr = "%s:%s"
token = "%s"
carrier = "%s"
local_ip = "%s/30"
peer_ip = "%s"
iface = "%s"
mtu = %s
%s`, bracket(ipAny(c.T.Family)), port, tok, carrier, d.KHv4, d.IRv4, d.Iface, c.Opt("mtu"), sni)
		return backpackPlans(c, irToml, khToml)
	},
}

func backpackPlans(c *buildCtx, irToml, khToml string) (SidePlan, SidePlan, error) {
	cfg := tunnelDir(c.T) + "/backpack.toml"
	mk := func(toml, side string) SidePlan {
		return SidePlan{Files: map[string]FileSpec{cfg: {Content: []byte(toml), Mode: 0o600}}, Artifacts: []Artifact{artBackpack(c.Set)},
			Unit: Unit{Desc: "BackPack " + side + " " + c.T.Name, ExecStart: "/usr/local/bin/backpack -c " + cfg}}
	}
	return mk(irToml, "Iran"), mk(khToml, "foreign"), nil
}
