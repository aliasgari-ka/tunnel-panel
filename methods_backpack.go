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
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "preset", Label: "Preset", Type: "select", Default: "turbo", Options: []string{"balance", "turbo", "aggressive", "throughput"}},
		{Key: "accept_udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "needed for UDP services (Hysteria, WireGuard, QUIC)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		tr := c.Opt("transport")
		if c.T.Family == "v6" && (tr == "pck" || tr == "xdi") {
			return ir, kh, fmt.Errorf("BackPack %s is IPv4-only — pick another transport for an IPv6 tunnel", tr)
		}
		tp := portOr(c.Opt("tunnel_port"), c.D.BasePort)
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
accept_udp = %v
ports = [%s]
`, bind, tr, tok, c.Opt("preset"), c.OptB("accept_udp"), portsTOML(c.T.Ports))
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
	Desc:     "BackPack L3 TUN tunnel (GRE inside Noise, encrypted). Normally Iran dials out, so Iran needs no open inbound port; set \"Who connects\" to foreign for the reverse direction (the foreign server dials Iran).",
	Families: []string{"v4", "v6"},
	Encrypt:  "Noise (AEAD)",
	Fields: []Field{
		{Key: "dialer", Label: "Who connects", Type: "select", Default: "iran", Options: []string{"iran", "foreign"},
			Help: "iran = Iran dials the foreign server (Iran needs no inbound port); foreign = reverse: the foreign server dials Iran (foreign needs no inbound port)"},
		{Key: "carrier", Label: "Carrier", Type: "select", Default: "udp", Options: []string{"udp", "quic", "pck", "sni", "xdi"}},
		{Key: "port", Label: "Carrier port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1400"},
		{Key: "sni_domain", Label: "SNI domain (sni carrier)", Type: "text", Default: "mci.ir"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		carrier := c.Opt("carrier")
		if c.T.Family == "v6" && (carrier == "pck" || carrier == "sni" || carrier == "xdi") {
			return ir, kh, fmt.Errorf("BackPack L3 carrier %s is IPv4-only — use udp or quic for an IPv6 tunnel", carrier)
		}
		port := portOr(c.Opt("port"), c.D.BasePort)
		tok := c.T.secret("bp-l3-token")
		sni := ""
		if carrier == "sni" {
			sni = "sni_domain = \"" + c.Opt("sni_domain") + "\"\n"
		}
		// Default: Iran dials the foreign listener. Reverse: Iran listens, foreign dials.
		irMode, irAddr := "dial", bracket(d.KHPub)+":"+port
		khMode, khAddr := "listen", bracket(ipAny(c.T.Family))+":"+port
		if c.Opt("dialer") == "foreign" {
			irMode, irAddr = "listen", bracket(ipAny(c.T.Family))+":"+port
			khMode, khAddr = "dial", bracket(d.IRPub)+":"+port
		}
		irToml := fmt.Sprintf(`[l3]
mode = "%s"
addr = "%s"
token = "%s"
carrier = "%s"
local_ip = "%s/30"
peer_ip = "%s"
iface = "%s"
mtu = %s
%sports = [%s]
accept_udp = true
`, irMode, irAddr, tok, carrier, d.IRv4, d.KHv4, d.Iface, c.Opt("mtu"), sni, portsTOML(c.T.Ports))
		khToml := fmt.Sprintf(`[l3]
mode = "%s"
addr = "%s"
token = "%s"
carrier = "%s"
local_ip = "%s/30"
peer_ip = "%s"
iface = "%s"
mtu = %s
%s`, khMode, khAddr, tok, carrier, d.KHv4, d.IRv4, d.Iface, c.Opt("mtu"), sni)
		return backpackPlans(c, irToml, khToml)
	},
}

func backpackPlans(c *buildCtx, irToml, khToml string) (SidePlan, SidePlan, error) {
	// BackPack names a tunnel after its config file (metrics snapshot, usage totals in
	// /etc/backpack/<name>.*), so every tunnel needs its own basename or two tunnels on
	// one host — or a benchmark next to a live tunnel — overwrite each other's state.
	cfg := tunnelDir(c.T) + "/tp-" + c.T.ID + ".toml"
	mk := func(toml, side string) SidePlan {
		return SidePlan{Files: map[string]FileSpec{cfg: {Content: []byte(toml), Mode: 0o600}}, Artifacts: []Artifact{artBackpack(c.Set)},
			// validate before starting, so a bad option is reported by name instead of a crash loop
			// (the status is check's own: "check | tail" would always succeed)
			Setup: "mkdir -p /etc/backpack\nif ! out=$(/usr/local/bin/backpack check -c " + cfg + " 2>&1); then echo \"$out\" | tail -5; exit 1; fi\n",
			Unit:  Unit{Desc: "BackPack " + side + " " + c.T.Name, ExecStart: "/usr/local/bin/backpack -c " + cfg}}
	}
	return mk(irToml, "Iran"), mk(khToml, "foreign"), nil
}
