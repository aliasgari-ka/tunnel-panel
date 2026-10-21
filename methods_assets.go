package main

import "fmt"

func init() {
	register(methodGoldenGRE)
	register(methodPremium)
}

// ---- Golden-GRE: GRE+FOU with a C relay disguising packets as DNS/ICMP (IPv4 only) ----

var methodGoldenGRE = &Method{
	ID:       "golden",
	Title:    "Golden-GRE (DNS/ICMP)",
	Desc:     "GRE-in-FOU with a userspace relay that disguises traffic as DNS queries or ICMP echo. IPv4 only. Optional XChaCha20 encryption.",
	Families: []string{"v4"},
	Encrypt:  "optional XChaCha20",
	Fields: []Field{
		{Key: "facade", Label: "Disguise", Type: "select", Default: "dns", Options: []string{"dns", "icmp", "none"}},
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1380"},
		{Key: "encrypt", Label: "Encrypt payload", Type: "bool", Default: "true"},
		{Key: "fec", Label: "FEC K:M (blank = off)", Type: "text", Default: ""},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		facade, mtu := c.Opt("facade"), c.Opt("mtu")
		fouPort, relayPort := d.BasePort, d.BasePort+1
		dir := tunnelDir(c.T)
		keyPath := dir + "/golden.key"
		relayBin := "/usr/local/sbin/golden-gre-relay"
		useKey := c.OptB("encrypt") && facade != "none"
		relay := Artifact{Name: "golden-gre-relay", Asset: "golden-gre-relay", Dest: relayBin, Mode: 0o755}

		// link setup / teardown (ExecStartPre / ExecStopPost around the relay service)
		linkUp := func(selfPub, peerPub, tunAddr string) string {
			s := sysctlBBR
			if facade == "none" {
				s += fmt.Sprintf(`ip link del %[1]s 2>/dev/null || true
ip link add %[1]s type gre local %[2]s remote %[3]s ttl 255 key %[4]d
ip addr add %[5]s/30 dev %[1]s
ip link set %[1]s mtu %[6]s up
iptables -C INPUT -p gre -s %[3]s -j ACCEPT 2>/dev/null || iptables -I INPUT -p gre -s %[3]s -j ACCEPT
`, d.Iface, selfPub, peerPub, d.GREKey, tunAddr, mtu)
				return s
			}
			inRule := "-p udp --dport 53"
			if facade == "icmp" {
				inRule = "-p icmp"
			}
			s += fmt.Sprintf(`modprobe fou 2>/dev/null || true
ip link del %[1]s 2>/dev/null || true
ip fou del port %[2]d local 127.0.0.1 2>/dev/null || true
ip fou add port %[2]d ipproto 47 local 127.0.0.1
ip link add %[1]s type gre local 127.0.0.1 remote 127.0.0.1 ttl 255 key %[3]d encap fou encap-sport %[2]d encap-dport %[4]d
ip addr add %[5]s/30 dev %[1]s
ip link set %[1]s mtu %[6]s up
ethtool -K %[1]s tso off gso off gro off 2>/dev/null || true
iptables -C INPUT %[7]s -s %[8]s -j ACCEPT 2>/dev/null || iptables -I INPUT %[7]s -s %[8]s -j ACCEPT
`, d.Iface, fouPort, d.GREKey, relayPort, tunAddr, mtu, inRule, peerPub)
			if facade == "icmp" {
				// stop the kernel answering the relay's echo requests to the peer
				s += fmt.Sprintf("iptables -C OUTPUT -d %[1]s -p icmp --icmp-type 0 -j DROP 2>/dev/null || iptables -I OUTPUT -d %[1]s -p icmp --icmp-type 0 -j DROP\n", peerPub)
			}
			return s
		}
		linkDown := func(selfPub, peerPub string) string {
			s := fmt.Sprintf("ip link del %s 2>/dev/null || true\nip fou del port %d local 127.0.0.1 2>/dev/null || true\n", d.Iface, fouPort)
			inRule := "-p udp --dport 53"
			if facade == "icmp" {
				inRule = "-p icmp"
			}
			if facade != "none" {
				s += fmt.Sprintf("iptables -D INPUT %s -s %s -j ACCEPT 2>/dev/null || true\n", inRule, peerPub)
				if facade == "icmp" {
					s += fmt.Sprintf("iptables -D OUTPUT -d %s -p icmp --icmp-type 0 -j DROP 2>/dev/null || true\n", peerPub)
				}
			} else {
				s += fmt.Sprintf("iptables -D INPUT -p gre -s %s -j ACCEPT 2>/dev/null || true\n", peerPub)
			}
			return s
		}
		relayCmd := func(selfPub, peerPub string) string {
			if facade == "none" {
				return "/bin/sleep infinity" // GRE needs no relay; keep the unit alive
			}
			args := fmt.Sprintf("%s --facade %s --bind %s --peer %s --local 127.0.0.1:%d --reply 127.0.0.1:%d",
				relayBin, facade, selfPub, peerPub, relayPort, fouPort)
			if facade == "dns" {
				args += " --port 53"
			} else {
				args += " --itype 8"
			}
			if useKey {
				args += " --keyfile " + keyPath
			}
			if f := c.Opt("fec"); f != "" {
				args += " --fec " + f
			}
			return args
		}

		mk := func(selfPub, peerPub, tunAddr string, entry bool) SidePlan {
			up := linkUp(selfPub, peerPub, tunAddr)
			down := linkDown(selfPub, peerPub)
			if entry {
				up += portForwardV4(c.T.Ports, d.KHv4, d.Iface, fwdTag(d))
				down = portForwardDownV4(fwdTag(d)) + down
			}
			files := map[string]FileSpec{
				dir + "/up.sh":   {Content: []byte("#!/bin/bash\n" + up), Mode: 0o755},
				dir + "/down.sh": {Content: []byte("#!/bin/bash\n" + down), Mode: 0o755},
			}
			if useKey {
				files[keyPath] = FileSpec{Content: []byte(c.T.secret("golden-key")), Mode: 0o600}
			}
			sp := SidePlan{Files: files, Artifacts: []Artifact{relay}, Unit: Unit{
				Desc:         "Golden-GRE " + c.T.Name,
				Type:         "simple",
				ExecStartPre: dir + "/up.sh",
				ExecStart:    relayCmd(selfPub, peerPub),
				ExecStopPost: dir + "/down.sh",
			}}
			return sp
		}
		return mk(d.IRPub, d.KHPub, d.IRv4, true), mk(d.KHPub, d.IRPub, d.KHv4, false), nil
	},
}

// ---- Backhaul Premium (closed binary, uploaded & hash-pinned; new [listener]/[ipx] format) ----

var methodPremium = &Method{
	ID:       "premium",
	Title:    "Backhaul Premium (ipx/tun)",
	Desc:     "Closed-source core (uploaded to the panel, not fetched over HTTP). tun with ipx raw carrier (icmp/ipip/udp/tcp/gre/bip) and anytls. amd64 only.",
	Families: []string{"v4"},
	Encrypt:  "AEAD (ipx) / TLS",
	Fields: []Field{
		{Key: "mode", Label: "Mode", Type: "select", Default: "ipx", Options: []string{"ipx", "anytls", "tcpmux", "wssmux", "tcp"}},
		{Key: "profile", Label: "IPX carrier", Type: "select", Default: "tcp", Options: []string{"tcp", "bip", "gre", "ipip", "udp", "icmp"}},
		{Key: "port", Label: "Tunnel port (non-ipx)", Type: "number", Default: "8443"},
		{Key: "sni", Label: "SNI (anytls)", Type: "text", Default: "www.digikala.com"},
		{Key: "algorithm", Label: "IPX cipher", Type: "select", Default: "aes-256-gcm", Options: []string{"aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"}},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		mode := c.Opt("mode")
		dir := tunnelDir(c.T)
		bin := "/opt/backhaul-premium/backhaul_premium"
		core := Artifact{Name: "backhaul_premium", Asset: "backhaul_premium", Dest: bin, Mode: 0o755}
		irCfg, khCfg := dir+"/iran.toml", dir+"/kharej.toml"
		certDir := "/opt/backhaul-premium"

		var irToml, khToml string
		if mode == "ipx" {
			psk := c.T.secret("premium-psk")
			prof, alg := c.Opt("profile"), c.Opt("algorithm")
			ipxCommon := func(self, peer string) string {
				return fmt.Sprintf(`[transport]
type = "tun"
heartbeat_interval = 10
heartbeat_timeout = 25

[tun]
encapsulation = "ipx"
name = "bhp%d"
local_addr = "%s/30"
remote_addr = "%s/30"
health_port = %d
mtu = 1320

[security]
enable_encryption = true
algorithm = "%s"
psk = "%s"
kdf_iterations = 100000

[tuning]
auto_tuning = true
tuning_profile = "balanced"
channel_size = 10_000

[logging]
log_level = "info"
`, d.Idx, self, peer, d.BasePort, alg, psk)
			}
			irToml = fmt.Sprintf("[ipx]\nmode = \"server\"\nprofile = %q\nlisten_ip = %q\ndst_ip = %q\ninterface = \"IFACE\"\n\n", prof, d.IRPub, d.KHPub) +
				ipxCommon(d.IRv4, d.KHv4) + fmt.Sprintf("\n[ports]\nforwarder = \"iptables\"\nmapping = [%s]\n", portsTOML(c.T.Ports))
			khToml = fmt.Sprintf("[ipx]\nmode = \"client\"\nprofile = %q\nlisten_ip = %q\ndst_ip = %q\ninterface = \"IFACE\"\n\n", prof, d.KHPub, d.IRPub) +
				ipxCommon(d.KHv4, d.IRv4)
		} else {
			tok := c.T.secret("premium-token")
			port := c.Opt("port")
			muxBlock, tlsBlock, tlsClient := "", "", ""
			if mode == "tcpmux" || mode == "wssmux" {
				muxBlock = "\n[mux]\nmux_version = 2\nmux_framesize = 32768\nmux_recievebuffer = 4194304\nmux_streambuffer = 2097152\nmux_concurrency = 8\n"
			}
			if mode == "anytls" || mode == "wssmux" {
				tlsBlock = fmt.Sprintf("\n[tls]\nsni = %q\ntls_cert = %q\ntls_key = %q\n", c.Opt("sni"), certDir+"/cert.crt", certDir+"/cert.key")
			}
			if mode == "anytls" {
				tlsClient = fmt.Sprintf("\n[tls]\nsni = %q\n", c.Opt("sni"))
			}
			irToml = fmt.Sprintf(`[listener]
bind_addr = ":%s"

[transport]
type = "%s"
nodelay = true
keepalive_period = 40
heartbeat_interval = 10
heartbeat_timeout = 25
%s
[security]
token = "%s"
%s
[tuning]
auto_tuning = true
tuning_profile = "balanced"
channel_size = 4096

[logging]
log_level = "info"

[ports]
mapping = [%s]
`, port, mode, muxBlock, tok, tlsBlock, portsTOML(c.T.Ports))
			khToml = fmt.Sprintf(`[dialer]
remote_addr = "%s:%s"
dial_timeout = 10
retry_interval = 3

[transport]
type = "%s"
nodelay = true
keepalive_period = 40
connection_pool = 8
heartbeat_interval = 10
heartbeat_timeout = 25
%s
[security]
token = "%s"
%s
[tuning]
auto_tuning = true
tuning_profile = "balanced"
channel_size = 4096

[logging]
log_level = "info"
`, d.IRPub, port, mode, muxBlock, tok, tlsClient)
		}

		certGen := ""
		if mode == "anytls" || mode == "wssmux" {
			certGen = fmt.Sprintf("[ -f %[1]s/cert.crt ] || openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -x509 -days 365 -sha256 -keyout %[1]s/cert.key -out %[1]s/cert.crt -subj \"/CN=cdn.example.com\"\n", certDir)
		}
		fixIface := func(cfg string) string {
			return "sed -i \"s/IFACE/$(ip route show default | awk '{print $5; exit}')/\" " + cfg + " 2>/dev/null || true\n"
		}
		mk := func(toml, cfg, side string) SidePlan {
			return SidePlan{
				Files:     map[string]FileSpec{cfg: {Content: []byte(toml), Mode: 0o600}},
				Artifacts: []Artifact{core},
				Setup:     sysctlBBR + certGen + fixIface(cfg),
				Unit:      Unit{Desc: "Backhaul Premium " + side + " " + c.T.Name, ExecStart: bin + " -c " + cfg},
			}
		}
		return mk(irToml, irCfg, "Iran"), mk(khToml, khCfg, "foreign"), nil
	},
}
