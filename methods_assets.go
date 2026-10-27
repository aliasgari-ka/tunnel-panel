package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
)

func init() {
	register(methodGoldenGRE)
	register(methodICMP)
	register(methodPremium)
}

// ---- Golden-GRE: GRE+FOU with a C relay disguising packets as DNS/ICMP (IPv4 only) ----

var methodGoldenGRE = &Method{
	ID:       "golden",
	Title:    "Golden-GRE (DNS/ICMP)",
	Desc:     "GRE-in-FOU with a userspace relay that disguises traffic as DNS queries or ICMP echo. IPv4 only. Optional XChaCha20 encryption.",
	Families: []string{"v4"},
	Encrypt:  "optional XChaCha20",
	Helper:   "golden-gre-relay",
	Fields: []Field{
		{Key: "facade", Label: "Disguise", Type: "select", Default: "dns", Options: []string{"dns", "icmp", "none"}},
		{Key: "dnsport", Label: "DNS port on the wire (change only for a 2nd Golden tunnel between the same two servers)", Type: "number", Default: "53"},
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1380"},
		{Key: "encrypt", Label: "Encrypt payload", Type: "bool", Default: "true"},
		{Key: "fec", Label: "FEC K:M (blank = off)", Type: "text", Default: ""},
	},
	// DNS on UDP 53 is intercepted on many Iranian networks
	Alts: func(string) []map[string]string {
		return []map[string]string{{"facade": "icmp"}, {"facade": "none"}}
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		return buildGolden(c, c.Opt("facade"))
	},
}

// ---- ICMP tunnel: the Golden relay locked to the ICMP-echo disguise (IPv4 only) ----

// methodICMP tunnels through ICMP echo (ping) using the same userspace relay as Golden-GRE,
// for networks that let ping through but block most else. It is Golden-GRE with the facade
// fixed to icmp, so it has no DNS-port field.
var methodICMP = &Method{
	ID:       "icmp",
	Title:    "ICMP tunnel (ping)",
	Desc:     "GRE-in-FOU disguised as ICMP echo (ping) by a userspace relay, so it passes where only ping gets through. IPv4 only. Optional XChaCha20 encryption.",
	Families: []string{"v4"},
	Encrypt:  "optional XChaCha20",
	Helper:   "golden-gre-relay",
	Fields: []Field{
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1380"},
		{Key: "encrypt", Label: "Encrypt payload", Type: "bool", Default: "true"},
		{Key: "fec", Label: "FEC K:M (blank = off)", Type: "text", Default: "", Advanced: true},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		return buildGolden(c, "icmp")
	},
}

// buildGolden builds the relay plan for a Golden-GRE-family method with the given facade
// (dns | icmp | none). methodGoldenGRE passes the chosen facade; methodICMP fixes it to icmp.
func buildGolden(c *buildCtx, facade string) (ir, kh SidePlan, err error) {
	d := c.D
	mtu, wirePort := c.Opt("mtu"), c.Opt("dnsport")
	if facade == "dns" {
		if p, err := strconv.Atoi(wirePort); err != nil || p < 1 || p > 65535 {
			return ir, kh, fmt.Errorf("Golden-GRE: DNS port must be 1..65535")
		}
	}
	// the relay receives on its own port; a TPROXY rule per peer hands it that peer's port-53
	// packets, so several Golden tunnels (to different peers) share one server's public port 53
	fouPort, relayPort, rxPort := d.BasePort, d.BasePort+1, d.BasePort+3
	tag := "tpg-" + c.T.ID
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
		inRule := "-p udp --dport " + wirePort
		if facade == "icmp" {
			inRule = "-p icmp"
		}
		if facade == "dns" {
			s += goldenSteer(true, peerPub, wirePort, selfPub, rxPort, tag)
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
		inRule := "-p udp --dport " + wirePort
		if facade == "icmp" {
			inRule = "-p icmp"
		}
		if facade == "dns" {
			s += goldenSteer(false, peerPub, wirePort, selfPub, rxPort, tag)
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
			args += fmt.Sprintf(" --port %s --listen %d", wirePort, rxPort)
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
		up := linkUp(selfPub, peerPub, tunAddr) +
			fmt.Sprintf("ip link show %[1]s >/dev/null 2>&1 || { echo \"could not create interface %[1]s (gre/fou kernel modules?)\"; exit 1; }\n", d.Iface)
		down := linkDown(selfPub, peerPub)
		if entry {
			up += portForwardV4(c.T.Ports, d.KHv4, d.Iface, fwdTag(d))
			down = portForwardDownV4(fwdTag(d)) + down
		}
		files := map[string]FileSpec{
			dir + "/up.sh":   {Content: []byte("#!/bin/bash\n" + up), Mode: 0o755},
			dir + "/down.sh": {Content: []byte("#!/bin/bash\n" + down), Mode: 0o755},
			// which relay source this binary was built from (see golden_src.go)
			relayBin + ".src": {Content: []byte(goldenRelaySrc + "\n"), Mode: 0o644},
		}
		if useKey {
			// the relay wants exactly 32 raw bytes; derive them from the stored secret
			k := sha256.Sum256([]byte(c.T.secret("golden-key")))
			files[keyPath] = FileSpec{Content: k[:], Mode: 0o600}
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
}

// ipxEmuCheck: on a non-amd64 server the amd64 Premium core runs emulated, and only box64
// (not qemu-user) can open ipx's packet socket. Get box64 if the distro has it, else stop
// with what to do — a unit that is "active" but carries nothing helps nobody.
// box64Release is where the release workflow publishes box64 for arm64 (built from pinned
// upstream source on Ubuntu 22.04), for distros that don't package it.
const box64Release = "https://github.com/aliasgari-ka/tunnel-panel/releases/latest/download/box64-arm64"

func ipxEmuCheck(mode, ghPrefix string) string {
	if mode != "ipx" {
		return ""
	}
	return `if [ -f /opt/backhaul-premium/backhaul_premium.amd64 ] && [ "$(uname -m)" != x86_64 ] && ! command -v box64 >/dev/null 2>&1; then
  echo "ipx on $(uname -m) needs box64 — trying the distro's package"
  # (setup runs with set -e: every try must be allowed to fail, the check below decides)
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq box64 >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq box64 >/dev/null 2>&1; } || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y box64 >/dev/null 2>&1 || true
  fi
  if ! command -v box64 >/dev/null 2>&1 && [ "$(uname -m)" = aarch64 ]; then
    echo "no box64 package — installing the panel release's box64 build"
    T=$(mktemp -d)
    if curl -fsSL --retry 2 --max-time 300 -o "$T/box64" ` + shq(ghPrefix+box64Release) + ` &&
       curl -fsSL --retry 2 --max-time 30 -o "$T/box64.sha256" ` + shq(ghPrefix+box64Release+".sha256") + ` &&
       (cd "$T" && sed 's#  *[^ ]*$#  box64#' box64.sha256 | sha256sum -c - >/dev/null 2>&1) &&
       chmod 0755 "$T/box64" && "$T/box64" --version >/dev/null 2>&1; then
      install -m0755 "$T/box64" /usr/local/bin/box64 && echo "box64 installed: $(box64 --version 2>/dev/null | head -1)"
    else
      echo "could not download/verify box64 from the panel's GitHub release"
    fi
    rm -rf "$T"
  fi
  if ! command -v box64 >/dev/null 2>&1; then
    echo "Premium ipx can't run on this $(uname -m) server: there is no arm64 v2 core, the amd64 core runs under qemu-user (which can't open ipx's packet socket), and this distro has no box64 package ($(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}"))."
    echo "→ in Options set Mode to tcpmux, wssmux or anytls and Apply again (they work under emulation), or use Backhaul Premium v1 (native arm64), or install box64 by hand"
    exit 1
  fi
fi
`
}

// goldenSteer adds (or removes) the TPROXY rule that hands the peer's DNS-port packets to
// this tunnel's relay. TPROXY picks the socket per packet and rewrites nothing, so unlike
// NAT no conntrack entry from before the rule (or from another relay) can get in the way.
func goldenSteer(add bool, peer, wirePort, self string, rxPort int, tag string) string {
	rule := fmt.Sprintf("PREROUTING -p udp -s %s -d %s --dport %s -m comment --comment %s -j TPROXY --on-ip %s --on-port %d", peer, self, wirePort, tag, self, rxPort)
	if !add {
		return fmt.Sprintf("while iptables -w -t mangle -D %s 2>/dev/null; do :; done\n", rule)
	}
	return fmt.Sprintf(`modprobe xt_TPROXY 2>/dev/null; modprobe nf_tproxy_ipv4 2>/dev/null
iptables -w -t mangle -C %[1]s 2>/dev/null || iptables -w -t mangle -I %[1]s || { echo "could not add the TPROXY rule for the relay (kernel module xt_TPROXY missing?)"; exit 1; }
`, rule)
}

// goldenConflict names a running Golden-GRE (dns) tunnel that already uses t's DNS port
// between the same two servers: both relays would be sent the same peer's packets.
func goldenConflict(st *State, t *Tunnel) string {
	if t.Family != "v4" {
		return ""
	}
	get, _ := resolveOptions(methodGoldenGRE, t.Options["golden"])
	if get("facade") != "dns" {
		return ""
	}
	for _, o := range st.Tunnels {
		if o.ID == t.ID || o.Active != "golden" || o.Family != "v4" || o.ServerID != t.ServerID || o.ForeignID != t.ForeignID {
			continue
		}
		og, _ := resolveOptions(methodGoldenGRE, o.Options["golden"])
		if og("facade") == "dns" && og("dnsport") == get("dnsport") {
			return o.Name
		}
	}
	return ""
}

// ---- Backhaul Premium (closed binary, uploaded & hash-pinned; new [listener]/[ipx] format) ----

// The Premium core checks its license online (bound to the server's public IP) and stops on
// a bad verdict. premiumLicenseCheck waits for the verdict after a start and fails the apply
// with it, instead of a tunnel that just doesn't work; no verdict (no internet/DNS on the
// server) is only noted. premiumRestartSec keeps a failing core from asking the vendor's
// license servers every 3 seconds.
const premiumRestartSec = 30

const premiumLicenseCheck = `jl() { inv=$(systemctl show -p InvocationID --value $UNIT 2>/dev/null)
  if [ -n "$inv" ]; then journalctl _SYSTEMD_INVOCATION_ID=$inv --no-pager -o cat 2>/dev/null; else journalctl -u $UNIT -n 80 --no-pager -o cat 2>/dev/null; fi; }
for i in $(seq 1 15); do
  l=$(jl | sed 's/\x1b\[[0-9;]*m//g' | grep -i -E 'licen[cs]e (is valid|ip|does not|has expired|is expired|is invalid|status unknown|issue)|invalid license|unknown license' | tail -1)
  case "$l" in
    *[Ii]s\ valid*) echo "Backhaul Premium license: valid"; exit 0 ;;
    "") sleep 1 ;;
    *) echo "Backhaul Premium license problem: $(echo "$l" | sed 's/^.*\] *//') — the license is bound to this server's public IP; check it with the vendor"; exit 1 ;;
  esac
done
echo "note: no license verdict from the Premium core within 15 s (it validates online: is this server's internet / DNS working?)"
exit 0
`

var methodPremium = &Method{
	ID:       "premium",
	Title:    "Backhaul Premium (ipx/tun)",
	Desc:     "Closed-source core (uploaded to the panel, not fetched over HTTP). tun with ipx raw carrier (icmp/ipip/udp/tcp/gre/bip) and anytls. amd64 and arm64: upload the core for each architecture you use.",
	Families: []string{"v4"},
	Encrypt:  "AEAD (ipx) / TLS",
	Helper:   "backhaul_premium",
	Fields: []Field{
		{Key: "mode", Label: "Mode", Type: "select", Default: "ipx", Options: []string{"ipx", "anytls", "tcpmux", "wssmux", "tcp"}},
		{Key: "profile", Label: "IPX carrier", Type: "select", Default: "tcp", Options: []string{"tcp", "bip", "gre", "ipip", "udp", "icmp"}},
		{Key: "port", Label: "Tunnel port (non-ipx)", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "sni", Label: "SNI (anytls)", Type: "text", Default: "www.digikala.com"},
		{Key: "algorithm", Label: "IPX cipher", Type: "select", Default: "aes-256-gcm", Options: []string{"aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"}},
		{Key: "mtu", Label: "TUN MTU (ipx)", Type: "number", Default: "1280",
			Help: "lower it (1200, 1100) if download works but upload/handshakes stall — the Iran→foreign path drops big packets"},
		{Key: "heartbeat_interval", Label: "Heartbeat interval (s)", Type: "number", Default: "10", Advanced: true},
		{Key: "heartbeat_timeout", Label: "Heartbeat timeout (s)", Type: "number", Default: "25",
			Help: "must be longer than the interval; lower = a dead link is noticed sooner", Advanced: true},
		{Key: "connection_pool", Label: "Connection pool (non-ipx)", Type: "number", Default: "8", Advanced: true},
		{Key: "mux_concurrency", Label: "Mux concurrency (tcpmux / wssmux)", Type: "number", Default: "8", Advanced: true},
		{Key: "channel_size", Label: "Channel size (non-ipx)", Type: "number", Default: "4096", Advanced: true},
		{Key: "log_level", Label: "Log level", Type: "select", Default: "info", Options: []string{"debug", "info", "warn", "error"}, Advanced: true},
	},
	// the default tcp profile is hand-made TCP segments without a handshake, which stateful
	// filtering drops; gre passes wherever Plain GRE does
	// last, the modes over real TCP: they pass where only TCP does, and they also run on an
	// ARM server, where ipx can't (no ARM v2 core; the emulated one can't open ipx's socket)
	Alts: func(string) []map[string]string {
		return []map[string]string{{"profile": "gre"}, {"profile": "icmp"}, {"profile": "ipip"}, {"profile": "bip"}, {"profile": "udp"},
			{"mode": "tcpmux"}, {"mode": "anytls"}}
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		mode := c.Opt("mode")
		hbi, _ := strconv.Atoi(c.Opt("heartbeat_interval"))
		hbt, _ := strconv.Atoi(c.Opt("heartbeat_timeout"))
		if hbi < 1 || hbt <= hbi {
			return ir, kh, fmt.Errorf("Backhaul Premium: the heartbeat timeout (%d s) must be longer than the interval (%d s)", hbt, hbi)
		}
		logLevel := c.Opt("log_level")
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
heartbeat_interval = %d
heartbeat_timeout = %d

[tun]
encapsulation = "ipx"
name = "bhp%d"
local_addr = "%s/30"
remote_addr = "%s/30"
health_port = %d
mtu = %s

[security]
enable_encryption = true
algorithm = "%s"
psk = "%s"
kdf_iterations = 100000

[tuning]
auto_tuning = true
tuning_profile = "balanced"
workers = 0
channel_size = 10_000
batch_size = 2048
so_sndbuf = 0

[logging]
log_level = "%s"
`, hbi, hbt, d.Idx, self, peer, d.BasePort, c.Opt("mtu"), alg, psk, logLevel)
			}
			irToml = fmt.Sprintf("[ipx]\nmode = \"server\"\nprofile = %q\nlisten_ip = %q\ndst_ip = %q\ninterface = \"IFACE\"\n\n", prof, d.IRPub, d.KHPub) +
				ipxCommon(d.IRv4, d.KHv4) + fmt.Sprintf("\n[ports]\nforwarder = \"iptables\"\nmapping = [%s]\n", portsTOML(c.T.Ports))
			khToml = fmt.Sprintf("[ipx]\nmode = \"client\"\nprofile = %q\nlisten_ip = %q\ndst_ip = %q\ninterface = \"IFACE\"\n\n", prof, d.KHPub, d.IRPub) +
				ipxCommon(d.KHv4, d.IRv4)
		} else {
			tok := c.T.secret("premium-token")
			port := portOr(c.Opt("port"), d.BasePort)
			muxBlock, tlsBlock, tlsClient := "", "", ""
			if mode == "tcpmux" || mode == "wssmux" {
				muxBlock = "\n[mux]\nmux_version = 2\nmux_framesize = 32768\nmux_recievebuffer = 4194304\nmux_streambuffer = 2097152\nmux_concurrency = " + c.Opt("mux_concurrency") + "\n"
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
heartbeat_interval = %d
heartbeat_timeout = %d
%s
[security]
token = "%s"
%s
[tuning]
auto_tuning = true
tuning_profile = "balanced"
channel_size = %s

[logging]
log_level = "%s"

[ports]
mapping = [%s]
`, port, mode, hbi, hbt, muxBlock, tok, tlsBlock, c.Opt("channel_size"), logLevel, portsTOML(c.T.Ports))
			khToml = fmt.Sprintf(`[dialer]
remote_addr = "%s:%s"
dial_timeout = 10
retry_interval = 3

[transport]
type = "%s"
nodelay = true
keepalive_period = 40
connection_pool = %s
heartbeat_interval = %d
heartbeat_timeout = %d
%s
[security]
token = "%s"
%s
[tuning]
auto_tuning = true
tuning_profile = "balanced"
channel_size = %s

[logging]
log_level = "%s"
`, d.IRPub, port, mode, c.Opt("connection_pool"), hbi, hbt, muxBlock, tok, tlsClient, c.Opt("channel_size"), logLevel)
		}

		certGen := ""
		if mode == "anytls" || mode == "wssmux" {
			certGen = fmt.Sprintf("[ -f %[1]s/cert.crt ] || openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -x509 -days 365 -sha256 -keyout %[1]s/cert.key -out %[1]s/cert.crt -subj \"/CN=cdn.example.com\"\n", certDir)
		}
		// ipx sends raw packets on the interface the route to the peer server leaves by —
		// not the default route's, which on a server with a VPN, a proxy tun or a second NIC
		// is another interface, and then nothing arrives
		fixIface := func(cfg, peer string) string {
			return fmt.Sprintf(`dev=$(ip -4 route get %s 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
[ -n "$dev" ] || dev=$(ip route show default | awk '{print $5; exit}')
[ -n "$dev" ] || { echo "no route to %s on this server — ipx needs one"; exit 1; }
sed -i "s/IFACE/$dev/" %s 2>/dev/null || true
`, peer, peer, cfg)
		}
		mk := func(toml, cfg, side, peer string) SidePlan {
			sp := SidePlan{
				Files:     map[string]FileSpec{cfg: {Content: []byte(toml), Mode: 0o600}},
				Artifacts: []Artifact{core},
				Setup:     sysctlBBR + certGen + fixIface(cfg, peer) + ipxEmuCheck(mode, c.Set.GitHubProxy),
				Unit:      Unit{Desc: "Backhaul Premium " + side + " " + c.T.Name, ExecStart: bin + " -c " + cfg, RestartSec: premiumRestartSec},
				Check:     premiumLicenseCheck,
			}
			if mode == "ipx" {
				// The core DNATs the mapped ports into the TUN but neither accepts them in
				// FORWARD (dropped when ufw/docker set the policy to DROP) nor clamps the TCP
				// MSS (users' full-size packets don't fit the TUN MTU, handshakes stall).
				ifc := fmt.Sprintf("bhp%d", d.Idx)
				up, down := tunFwdRules(ifc, fwdTag(d))
				sp.Files[dir+"/fw-up.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + up), Mode: 0o755}
				sp.Files[dir+"/fw-down.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + down), Mode: 0o755}
				sp.Unit.ExecStartPre = dir + "/fw-up.sh"
				sp.Unit.ExecStopPost = dir + "/fw-down.sh"
			}
			return sp
		}
		return mk(irToml, irCfg, "Iran", d.KHPub), mk(khToml, khCfg, "foreign", d.IRPub), nil
	},
}
