package main

import (
	"fmt"
	"strconv"
	"strings"
)

// BackPack v2 (AminMGMT/BackPack v2.0.0), next to the v1 methods and never instead of them.
//
// v2 is not a drop-in for the v1 binary: its direct PCK is another engine with another wire,
// the udp and quic carriers of the L3 tunnel are gone, and the plain transports changed their
// handshake. So v2 has its own binary (/usr/local/bin/backpack2), its own method ids and its
// own token, and a tunnel that runs a v1 method keeps the v1 binary it was built with.
//
// What v2 brings that is worth a method of its own:
//   - reverse transports with a send-side window control on kcp / pck / xdi (they no longer
//     fill the path's queue), a larger pool on the plain ones, and a challenge-response
//     handshake where v1 sent the token as it is;
//   - direct PCK as a port forwarder over KCP inside crafted TCP segments (a port of paqet):
//     Iran dials, so Iran needs no inbound port.
func init() {
	register(methodBackpack2Reverse)
	register(methodBackpack2RPck)
	register(methodBackpack2Pck)
}

const backpack2Bin = "/usr/local/bin/backpack2"

// BackPack v2 is pinned like v1, with the archive checksums of the release itself
// (SHA256SUMS of v2.0.0, whose signature verifies with the key v1.8.5 was signed with).
const backpack2Version = "v2.0.0"

var backpack2SHA256 = map[string]string{
	"amd64": "6e38749a1d749cbf11eb293457ddc94142a96659350acf6047fc7ef44a6115d3",
	"arm64": "7f709943079b257856349ddbb370cdd1b386ea7059e11584d9ae1fcab40616fe",
}

func artBackpack2(set Settings) Artifact {
	return Artifact{Name: "backpack-" + backpack2Version, Dest: backpack2Bin, Mode: 0o755, Fetch: fmt.Sprintf(`
case "$ARCH" in amd64) want=%s ;; arm64) want=%s ;; *) echo "no pinned BackPack v2 checksum for $ARCH"; exit 1 ;; esac
curl -fL --retry 3 -o bp2.tgz "%shttps://github.com/AminMGMT/BackPack/releases/download/%s/backpack_linux_${ARCH}.tar.gz"
echo "$want  bp2.tgz" | sha256sum -c - || { echo "BackPack v2 archive checksum mismatch — refusing to install it"; exit 1; }
tar -xzf bp2.tgz backpack
install -m0755 backpack "$OUT"`, backpack2SHA256["amd64"], backpack2SHA256["arm64"], set.GitHubProxy, backpack2Version)}
}

// bp2ReverseTransports are v2's reverse transports that need no helper program (its HTTPS
// family — Naive, XHTTP, REALITY — runs sing-box / Xray beside the engine and is left out).
var bp2ReverseTransports = []string{"tcp", "tcpmux", "stealth", "pck", "udp", "kcp", "quic", "ws", "wsmux", "wss", "wssmux", "xdi"}

func bp2IsMux(tr string) bool { return tr == "tcpmux" || tr == "wsmux" || tr == "wssmux" }

// bp2IsKCP: the transports that ride on KCP and read the kcp_* keys.
func bp2IsKCP(tr string) bool { return tr == "kcp" || tr == "pck" || tr == "xdi" }

// bp2Tuning is what v2's own setup writes for a preset (internal/manage/tunnelspec/preset.go
// of v2.0.0). In BackPack the preset key is only a label — the engine reads the values — so
// they are written out here; leaving them out would run every preset on the engine's defaults.
func bp2Tuning(preset, tr string) (common, server, client string, err error) {
	type tune struct {
		keepalive, heartbeat, channel, pool, muxCon, frame, recv, stream int
		aggressive                                                       bool
		kcpWnd, parity, kcpInterval                                      int
		ackNoDelay                                                       bool
	}
	var t tune
	switch preset {
	case "balance":
		t = tune{75, 40, 2048, 4, 4, 32768, 4 << 20, 256 << 10, false, 512, 2, 10, true}
	case "turbo":
		t = tune{75, 40, 4096, 8, 8, 32768, 16 << 20, 2 << 20, false, 1024, 3, 10, true}
	case "aggressive":
		t = tune{60, 25, 8192, 16, 16, 65535, 32 << 20, 16 << 20, true, 2048, 4, 10, true}
	case "throughput":
		if tr != "kcp" {
			return "", "", "", fmt.Errorf("the throughput preset is for the kcp transport only — pick turbo or aggressive for %s", tr)
		}
		t = tune{75, 40, 8192, 16, 8, 65535, 64 << 20, 32 << 20, false, 4096, 1, 20, false}
	default:
		return "", "", "", fmt.Errorf("unknown BackPack preset %q", preset)
	}
	// a plain transport spends one pooled connection per user connection, a mux one a session
	if !bp2IsMux(tr) {
		switch preset {
		case "turbo":
			t.pool = 16
		case "aggressive":
			t.pool = 32
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "nodelay = true\nkeepalive_period = %d\nmux_version = 2\nmux_framesize = %d\nmux_recievebuffer = %d\nmux_streambuffer = %d\n",
		t.keepalive, t.frame, t.recv, t.stream)
	if bp2IsKCP(tr) {
		fmt.Fprintf(&b, "kcp_mtu = 1250\nkcp_nodelay = 1\nkcp_interval = %d\nkcp_resend = 2\nkcp_nocongestion = 1\nkcp_acknodelay = %v\nkcp_sndwnd = %d\nkcp_rcvwnd = %d\nkcp_datashards = 10\nkcp_parityshards = %d\n",
			t.kcpInterval, t.ackNoDelay, t.kcpWnd, t.kcpWnd, t.parity)
	}
	server = fmt.Sprintf("heartbeat = %d\nchannel_size = %d\nmux_con = %d\n", t.heartbeat, t.channel, t.muxCon)
	client = fmt.Sprintf("connection_pool = %d\naggressive_pool = %v\n", t.pool, t.aggressive)
	return b.String(), server, client, nil
}

var bp2PresetField = Field{Key: "preset", Label: "Preset", Type: "select", Default: "turbo", Options: []string{"balance", "turbo", "aggressive", "throughput"},
	Help: "balance = light on CPU, turbo = the tuned default, aggressive = more pool and windows (more CPU), throughput = kcp only"}

var methodBackpack2Reverse = &Method{
	ID:       "bp2_reverse",
	Title:    "BackPack v2 reverse",
	Desc:     "BackPack v2.0.0 reverse tunnel (its own binary, beside v1). Both ends prove the token (v1 sent it as it is on the plain transports), a larger pool on tcp/ws, and kcp / pck / xdi no longer fill the path's queue. Iran listens, foreign dials.",
	Families: []string{"v4", "v6"},
	Encrypt:  "stealth/TLS/token",
	Fields: []Field{
		{Key: "transport", Label: "Transport", Type: "select", Default: "stealth", Options: bp2ReverseTransports},
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		bp2PresetField,
		{Key: "accept_udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "needed for UDP services (Hysteria, WireGuard, QUIC)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		return bp2ReverseBuild(c, c.Opt("transport"))
	},
}

// The reverse TCP + PCK transport as a method of its own, so the benchmark measures it next
// to the v1 PCK recipes: it is the transport v2 changed most (window control, pacing).
var methodBackpack2RPck = &Method{
	ID:       "bp2_rpck",
	Title:    "BackPack v2 TCP + PCK (reverse)",
	Desc:     "BackPack v2.0.0 reverse tunnel over pck: KCP with error correction inside TCP-looking raw packets, with v2's window control and pacing (v1 filled the path's queue). Made for lossy paths. IPv4 only. Iran listens, foreign dials.",
	Families: []string{"v4"},
	Encrypt:  "token",
	Fields: []Field{
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "preset", Label: "Preset", Type: "select", Default: "turbo", Options: []string{"balance", "turbo", "aggressive"}},
		{Key: "accept_udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "needed for UDP services (Hysteria, WireGuard, QUIC)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		return bp2ReverseBuild(c, "pck")
	},
}

func bp2ReverseBuild(c *buildCtx, tr string) (ir, kh SidePlan, err error) {
	if !inList(bp2ReverseTransports, tr) {
		return ir, kh, fmt.Errorf("unknown BackPack v2 transport %q", tr)
	}
	if c.T.Family == "v6" && (tr == "pck" || tr == "xdi") {
		return ir, kh, fmt.Errorf("BackPack %s is IPv4-only — pick another transport for an IPv6 tunnel", tr)
	}
	common, server, client, err := bp2Tuning(c.Opt("preset"), tr)
	if err != nil {
		return ir, kh, err
	}
	tp := portOr(c.Opt("tunnel_port"), c.D.BasePort)
	tok := c.T.secret("bp2-token")
	// peer_auth: both ends are v2, so the handshake of before v2.0.0 (the token in the
	// clear) is refused from the first connection, not only after the first good one
	irToml := fmt.Sprintf(`[server]
bind_addr = "%s:%s"
transport = "%s"
token = "%s"
peer_auth = "required"
preset = "%s"
log_level = "info"
skip_optz = true
sniffer = false
web_port = 0
accept_udp = %v
%s%sports = [%s]
`, bracket(ipAny(c.T.Family)), tp, tr, tok, c.Opt("preset"), c.OptB("accept_udp"), common, server, portsTOML(c.T.Ports))
	khToml := fmt.Sprintf(`[client]
remote_addr = "%s:%s"
transport = "%s"
token = "%s"
peer_auth = "required"
preset = "%s"
log_level = "info"
skip_optz = true
sniffer = false
web_port = 0
retry_interval = 3
dial_timeout = 10
%s%s`, bracket(c.D.IRPub), tp, tr, tok, c.Opt("preset"), common, client)
	ir, kh = backpack2Plans(c, irToml, khToml)
	return ir, kh, nil
}

var methodBackpack2Pck = &Method{
	ID:       "bp2_pck",
	Title:    "BackPack v2 PCK direct (KCP)",
	Desc:     "BackPack v2.0.0 direct PCK: a port forwarder over KCP inside crafted TCP segments (a port of paqet, with a window control of its own). Iran dials the foreign server, so Iran needs no open inbound port. Encrypted with the token. IPv4 only; carries ports, nothing routed.",
	Families: []string{"v4"},
	Encrypt:  "KCP (AES, token)",
	Fields: []Field{
		{Key: "port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel; nothing else may listen on it on the foreign server"},
		{Key: "preset", Label: "Preset", Type: "select", Default: "turbo", Options: []string{"balance", "turbo", "aggressive"},
			Help: "balance = 1 KCP session, turbo = 2 (default), aggressive = 4 with larger windows (long, lossy routes; slower than turbo on a clean one)"},
		{Key: "conns", Label: "KCP sessions", Type: "number", Default: "", Help: "blank = the preset's; 1-16, each its own TCP-looking flow"},
		{Key: "accept_udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "needed for UDP services (Hysteria, WireGuard, QUIC)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		if c.T.Family == "v6" {
			return ir, kh, fmt.Errorf("BackPack PCK is IPv4-only — its segments are IPv4")
		}
		preset := c.Opt("preset")
		if !inList([]string{"balance", "turbo", "aggressive"}, preset) {
			return ir, kh, fmt.Errorf("unknown BackPack PCK preset %q", preset)
		}
		conns := ""
		if v := strings.TrimSpace(c.Opt("conns")); v != "" {
			n, cerr := strconv.Atoi(v)
			if cerr != nil || n < 1 || n > 16 {
				return ir, kh, fmt.Errorf("KCP sessions must be a number from 1 to 16, not %q", v)
			}
			conns = fmt.Sprintf("pck_conns = %d\n", n)
		}
		port := portOr(c.Opt("port"), c.D.BasePort)
		tok := c.T.secret("bp2-pck-token")
		// here the preset is read by its name: direct PCK takes its sessions, KCP mode and
		// windows from it, and pck_* keys override them one by one
		irToml := fmt.Sprintf(`[l3]
mode = "dial"
addr = "%s:%s"
token = "%s"
carrier = "pck"
preset = "%s"
%saccept_udp = %v
ports = [%s]
`, c.D.KHPub, port, tok, preset, conns, c.OptB("accept_udp"), portsTOML(c.T.Ports))
		khToml := fmt.Sprintf(`[l3]
mode = "listen"
addr = "0.0.0.0:%s"
token = "%s"
carrier = "pck"
preset = "%s"
%s`, port, tok, preset, conns)
		ir, kh = backpack2Plans(c, irToml, khToml)
		return ir, kh, nil
	},
}

// backpack2Plans is backpackPlans on the v2 binary: one config per tunnel (BackPack names a
// tunnel after its file and keeps its metrics and its .peer note beside it), checked before
// the unit starts so a refused option is reported by name instead of a crash loop.
func backpack2Plans(c *buildCtx, irToml, khToml string) (SidePlan, SidePlan) {
	cfg := tunnelDir(c.T) + "/tp-" + c.T.ID + ".toml"
	mk := func(toml, side string) SidePlan {
		return SidePlan{Files: map[string]FileSpec{cfg: {Content: []byte(toml), Mode: 0o600}}, Artifacts: []Artifact{artBackpack2(c.Set)},
			Setup: "mkdir -p /etc/backpack\nif ! out=$(" + backpack2Bin + " check -c " + cfg + " 2>&1); then echo \"$out\" | tail -5; exit 1; fi\n",
			Unit:  Unit{Desc: "BackPack v2 " + side + " " + c.T.Name, ExecStart: backpack2Bin + " -c " + cfg}}
	}
	return mk(irToml, "Iran"), mk(khToml, "foreign")
}
