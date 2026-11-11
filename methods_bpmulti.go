package main

import (
	"fmt"
	"strconv"
)

// BackPack multi-link reverse: the fixed BackPack recipes another panel ships as
// standalone kits — wsmux with many parallel links, and pck (TCP-looking raw packets)
// carrying KCP with FEC, in a 3-link and a 6-link "turbo" form — rebuilt on the panel's own BackPack build and plumbing. Iran
// runs [server] on the tunnel port, the foreign server dials it.
//
// "Links" is how many tunnel connections the foreign side keeps open in parallel. The
// kits write it as channel_size on both ends, but in BackPack channel_size is the
// server's accept queue (connections beyond it are dropped) and the client has no such
// key; the client's parallel connections are connection_pool. So links goes to
// connection_pool and the server keeps a queue big enough for a burst of users.
func init() {
	register(methodBackpackMulti)
	register(methodBackpackPckFEC)
	register(methodBackpackPckTurbo)
}

// bpMultiTuning is what both kits write on both ends (mux_con is a server-only key).
const bpMultiTuning = `nodelay = true
keepalive_period = 75
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
mux_session = 1
skip_optz = true
sniffer = false
web_port = 0
log_level = "info"
`

// bpPckKCP is the KCP and FEC tuning of the pck recipe (both ends must match).
const bpPckKCP = `kcp_datashards = 10
kcp_parityshards = 4
kcp_nodelay = 1
kcp_interval = 10
kcp_resend = 2
kcp_nocongestion = 1
kcp_acknodelay = true
kcp_sndwnd = 1024
kcp_rcvwnd = 1024
kcp_mtu = 1350
`

func bpLinksField(def string) Field {
	return Field{Key: "links", Label: "Parallel links", Type: "number", Default: def,
		Help: "tunnel connections the foreign server keeps open at once (1-64)"}
}

var methodBackpackMulti = &Method{
	ID:       "bp_multi",
	Title:    "BackPack WSMux multi-link (reverse)",
	Desc:     "BackPack wsmux (smux over WebSocket) reverse tunnel with many parallel links and fixed mux tuning. Iran listens, foreign dials.",
	Families: []string{"v4", "v6"},
	Encrypt:  "token",
	Fields: []Field{
		bpLinksField("12"),
		{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "accept_udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "needed for UDP services (Hysteria, WireGuard, QUIC)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		return bpMultiBuild(c, "wsmux", 8, "")
	},
}

var methodBackpackPckFEC = bpPckMethod("bp_pckfec", "BackPack PCK + KCP/FEC multi-link (reverse)", 3, 7,
	"BackPack pck reverse tunnel: KCP with forward error correction (10+4) inside TCP-looking raw packets, 3 parallel links. ")

var methodBackpackPckTurbo = bpPckMethod("bp_pckturbo", "BackPack PCK + KCP/FEC turbo (reverse)", 6, 6,
	"The same KCP/FEC pck tunnel with 6 parallel links and 6 mux streams per link, for more throughput. ")

// bpPckMethod is the pck recipe with its link count and mux streams per link. (The turbo
// kit also writes iface = "<foreign IPv4>"; BackPack has no such key outside L3 — pck
// finds its own egress from the route — so it is left out.)
func bpPckMethod(id, title string, links, muxCon int, desc string) *Method {
	return &Method{
		ID:       id,
		Title:    title,
		Desc:     desc + "Made for lossy paths. IPv4 only. Iran listens, foreign dials.",
		Families: []string{"v4"},
		Encrypt:  "token",
		Fields: []Field{
			bpLinksField(strconv.Itoa(links)),
			{Key: "tunnel_port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
			{Key: "accept_udp", Label: "Forward UDP too", Type: "bool", Default: "false", Help: "needed for UDP services (Hysteria, WireGuard, QUIC)"},
		},
		Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
			if c.T.Family == "v6" {
				return ir, kh, fmt.Errorf("BackPack pck is IPv4-only — use BackPack WSMux multi-link for an IPv6 tunnel")
			}
			return bpMultiBuild(c, "pck", muxCon, bpPckKCP)
		},
	}
}

func bpMultiBuild(c *buildCtx, transport string, muxCon int, extra string) (SidePlan, SidePlan, error) {
	links, err := strconv.Atoi(c.Opt("links"))
	if err != nil || links < 1 || links > 64 {
		return SidePlan{}, SidePlan{}, fmt.Errorf("parallel links must be a number from 1 to 64, not %q", c.Opt("links"))
	}
	tp := portOr(c.Opt("tunnel_port"), c.D.BasePort)
	tok := c.T.secret("bp-token")
	irToml := fmt.Sprintf(`[server]
bind_addr = "%s:%s"
transport = "%s"
token = "%s"
heartbeat = 20
mux_con = %d
channel_size = 4096
accept_udp = %v
%s%sports = [%s]
`, bracket(ipAny(c.T.Family)), tp, transport, tok, muxCon, c.OptB("accept_udp"), bpMultiTuning, extra, portsTOML(c.T.Ports))
	khToml := fmt.Sprintf(`[client]
remote_addr = "%s:%s"
transport = "%s"
token = "%s"
connection_pool = %d
retry_interval = 3
dial_timeout = 10
%s%s`, bracket(c.D.IRPub), tp, transport, tok, links, bpMultiTuning, extra)
	return backpackPlans(c, irToml, khToml)
}
