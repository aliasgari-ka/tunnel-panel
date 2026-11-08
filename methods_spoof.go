package main

import (
	"fmt"
	"strconv"
	"strings"
)

func init() { register(methodSpoofTunnel) }

// spoof-tunnel (ParsaKSH/spoof-tunnel) is a stateless UDP/raw pipe between two hosts that
// forge each other's source IP, to cross a whitelist-style L3 firewall. Iran = "local"
// (users connect to its listen port), foreign = "remote" (delivers to a local service).
// IPv4 only, needs CAP_NET_RAW (runs as root), single forwarded port per tunnel.
var methodSpoofTunnel = &Method{
	ID:       "spoof",
	Title:    "Spoof-Tunnel (raw IP)",
	Desc:     "Stateless raw pipe using mutual source-IP spoofing. Needs both providers to allow spoofed egress (no BCP38). Plaintext — put an encrypted protocol inside. IPv4 only, one port per tunnel.",
	Families: []string{"v4"},
	Encrypt:  "none (spoofed)",
	Fields: []Field{
		{Key: "spoof_ip", Label: "Iran forged source IP", Type: "text", Default: "", Help: "a source IP the Iran route lets out"},
		{Key: "peer_spoof_ip", Label: "Foreign forged source IP", Type: "text", Default: "", Help: "a source IP the foreign route lets out"},
		{Key: "send_transport", Label: "Send transport", Type: "select", Default: "tcp", Options: []string{"tcp", "udp", "icmp", "icmpv6"}},
		{Key: "recv_transport", Label: "Receive transport", Type: "select", Default: "udp", Options: []string{"tcp", "udp", "icmp", "icmpv6"}},
		{Key: "xdp_interface", Label: "XDP interface", Type: "text", Default: "", Help: "leave blank on a VPS (raw-socket fallback is used)"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		// a single forwarded port: users connect to its listen side on Iran, the foreign
		// side delivers to its destination ("8080=80" → 127.0.0.1:80, not :8080)
		port, dst, err := spoofPorts(c.T.Ports)
		if err != nil {
			return SidePlan{}, SidePlan{}, err
		}
		remotePort := d.BasePort   // local.remote_port == remote.listen_port
		recvPort := d.BasePort + 1 // remote.client_port == local.recv_port
		spoofA := c.Opt("spoof_ip")
		spoofB := c.Opt("peer_spoof_ip")
		send, recv := c.Opt("send_transport"), c.Opt("recv_transport")
		xdp := c.Opt("xdp_interface")
		if spoofA == "" || spoofB == "" {
			return SidePlan{}, SidePlan{}, fmt.Errorf("Spoof-Tunnel needs both forged source IPs — use the project's `spoof tester` to find addresses your routes allow, then set them in the method options")
		}
		xdpField := ""
		if xdp != "" {
			xdpField = fmt.Sprintf(",\n  \"xdp_interface\": %q", xdp)
		}

		// Iran = local: users connect to listen; traffic is piped to the foreign host.
		irCfg := fmt.Sprintf(`{
  "mode": "local",
  "listen": "0.0.0.0:%s",
  "remote": %q,
  "remote_port": %d,
  "recv_port": %d,
  "spoof_ip": %q,
  "spoof_port": %s,
  "peer_spoof_ip": %q,
  "send_transport": %q,
  "recv_transport": %q%s
}
`, port, d.KHPub, remotePort, recvPort, spoofA, port, spoofB, send, recv, xdpField)

		// Foreign = remote: delivers to the local service on the mapped port, mirrored transports.
		khCfg := fmt.Sprintf(`{
  "mode": "remote",
  "listen_port": %d,
  "forward": "127.0.0.1:%s",
  "client_ip": %q,
  "client_port": %d,
  "spoof_ip": %q,
  "spoof_port": %d,
  "peer_spoof_ip": %q,
  "send_transport": %q,
  "recv_transport": %q%s
}
`, remotePort, dst, d.IRPub, recvPort, spoofB, remotePort, spoofA, recv, send, xdpField)

		bin := "/opt/spoof-tunnel/spoof"
		dir := tunnelDir(c.T)
		irPath, khPath := dir+"/spoof.json", dir+"/spoof.json"
		art := Artifact{Name: "spoof-tunnel-latest", Dest: bin, Mode: 0o755, Fetch: fmt.Sprintf(`
VER=$(curl -fsSLI -o /dev/null -w '%%{url_effective}' https://github.com/ParsaKSH/spoof-tunnel/releases/latest | sed 's#.*/tag/##')
[ -n "$VER" ] || VER=v3.1.0
curl -fL --retry 3 -o "$OUT" "%shttps://github.com/ParsaKSH/spoof-tunnel/releases/download/${VER}/spoof-linux-${ARCH}"`, c.Set.GitHubProxy)}

		mk := func(cfg, path, side string) SidePlan {
			return SidePlan{
				Files:     map[string]FileSpec{path: {Content: []byte(cfg), Mode: 0o600}},
				Artifacts: []Artifact{art},
				Setup:     sysctlBBR,
				Unit:      Unit{Desc: "Spoof-Tunnel " + side + " " + c.T.Name, ExecStart: bin + " run -c " + path},
			}
		}
		return mk(irCfg, irPath, "Iran"), mk(khCfg, khPath, "foreign"), nil
	},
}

// spoofPorts returns the one listen and destination port of a Spoof-Tunnel tunnel (443
// when none is set). The pipe forwards exactly one port, so a list or a range is an error
// instead of silently using only its first port.
func spoofPorts(ports string) (listen, dst string, err error) {
	ps := splitPorts(ports)
	if len(ps) == 0 {
		return "443", "443", nil
	}
	if len(ps) > 1 || strings.Contains(ps[0].listen, "-") || strings.Contains(ps[0].dst, "-") {
		return "", "", fmt.Errorf("Spoof-Tunnel forwards a single port — set one port (or one mapping like 8080=80), not %q; use another tunnel for more ports", ports)
	}
	listen, dst = ps[0].listen, ps[0].dst
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		listen = listen[i+1:] // "0.0.0.0:443" style binds: spoof listens on all addresses
	}
	if i := strings.LastIndex(dst, ":"); i >= 0 {
		dst = dst[i+1:]
	}
	for _, v := range []string{listen, dst} {
		if n, e := strconv.Atoi(v); e != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("Spoof-Tunnel port %q is not a port number", v)
		}
	}
	return listen, dst, nil
}
