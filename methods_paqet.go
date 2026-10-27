package main

import (
	"fmt"
	"strings"
)

func init() { register(methodPaqet) }

// paqet-plus (LivingG0D/paqet-plus, MIT): KCP over hand-made TCP frames sent on a raw socket,
// past the kernel's TCP stack. Iran runs the client (it listens on the users' ports and
// forwards them), foreign runs the server. Upstream calls it alpha, so the release is pinned
// and its archives checked.
const (
	paqetVersion      = "v1.0.0-alpha.41"
	paqetSHA256amd64  = "894f80c6240deb9772b0447bcc0f179c8f3524c20e3c2b3fea1afa805ec725d8"
	paqetSHA256arm64  = "ebb237d594b40eefff6ae421d6851f3d1310cfecaa7d14af3c3570fc011e41b0"
	paqetBin          = "/opt/paqet-plus-tp/paqet-plus"
	paqetMaxForwarded = 512
)

func artPaqet(set Settings) Artifact {
	return Artifact{Name: "paqet-plus-" + paqetVersion, Dest: paqetBin, Mode: 0o755, Fetch: fmt.Sprintf(`
curl -fL --retry 3 -o pq.tgz "%s"
case "$ARCH" in amd64) want=%s ;; arm64) want=%s ;; *) echo "no pinned paqet-plus checksum for $ARCH"; exit 1 ;; esac
echo "$want  pq.tgz" | sha256sum -c - || { echo "paqet-plus archive checksum mismatch — refusing to install it"; exit 1; }
tar -xzf pq.tgz "paqet-plus_linux_$ARCH"
install -m0755 "paqet-plus_linux_$ARCH" "$OUT"`,
		ghURL(set, "https://github.com/LivingG0D/paqet-plus/releases/download/"+paqetVersion+"/paqet-plus-linux-${ARCH}-"+paqetVersion+".tar.gz"),
		paqetSHA256amd64, paqetSHA256arm64)}
}

var methodPaqet = &Method{
	ID:       "paqet",
	Title:    "Paqet-plus (raw TCP)",
	Desc:     "LivingG0D/paqet-plus " + paqetVersion + " (alpha): encrypted KCP inside hand-made TCP frames on a raw socket, invisible to the kernel's TCP stack and connection tracking. Iran forwards the ports, foreign is the server.",
	Families: []string{"v4", "v6"},
	Encrypt:  "aes-128-gcm",
	Fields: []Field{
		{Key: "port", Label: "Server port", Type: "number", Default: "", Help: "TCP port the foreign side answers on (blank = auto, unique per tunnel)"},
		{Key: "mode", Label: "KCP mode", Type: "select", Default: "normal", Options: []string{"normal", "fast", "fast2", "fast3"},
			Help: "normal measured best on shared paths; fast* react quicker at more overhead"},
		{Key: "conn", Label: "Sessions", Type: "number", Default: "8", Help: "parallel KCP sessions (autoscaled up to twice this)"},
		{Key: "udp", Label: "Forward UDP too", Type: "bool", Default: "false"},
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1250", Help: "lower it if large packets get dropped", Advanced: true},
		{Key: "block", Label: "Cipher", Type: "select", Default: "aes-128-gcm", Options: []string{"aes-128-gcm", "aes", "salsa20", "none"},
			Help: "aes-128-gcm is the only one that also detects tampering", Advanced: true},
		{Key: "fec", Label: "FEC (Reed-Solomon 10+1)", Type: "bool", Default: "false", Help: "for lossy links, at about 10 % more traffic", Advanced: true},
		{Key: "log_level", Label: "Log level", Type: "select", Default: "info", Options: []string{"debug", "info", "warn", "error"}, Advanced: true},
	},
	Build: buildPaqet,
}

func buildPaqet(c *buildCtx) (ir, kh SidePlan, err error) {
	d := c.D
	if d.IRPub == "" || d.KHPub == "" {
		return ir, kh, fmt.Errorf("paqet-plus needs both servers' public %s addresses", famName(c.T.Family))
	}
	port := portOr(c.Opt("port"), d.BasePort)
	pairs, err := expandPortPairs(c.T.Ports, paqetMaxForwarded)
	if err != nil {
		return ir, kh, fmt.Errorf("ports: %v (paqet-plus forwards at most %d)", err, paqetMaxForwarded)
	}
	var fwd strings.Builder
	for _, p := range pairs {
		protos := []string{"tcp"}
		if c.OptB("udp") {
			protos = append(protos, "udp")
		}
		for _, pr := range protos {
			fmt.Fprintf(&fwd, "  - listen: \"0.0.0.0:%s\"\n    target: \"%s:%s\"\n    protocol: \"%s\"\n", p.listen, bracket(p.host), p.dst, pr)
		}
	}
	shards := "0"
	if c.OptB("fec") {
		shards = "10"
	}
	pshard := map[string]string{"0": "0", "10": "1"}[shards]
	transport := fmt.Sprintf(`transport:
  protocol: "kcp"
  conn: %s
  kcp:
    mode: "%s"
    mtu: %s
    key: "%s"
    block: "%s"
    dshard: %s
    pshard: %s
`, c.Opt("conn"), c.Opt("mode"), c.Opt("mtu"), c.T.secret("paqet-key"), c.Opt("block"), shards, pshard)
	// @DEV@ @SRC@ @MAC@ are filled in at start (pre.sh): raw frames go out on the interface
	// towards the other server, from its address, to the next hop's MAC
	addrKey := "ipv4"
	if c.T.Family == "v6" {
		addrKey = "ipv6"
	}
	network := func(localPort string) string {
		return fmt.Sprintf("network:\n  interface: \"@DEV@\"\n  %s:\n    addr: \"@SRC@:%s\"\n    router_mac: \"@MAC@\"\n  pcap:\n    sockbuf: 16777216\n", addrKey, localPort)
	}
	logBlock := fmt.Sprintf("log:\n  level: \"%s\"\n", c.Opt("log_level"))
	irTmpl := "role: \"client\"\n" + logBlock + network("0") + fmt.Sprintf("server:\n  addr: \"%s:%s\"\n", bracket(d.KHPub), port) + transport + "forward:\n" + fwd.String()
	khTmpl := "role: \"server\"\n" + logBlock + network(port) + transport

	dir := tunnelDir(c.T)
	side := func(tmpl, peer, rules string) SidePlan {
		return SidePlan{
			Files: map[string]FileSpec{
				dir + "/paqet.tmpl": {Content: []byte(tmpl), Mode: 0o600},
				dir + "/pq-up.sh":   {Content: []byte(paqetUp(c.T, peer, rules)), Mode: 0o755},
				dir + "/pq-down.sh": {Content: []byte(paqetDown(c.T, rules)), Mode: 0o755},
			},
			Artifacts: []Artifact{artPaqet(c.Set)},
			Setup:     paqetSetup,
			Unit: Unit{Desc: "Paqet-plus " + c.T.Name, ExecStartPre: dir + "/pq-up.sh",
				ExecStart: paqetBin + " run -c " + dir + "/paqet.yaml", ExecStopPost: dir + "/pq-down.sh"},
		}
	}
	// the kernel must neither track nor reset the frames paqet-plus builds: on the server
	// its port, on the client the connection to that port (the client's own port is random)
	khRules := fmt.Sprintf("raw PREROUTING -p tcp --dport %[1]s -j NOTRACK\nraw OUTPUT -p tcp --sport %[1]s -j NOTRACK\nmangle OUTPUT -p tcp --sport %[1]s --tcp-flags RST RST -j DROP", port)
	irRules := fmt.Sprintf("raw PREROUTING -p tcp -s %[2]s --sport %[1]s -j NOTRACK\nraw OUTPUT -p tcp -d %[2]s --dport %[1]s -j NOTRACK\nmangle OUTPUT -p tcp -d %[2]s --dport %[1]s --tcp-flags RST RST -j DROP", port, d.KHPub)
	return side(irTmpl, d.KHPub, irRules), side(khTmpl, d.IRPub, khRules), nil
}

// paqetSetup: the raw path wants big socket buffers (sockbuf 16 MB is capped at rmem_max)
const paqetSetup = `for k in rmem_max wmem_max; do [ "$(cat /proc/sys/net/core/$k 2>/dev/null || echo 0)" -ge 33554432 ] || sysctl -qw net.core.$k=33554432 2>/dev/null || true; done
`

// paqetUp finds the interface, local address and next-hop MAC towards peer, writes the
// config, and adds the firewall rules (tagged with the tunnel, so pq-down removes only them).
func paqetUp(t *Tunnel, peer, rules string) string {
	fam, ipt := "-4", "iptables"
	if t.Family == "v6" {
		fam, ipt = "-6", "ip6tables"
	}
	var add strings.Builder
	for _, r := range strings.Split(rules, "\n") {
		f := strings.SplitN(r, " ", 3) // table chain match...
		fmt.Fprintf(&add, "%[1]s -w -t %[2]s -C %[3]s %[4]s -m comment --comment tp-%[5]s 2>/dev/null || %[1]s -w -t %[2]s -I %[3]s %[4]s -m comment --comment tp-%[5]s\n", ipt, f[0], f[1], f[2], t.ID)
	}
	return fmt.Sprintf(`#!/bin/bash
cd "$(dirname "$0")" || exit 1
peer=%[1]s
field() { awk -v k="$1" '{for (i = 1; i < NF; i++) if ($i == k) {print $(i+1); exit}}'; }
r=$(ip %[2]s -o route get "$peer" 2>/dev/null)
dev=$(field dev <<< "$r"); src=$(field src <<< "$r"); nh=$(field via <<< "$r"); [ -n "$nh" ] || nh=$peer
mac=""
for i in 1 2 3 4 5; do
  [ -n "$dev" ] && mac=$(ip %[2]s neigh show "$nh" dev "$dev" 2>/dev/null | field lladdr)
  [ -n "$mac" ] && break
  ping %[2]s -c 1 -W 1 "$nh" >/dev/null 2>&1 || true
done
if [ -z "$dev" ] || [ -z "$src" ] || [ -z "$mac" ]; then
  echo "paqet-plus: no interface, address or next-hop MAC towards $peer (dev=${dev:-?} src=${src:-?} next hop $nh mac=${mac:-?})" >&2
  exit 1
fi
case "$src" in *:*) src="[$src]" ;; esac
sed -e "s|@DEV@|$dev|" -e "s|@SRC@|$src|" -e "s|@MAC@|$mac|" paqet.tmpl > paqet.yaml.new && chmod 600 paqet.yaml.new && mv paqet.yaml.new paqet.yaml
%[3]sexit 0
`, peer, fam, add.String())
}

func paqetDown(t *Tunnel, rules string) string {
	ipt := "iptables"
	if t.Family == "v6" {
		ipt = "ip6tables"
	}
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	for _, r := range strings.Split(rules, "\n") {
		f := strings.SplitN(r, " ", 3)
		fmt.Fprintf(&b, "while %[1]s -w -t %[2]s -D %[3]s %[4]s -m comment --comment tp-%[5]s 2>/dev/null; do :; done\n", ipt, f[0], f[1], f[2], t.ID)
	}
	b.WriteString("exit 0\n")
	return b.String()
}
