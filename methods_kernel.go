package main

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	register(methodDirectV6)
	register(methodIPsecV6)
	register(methodGRE)
}

func fwdTag(d derived) string { return fmt.Sprintf("tp%d", d.Idx) }

// localAddr sets $TPL to the address a kernel tunnel uses as its local end: the server's
// public address when it is on the server, else (IPv4 behind 1:1 NAT) the source the
// server uses towards the peer. An IPv6 address the server doesn't have is a config error:
// the peer would get packets from another address and drop them all.
func localAddr(self, peer string) string {
	if strings.Contains(self, ":") {
		return fmt.Sprintf(`TPL=%[1]s
if ! ip -6 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qxF %[1]s; then
  echo "IPv6 %[1]s is not on this server (it has: $(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')) — correct the server's IPv6 on the Servers page, or clear it and run Test connection"
  exit 1
fi
`, self)
	}
	return fmt.Sprintf(`TPL=%[1]s
if ! ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qxF %[1]s; then
  TPL=$(ip -4 route get %[2]s 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
  [ -n "$TPL" ] || { echo "no IPv4 route to %[2]s"; exit 1; }
  echo "note: %[1]s is not on this server (NAT) — the tunnel's local end is $TPL"
fi
`, self, peer)
}

// kernelTunnel builds the two oneshot plans for a kernel tunnel interface.
// ifaceUp creates the interface on one host given (selfPub, peerPub).
// Iran (the entry point users hit) also gets the port-forward rules.
func kernelTunnel(c *buildCtx, desc string, ifaceUp func(selfPub, peerPub string) string, extraDown string) (SidePlan, SidePlan) {
	d := c.D
	addrs := func(v4, v6 string) string {
		return fmt.Sprintf("ip addr add %s/30 dev %s\nip -6 addr add %s/64 dev %s 2>/dev/null || true\n", v4, d.Iface, v6, d.Iface)
	}
	del := fmt.Sprintf("ip link del %s 2>/dev/null || true\n", d.Iface)
	// without set -e the unit would report "active" even when the interface is missing
	check := fmt.Sprintf("ip link show %[1]s >/dev/null 2>&1 || { echo \"could not create interface %[1]s (kernel module missing, or the addresses are wrong?)\"; exit 1; }\n", d.Iface)
	irUp := sysctlBBR + del + ifaceUp(d.IRPub, d.KHPub) + check + addrs(d.IRv4, d.IRv6) +
		portForwardV4(c.T.Ports, d.KHv4, d.Iface, fwdTag(d))
	irDown := portForwardDownV4(fwdTag(d)) + extraDown + del
	khUp := sysctlBBR + del + ifaceUp(d.KHPub, d.IRPub) + check + addrs(d.KHv4, d.KHv6)
	khDown := extraDown + del
	irF, irU := scriptPair(c.T, desc+" (Iran)", irUp, irDown)
	khF, khU := scriptPair(c.T, desc+" (foreign)", khUp, khDown)
	return SidePlan{Files: irF, Unit: irU}, SidePlan{Files: khF, Unit: khU}
}

// ---- Direct v6<->v6 via ip6gre (kernel, no daemon) ----

var methodDirectV6 = &Method{
	ID:       "direct6",
	Title:    "Direct v6 (ip6gre)",
	Desc:     "Kernel ip6gre tunnel between two native-IPv6 servers. Lowest overhead, no daemon. Unencrypted. Carrier \"udp\" puts the GRE packets inside UDP for paths that drop protocol 47.",
	Families: []string{"v6"},
	Encrypt:  "none",
	Fields: []Field{
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1420"},
		{Key: "carrier", Label: "Carrier (udp = GRE inside UDP, when GRE/protocol 47 is filtered)", Type: "select", Default: "gre", Options: []string{"gre", "udp"}},
		{Key: "udpport", Label: "UDP port (carrier udp; blank = per-tunnel default)", Type: "number", Default: ""},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		encap, extraDown := "", ""
		port := d.BasePort + 3
		if p := c.Opt("udpport"); p != "" {
			if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
				return ir, kh, fmt.Errorf("Direct v6: UDP port must be 1..65535")
			}
		}
		if c.Opt("carrier") == "udp" {
			// FOU over IPv6: the kernel listens on the UDP port and hands what arrives to ip6gre
			encap = fmt.Sprintf(" encap fou encap-sport auto encap-dport %d", port)
			extraDown = fmt.Sprintf("ip fou del port %d -6 2>/dev/null || true\n", port)
		}
		up := func(self, peer string) string {
			s := localAddr(self, peer)
			if encap != "" {
				s += fmt.Sprintf(`modprobe fou6 2>/dev/null || modprobe fou 2>/dev/null || true
ip fou del port %[1]d -6 2>/dev/null || true
ip fou add port %[1]d ipproto 47 -6 || { echo "this kernel can't carry GRE inside UDP over IPv6 (fou6 module missing) — use carrier gre"; exit 1; }
`, port)
			}
			return s + fmt.Sprintf("ip link add %s type ip6gre local $TPL remote %s ttl 255 key %d encaplimit none%s\nip link set %s mtu %s up\n",
				d.Iface, peer, d.GREKey, encap, d.Iface, c.Opt("mtu"))
		}
		ir, kh = kernelTunnel(c, "ip6gre "+c.T.Name, up, extraDown)
		return ir, kh, nil
	},
}

// ---- Plain GRE (gre over v4, ip6gre over v6) ----

var methodGRE = &Method{
	ID:       "gre",
	Title:    "Plain GRE",
	Desc:     "Kernel GRE over IPv4, or ip6gre over IPv6. Simple and fast, unencrypted. Needs protocol 47 open.",
	Families: []string{"v4", "v6"},
	Encrypt:  "none",
	Fields: []Field{
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1436"},
	},
	// pings pass but bulk data stalls on some routes (a smaller MTU somewhere on the way that
	// drops instead of fragmenting, seen live on netherlands-iran): a lower MTU gets through
	Alts: func(string) []map[string]string {
		return []map[string]string{{"mtu": "1400"}, {"mtu": "1280"}}
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		typ, extra := "gre", ""
		if c.T.Family == "v6" {
			typ, extra = "ip6gre", " encaplimit none"
		}
		up := func(self, peer string) string {
			return localAddr(self, peer) + fmt.Sprintf("ip link add %s type %s local $TPL remote %s ttl 255 key %d%s\nip link set %s mtu %s up\n",
				d.Iface, typ, peer, d.GREKey, extra, d.Iface, c.Opt("mtu"))
		}
		ir, kh = kernelTunnel(c, "GRE "+c.T.Name, up, "")
		return ir, kh, nil
	},
}

// ---- IPsec via strongSwan + XFRM interface ----

var methodIPsecV6 = &Method{
	ID:       "ipsec6",
	Title:    "IPsec (strongSwan)",
	Desc:     "Encrypted IKEv2 tunnel (ESP-in-UDP/4500), route-based XFRM interface. Works over IPv6 or IPv4; carries private IPv4 for port forwarding.",
	Families: []string{"v6", "v4"},
	Encrypt:  "AES-GCM",
	Fields: []Field{
		{Key: "mtu", Label: "Tunnel MTU", Type: "number", Default: "1400"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		psk := c.T.secret("ipsec-psk")
		confPath := fmt.Sprintf("/etc/swanctl/conf.d/tp%d.conf", d.Idx)
		conn := fmt.Sprintf("tp%d", d.Idx)
		// Iran initiates and re-initiates; the foreign side only answers, so exactly one
		// IKE SA exists (both sides starting gave two, which collide on rekey)
		conf := func(localPub, remotePub, localID, remoteID string, initiator bool) FileSpec {
			start, dpd, closeA := "start", "restart", "start"
			if !initiator {
				start, dpd, closeA = "none", "clear", "none"
			}
			return FileSpec{Mode: 0o600, Content: []byte(fmt.Sprintf(`connections {
  %[1]s {
    version = 2
    local_addrs = %[2]s
    remote_addrs = %[3]s
    encap = yes
    dpd_delay = 15s
    keyingtries = 0
    proposals = aes256gcm16-prfsha256-x25519,chacha20poly1305-prfsha256-x25519,aes256gcm16-prfsha256-ecp256
    if_id_in = %[4]d
    if_id_out = %[4]d
    # one setting per line: swanctl.conf reads a value up to the end of its line
    local {
      auth = psk
      id = %[5]s
    }
    remote {
      auth = psk
      id = %[6]s
    }
    children {
      net {
        local_ts = 0.0.0.0/0,::/0
        remote_ts = 0.0.0.0/0,::/0
        esp_proposals = aes256gcm16-x25519,chacha20poly1305-x25519,aes256gcm16-ecp256
        dpd_action = %[9]s
        start_action = %[7]s
        close_action = %[10]s
        rekey_time = 1h
      }
    }
  }
}
secrets {
  ike-%[1]s {
    id-1 = %[5]s
    id-2 = %[6]s
    secret = "%[8]s"
  }
}
`, conn, localPub, remotePub, d.IfID, localID, remoteID, start, psk, dpd, closeA))}
		}
		setup := `if ! command -v swanctl >/dev/null 2>&1 || { command -v apt-get >/dev/null 2>&1 && ! systemctl cat strongswan.service >/dev/null 2>&1; }; then
  # swanctl + charon-systemd (strongswan.service) is the vici-native daemon we drive
  (apt-get update -qq && apt-get install -y -qq strongswan-swanctl charon-systemd libcharon-extra-plugins) \
  || dnf install -y strongswan || yum install -y strongswan || { echo "could not install strongSwan"; exit 1; }
fi
# configs written by earlier panel versions (several settings on one line) don't load, and
# strongswan.service fails to start while any file in conf.d is broken
for f in /etc/swanctl/conf.d/tp*.conf; do
  if [ -f "$f" ] && grep -qE '[{] *auth = psk +id = ' "$f"; then echo "removing $f (broken config from an earlier version)"; rm -f "$f"; fi
done
` + charonUp + "tp_charon || exit 1\n"
		up := func(self, peer string) string {
			// the XFRM interface hangs off the device towards the peer (works for v4 and v6)
			return localAddr(self, peer) + fmt.Sprintf(`if [ "$TPL" != %[5]s ]; then sed -i "s/local_addrs = %[5]s\$/local_addrs = $TPL/" %[6]s; fi
dev=$(ip -o route get %[7]s 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
[ -n "$dev" ] || dev=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$dev" ] || { echo "no route to %[7]s"; exit 1; }
ip link add %[1]s type xfrm dev $dev if_id %[2]d
ip link set %[1]s mtu %[3]s up
# charon must answer on its vici socket before swanctl can load the connection
%[4]stp_charon || exit 1
if ! swanctl --load-all --noprompt >/tmp/tp-swanctl.log 2>&1; then
  grep -v -e '^usage' -e '^ ' -e '^plugin ' /tmp/tp-swanctl.log | head -4
  exit 1
fi
`, d.Iface, d.IfID, c.Opt("mtu"), charonUp, self, confPath, peer)
		}
		down := fmt.Sprintf("swanctl --terminate --ike %s >/dev/null 2>&1 || true\n", conn)
		ir, kh = kernelTunnel(c, "IPsec "+c.T.Name, up, down)
		ir.Files[confPath] = conf(d.IRPub, d.KHPub, "ir-"+conn, "kh-"+conn, true)
		kh.Files[confPath] = conf(d.KHPub, d.IRPub, "kh-"+conn, "ir-"+conn, false)
		ir.Setup, kh.Setup = setup, setup
		// remove the conf on teardown so swanctl stops the connection
		rm := fmt.Sprintf("rm -f %s; swanctl --load-all >/dev/null 2>&1 || true\n", confPath)
		appendDown(&ir, rm)
		appendDown(&kh, rm)
		return ir, kh, nil
	},
}

// appendDown appends shell to the plan's down.sh.
func appendDown(p *SidePlan, sh string) {
	for path, f := range p.Files {
		if len(path) > 8 && path[len(path)-8:] == "/down.sh" {
			f.Content = append(f.Content, []byte(sh)...)
			p.Files[path] = f
		}
	}
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }

// charonUp defines tp_charon: make sure strongSwan's charon really answers on its vici
// socket. A socket file alone proves nothing — a crashed daemon leaves it behind and
// swanctl then gets "Connection refused". On Debian/Ubuntu, strongswan-starter (ipsec.conf,
// its own charon) and charon-systemd (strongswan.service) fight over UDP 500/4500 and the
// socket when both run, so when charon-systemd is installed the starter is stopped.
const charonUp = `tp_charon() {
  ok() { timeout 5 swanctl --stats >/dev/null 2>&1; }
  ok && return 0
  if systemctl cat strongswan.service >/dev/null 2>&1; then
    svc=strongswan
    if systemctl is-active --quiet strongswan-starter 2>/dev/null; then
      echo "stopping strongswan-starter: it conflicts with charon-systemd (strongswan.service)"
    fi
    systemctl disable --now strongswan-starter >/dev/null 2>&1 || true
    pkill -x charon 2>/dev/null || true
  else
    svc=strongswan-starter
  fi
  systemctl stop $svc >/dev/null 2>&1 || true
  sleep 0.5
  rm -f /var/run/charon.vici /run/charon.vici
  systemctl enable $svc >/dev/null 2>&1 || true
  systemctl restart $svc >/dev/null 2>&1 || true
  for i in $(seq 1 30); do ok && return 0; sleep 0.5; done
  echo "strongSwan (charon) does not answer on its vici socket after restarting $svc. Its log:"
  journalctl -u $svc -n 8 --no-pager -o cat 2>/dev/null | tail -8
  return 1
}
`
