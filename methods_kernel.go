package main

import "fmt"

func init() {
	register(methodDirectV6)
	register(methodIPsecV6)
	register(methodGRE)
}

func fwdTag(d derived) string { return fmt.Sprintf("tp%d", d.Idx) }

// kernelTunnel builds the two oneshot plans for a kernel tunnel interface.
// ifaceUp creates the interface on one host given (selfPub, peerPub).
// Iran (the entry point users hit) also gets the port-forward rules.
func kernelTunnel(c *buildCtx, desc string, ifaceUp func(selfPub, peerPub string) string, extraDown string) (SidePlan, SidePlan) {
	d := c.D
	addrs := func(v4, v6 string) string {
		return fmt.Sprintf("ip addr add %s/30 dev %s\nip -6 addr add %s/64 dev %s 2>/dev/null || true\n", v4, d.Iface, v6, d.Iface)
	}
	del := fmt.Sprintf("ip link del %s 2>/dev/null || true\n", d.Iface)
	irUp := sysctlBBR + del + ifaceUp(d.IRPub, d.KHPub) + addrs(d.IRv4, d.IRv6) +
		portForwardV4(c.T.Ports, d.KHv4, d.Iface, fwdTag(d))
	irDown := portForwardDownV4(fwdTag(d)) + extraDown + del
	khUp := sysctlBBR + del + ifaceUp(d.KHPub, d.IRPub) + addrs(d.KHv4, d.KHv6)
	khDown := extraDown + del
	irF, irU := scriptPair(c.T, desc+" (Iran)", irUp, irDown)
	khF, khU := scriptPair(c.T, desc+" (foreign)", khUp, khDown)
	return SidePlan{Files: irF, Unit: irU}, SidePlan{Files: khF, Unit: khU}
}

// ---- Direct v6<->v6 via ip6gre (kernel, no daemon) ----

var methodDirectV6 = &Method{
	ID:       "direct6",
	Title:    "Direct v6 (ip6gre)",
	Desc:     "Kernel ip6gre tunnel between two native-IPv6 servers. Lowest overhead, no daemon. Unencrypted.",
	Families: []string{"v6"},
	Encrypt:  "none",
	Fields: []Field{
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1420"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		up := func(self, peer string) string {
			return fmt.Sprintf("ip link add %s type ip6gre local %s remote %s ttl 255 key %d encaplimit none\nip link set %s mtu %s up\n",
				d.Iface, self, peer, d.GREKey, d.Iface, c.Opt("mtu"))
		}
		ir, kh = kernelTunnel(c, "ip6gre "+c.T.Name, up, "")
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
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		typ, extra := "gre", ""
		if c.T.Family == "v6" {
			typ, extra = "ip6gre", " encaplimit none"
		}
		up := func(self, peer string) string {
			return fmt.Sprintf("ip link add %s type %s local %s remote %s ttl 255 key %d%s\nip link set %s mtu %s up\n",
				d.Iface, typ, self, peer, d.GREKey, extra, d.Iface, c.Opt("mtu"))
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
		conf := func(localPub, remotePub, localID, remoteID, start string) FileSpec {
			return FileSpec{Mode: 0o600, Content: []byte(fmt.Sprintf(`connections {
  %[1]s {
    version = 2
    local_addrs = %[2]s
    remote_addrs = %[3]s
    encap = yes
    dpd_delay = 15s
    keyingtries = 0
    proposals = aes256gcm16-prfsha256-x25519,chacha20poly1305-prfsha256-x25519
    if_id_in = %[4]d
    if_id_out = %[4]d
    local  { auth = psk  id = %[5]s }
    remote { auth = psk  id = %[6]s }
    children {
      net {
        local_ts = 0.0.0.0/0,::/0
        remote_ts = 0.0.0.0/0,::/0
        esp_proposals = aes256gcm16-x25519,chacha20poly1305-x25519
        dpd_action = restart
        start_action = %[7]s
        close_action = start
        rekey_time = 1h
      }
    }
  }
}
secrets {
  ike-%[1]s { id-1 = %[5]s  id-2 = %[6]s  secret = "%[8]s" }
}
`, conn, localPub, remotePub, d.IfID, localID, remoteID, start, psk))}
		}
		setup := `if ! command -v swanctl >/dev/null 2>&1 || { command -v apt-get >/dev/null 2>&1 && ! systemctl cat strongswan.service >/dev/null 2>&1; }; then
  # swanctl + charon-systemd (strongswan.service) is the vici-native daemon we drive
  (apt-get update -qq && apt-get install -y -qq strongswan-swanctl charon-systemd libcharon-extra-plugins) \
  || dnf install -y strongswan || yum install -y strongswan || { echo "could not install strongSwan"; exit 1; }
fi
` + charonUp + "tp_charon || exit 1\n"
		up := func(self, peer string) string {
			return fmt.Sprintf(`ip link add %[1]s type xfrm dev $(ip route show default | awk '{print $5; exit}') if_id %[2]d
ip link set %[1]s mtu %[3]s up
# charon must answer on its vici socket before swanctl can load the connection
%[4]stp_charon || exit 1
if ! swanctl --load-all --noprompt >/tmp/tp-swanctl.log 2>&1; then
  grep -v -e '^usage' -e '^ ' /tmp/tp-swanctl.log | head -4
  exit 1
fi
`, d.Iface, d.IfID, c.Opt("mtu"), charonUp)
		}
		down := fmt.Sprintf("swanctl --terminate --ike %s >/dev/null 2>&1 || true\n", conn)
		ir, kh = kernelTunnel(c, "IPsec "+c.T.Name, up, down)
		// Iran initiates; the foreign side waits (trap) so one SA is negotiated.
		ir.Files[confPath] = conf(d.IRPub, d.KHPub, "ir-"+conn, "kh-"+conn, "start")
		kh.Files[confPath] = conf(d.KHPub, d.IRPub, "kh-"+conn, "ir-"+conn, "trap")
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
