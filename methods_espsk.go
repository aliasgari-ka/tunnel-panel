package main

import "fmt"

func init() { register(methodESPStaticKey) }

// IPsec with a static key (raw ESP, no IKE). strongSwan (the ipsec6 method) needs IKE on
// UDP 500/4500 to exchange keys — but some routes let IPsec's data protocols (ESP proto 50,
// AH proto 51) through while dropping all new TCP/UDP, so IKE can't reach and strongSwan
// never comes up. This method skips IKE: the panel generates the keys once (stored per
// tunnel) and both ends install the ESP SAs with `ip xfrm`. The data path is raw ESP
// (proto 50), the same protocol that passes, so it works where IKE-based IPsec cannot.
// Route-based XFRM interface like ipsec6, carrying private IPv4 for port forwarding.
var methodESPStaticKey = &Method{
	ID:       "espsk",
	Title:    "IPsec static-key (ESP)",
	Desc:     "Encrypted ESP tunnel with a pre-shared static key — no IKE, no UDP. For routes that pass ESP (protocol 50) but drop the UDP that strongSwan's key exchange needs. AES-GCM, route-based XFRM interface carrying private IPv4.",
	Families: []string{"v4", "v6"},
	Encrypt:  "AES-GCM",
	Fields: []Field{
		{Key: "mtu", Label: "Tunnel MTU", Type: "number", Default: "1400"},
	},
	Build: func(c *buildCtx) (ir, kh SidePlan, err error) {
		d := c.D
		// AES-GCM-128 keying material: 16-byte key + 4-byte salt = 20 bytes = 40 hex.
		// secret() gives 48 hex (24 bytes); take 40. One key per direction.
		k1 := c.T.secret("espsk-a")[:40] // foreign → Iran
		k2 := c.T.secret("espsk-b")[:40] // Iran → foreign
		spiA := fmt.Sprintf("0x%x", 0x10000+d.Idx)
		spiB := fmt.Sprintf("0x%x", 0x20000+d.Idx)
		rid := d.IfID

		// the two ESP SAs, defined the same on both hosts (by src/dst/spi)
		states := fmt.Sprintf(
			"ip xfrm state add src %[1]s dst %[2]s proto esp spi %[3]s reqid %[5]d mode tunnel aead 'rfc4106(gcm(aes))' 0x%[7]s 128 if_id %[6]d\n"+
				"ip xfrm state add src %[2]s dst %[1]s proto esp spi %[4]s reqid %[5]d mode tunnel aead 'rfc4106(gcm(aes))' 0x%[8]s 128 if_id %[6]d\n",
			d.KHPub, d.IRPub, spiA, spiB, rid, d.IfID, k1, k2)

		// remove our own SAs and policies (by exact spi / selector+if_id) — leaves any other
		// IPsec on the host alone. Run before adding (re-apply/renew) and on teardown.
		clear := fmt.Sprintf(
			"ip xfrm state deleteall src %[1]s dst %[2]s proto esp spi %[3]s 2>/dev/null || true\n"+
				"ip xfrm state deleteall src %[2]s dst %[1]s proto esp spi %[4]s 2>/dev/null || true\n"+
				"for dir in out in fwd; do ip xfrm policy delete dir $dir src 0.0.0.0/0 dst 0.0.0.0/0 if_id %[5]d 2>/dev/null || true; done\n",
			d.KHPub, d.IRPub, spiA, spiB, d.IfID)

		up := func(self, peer string) string {
			s := clear
			// the XFRM interface hangs off the device towards the peer (works for v4 and v6)
			s += fmt.Sprintf(`dev=$(ip -o route get %[2]s 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
[ -n "$dev" ] || dev=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$dev" ] || { echo "no route to %[2]s"; exit 1; }
ip link add %[1]s type xfrm dev $dev if_id %[3]d
ip link set %[1]s mtu %[4]s up
`, d.Iface, peer, d.IfID, c.Opt("mtu"))
			s += states
			// policies: direction by self/peer, matched to the interface by if_id
			s += fmt.Sprintf(
				"ip xfrm policy add dir out src 0.0.0.0/0 dst 0.0.0.0/0 if_id %[3]d tmpl src %[1]s dst %[2]s proto esp mode tunnel reqid %[4]d\n"+
					"ip xfrm policy add dir in  src 0.0.0.0/0 dst 0.0.0.0/0 if_id %[3]d tmpl src %[2]s dst %[1]s proto esp mode tunnel reqid %[4]d\n"+
					"ip xfrm policy add dir fwd src 0.0.0.0/0 dst 0.0.0.0/0 if_id %[3]d tmpl src %[2]s dst %[1]s proto esp mode tunnel reqid %[4]d\n",
				self, peer, d.IfID, rid)
			return s
		}
		ir, kh = kernelTunnel(c, "IPsec static-key "+c.T.Name, up, clear)
		return ir, kh, nil
	},
}
