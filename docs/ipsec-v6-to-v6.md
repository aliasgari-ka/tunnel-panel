# IPsec IPv6 ↔ IPv6 (strongSwan, IKEv2, route-based XFRM interface)

Encrypted kernel tunnel between two native-IPv6 servers, carrying private IPv4 (and/or v6) inside.
Outer: ESP over IPv6 (proto 50) or ESP-in-UDP 4500 (forced encapsulation, survives proto-50 filtering).

```
IR6=2a01:aaaa::10   # Iran
KH6=2a01:bbbb::20   # foreign
PSK=$(openssl rand -base64 32)   # same on both sides
```

## 1. Install
```bash
apt update && apt install -y strongswan-swanctl charon-systemd strongswan-pki libcharon-extra-plugins
systemctl enable --now strongswan     # unit name on Debian/Ubuntu (charon-systemd)
```

## 2. XFRM interface (route-based; one per peer)
```bash
# both sides
ip link add ipsec0 type xfrm dev eth0 if_id 42
ip link set ipsec0 mtu 1400 up
# IR
ip addr add 10.88.0.1/30 dev ipsec0
# KH
ip addr add 10.88.0.2/30 dev ipsec0
```

## 3. swanctl config

`/etc/swanctl/conf.d/tun.conf` on **IR** (on KH swap local_addrs/remote_addrs and ids):
```conf
connections {
  ir-kh {
    version = 2
    local_addrs  = 2a01:aaaa::10
    remote_addrs = 2a01:bbbb::20
    encap = yes                  # force UDP/4500 (helps if ESP proto 50 is blocked/throttled)
    mobike = no
    dpd_delay = 10s
    keyingtries = 0              # retry forever
    proposals = aes256gcm16-prfsha256-x25519,chacha20poly1305-prfsha256-x25519
    if_id_in = 42
    if_id_out = 42
    local  { auth = psk  id = ir.tun }
    remote { auth = psk  id = kh.tun }
    children {
      net {
        local_ts  = 0.0.0.0/0,::/0
        remote_ts = 0.0.0.0/0,::/0
        esp_proposals = aes256gcm16-x25519,chacha20poly1305-x25519
        dpd_action = restart
        start_action = start     # use "trap" or "none" on the passive side if desired
        close_action = start
        rekey_time = 1h
      }
    }
  }
}
secrets {
  ike-1 { id-1 = ir.tun  id-2 = kh.tun  secret = "PUT_PSK_HERE" }
}
```
Load: `swanctl --load-all && swanctl --initiate --child net` then `swanctl --list-sas`.

Because traffic selectors are 0/0 and routing is by interface (`if_id`), only what you route into `ipsec0` gets encrypted — no policy loops, outer v6 traffic is untouched.

## 4. Test
```bash
ping 10.88.0.2           # from IR
ip -s xfrm state         # counters
tcpdump -ni eth0 'udp port 4500 or esp'
```

## 5. Port forwarding on IR into the tunnel
```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.88.0.2:443
iptables -t nat -A POSTROUTING -o ipsec0 -j MASQUERADE
iptables -t mangle -A FORWARD -o ipsec0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1340
```

## 6. Persistence
`/etc/systemd/system/xfrm-ipsec0.service`:
```ini
[Unit]
Description=XFRM interface ipsec0
Before=strongswan.service
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip link add ipsec0 type xfrm dev eth0 if_id 42; ip link set ipsec0 mtu 1400 up; ip addr add 10.88.0.1/30 dev ipsec0'
ExecStop=/sbin/ip link del ipsec0
[Install]
WantedBy=multi-user.target
```

## 7. Variant: IPsec transport mode protecting ip6gre (GRE-over-IPsec)
Useful when you need multicast/OSPF or an existing GRE6 setup (Golden-GRE style):
```conf
children { gre { mode = transport
                 local_ts  = 2a01:aaaa::10[gre]
                 remote_ts = 2a01:bbbb::20[gre]
                 esp_proposals = aes128gcm16-x25519
                 start_action = start } }
```
(no if_id; policy-based). Then build ip6gre as in direct-v6-to-v6.md, MTU ≈ 1380.

## 8. MTU math (ESP-in-UDP over IPv6)
40 (IPv6) + 8 (UDP) + 8 (ESP hdr) + 8 (GCM IV) + 16 (ICV) + ≤3 pad + 2 trailer ≈ 85 B → inner 1415 max; use 1400.

## 9. Firewall
Allow on both: UDP 500, UDP 4500 (and proto 50 if encap=no) from the peer's v6 only.
```bash
ip6tables -A INPUT -s $PEER6 -p udp -m multiport --dports 500,4500 -j ACCEPT
```

## 10. Caveats
- IPsec/IKE has a very recognizable fingerprint; Iranian DPI often throttles or blocks IKE. If so, fall back to UDP/TCP obfuscated tunnels (Backhaul / BackPack / FRP) and keep IPsec only for clean links.
- Alternative lighter crypto tunnel over v6: WireGuard (`Endpoint = [KH6]:51820`) — same xfrm-free route-based design, simpler, but also fingerprintable.
- Debug: `journalctl -u strongswan -f`, `swanctl --log`.
