# Direct IPv6 ↔ IPv6 (no userspace tunnel)

Scenario: both servers (IR = Iran relay, KH = foreign/"kharej") have native public IPv6.
Goal: carry traffic between them directly over v6 with kernel-only tunnels — lowest overhead, no daemon.

Variables used below:

```
IR6=2a01:aaaa::10      # Iran public IPv6
KH6=2a01:bbbb::20      # foreign public IPv6
IF=eth0                # WAN interface
```

---

## Option A — Pure forwarding (no tunnel at all)

Client connects to IR; IR NATs to KH's IPv6. Only works when clients reach IR, and IR→KH v6 path is open.

### A1. ip6tables DNAT (kernel, fastest)
```bash
# on IR
sysctl -w net.ipv6.conf.all.forwarding=1
ip6tables -t nat -A PREROUTING  -p tcp --dport 443 -j DNAT --to-destination [$KH6]:443
ip6tables -t nat -A PREROUTING  -p udp --dport 443 -j DNAT --to-destination [$KH6]:443
ip6tables -t nat -A POSTROUTING -d $KH6 -j MASQUERADE
```
IPv4 clients → IPv6 backend cannot be done by DNAT (different families). Use A2.

### A2. Userspace L4 forward v4→v6 (socat / haproxy / gost / realm)
```bash
# socat (simple, one process per port)
socat TCP4-LISTEN:443,fork,reuseaddr TCP6:[$KH6]:443
# haproxy backend line
server kh [$KH6]:443 check
```

---

## Option B — ip6ip6 / ipip6 tunnel (ip6tnl) carrying private IPv4 + IPv6

Mode `any` on ip6tnl carries both IPv4 (ipip6) and IPv6 (ip6ip6) inside an IPv6 outer header (40 B overhead).

```bash
# ---- IR ----
ip -6 tunnel add t6 mode any local $IR6 remote $KH6 ttl 255 encaplimit none
ip link set t6 mtu 1440 up
ip addr add 10.66.0.1/30 dev t6
ip -6 addr add fd66::1/64 dev t6

# ---- KH ----
ip -6 tunnel add t6 mode any local $KH6 remote $IR6 ttl 255 encaplimit none
ip link set t6 mtu 1440 up
ip addr add 10.66.0.2/30 dev t6
ip -6 addr add fd66::2/64 dev t6

ping 10.66.0.2   # from IR
```
`encaplimit none` is important: the default adds an 8-byte Destination-Options header that many providers drop.

## Option C — ip6gre / ip6gretap (GRE over IPv6)

```bash
# IR
ip link add gre6 type ip6gre local $IR6 remote $KH6 ttl 255 encaplimit none
ip link set gre6 mtu 1436 up
ip addr add 10.77.0.1/30 dev gre6
# KH: swap local/remote, address 10.77.0.2/30
```
Overhead 40 (v6) + 4 (GRE) = 44 → MTU 1456 theoretical; 1436–1420 is safer. Add `key 1234` both sides to differentiate multiple tunnels. Some DCs filter protocol 47 — if GRE fails, try Option B (proto 41/4) or a UDP-based tunnel.

### Optional: tunnel IPv4 under v6 when IR has no v6 reachability to clients — irrelevant; tunnel only links the two servers.

---

## Forwarding client ports through the tunnel (both B and C)

```bash
# on IR: forward public port 443 (v4) to KH's tunnel address
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING  -p tcp --dport 443 -j DNAT --to-destination 10.66.0.2:443
iptables -t nat -A PREROUTING  -p udp --dport 443 -j DNAT --to-destination 10.66.0.2:443
iptables -t nat -A POSTROUTING -o t6 -j MASQUERADE
# MSS clamp (avoid PMTU black-holes)
iptables -t mangle -A FORWARD -o t6 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```
Exclude SSH port from DNAT ranges (e.g. `--dport 1:21` + `23:65535` style or `! --dport 22`).

## Persistence (systemd)

`/usr/local/sbin/t6-up.sh` contains the `ip ...` lines; unit:
```ini
# /etc/systemd/system/t6.service
[Unit]
Description=ip6tnl tunnel
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/t6-up.sh
ExecStop=/sbin/ip link del t6
[Install]
WantedBy=multi-user.target
```
Iptables rules: `apt install iptables-persistent && netfilter-persistent save`.

## Sysctl
```
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.conf.all.rp_filter=0
```

## Keep-alive / watchdog (tunnels have no state — detect path loss)
```bash
# cron every minute on IR
ping -c3 -W2 10.66.0.2 >/dev/null || systemctl restart t6
```

## Notes
- No encryption. Iranian DPI sees inner payload in cleartext — combine with an encrypted inner protocol (VLESS/Reality, WireGuard) or use IPsec (see ipsec-v6-to-v6.md).
- Teardown: `ip link del t6` / `ip link del gre6`, flush NAT rules.
- Verify proto reachability: `tcpdump -ni eth0 ip6 and (ip6[6]==41 or ip6[6]==47 or ip6[6]==4)`.
