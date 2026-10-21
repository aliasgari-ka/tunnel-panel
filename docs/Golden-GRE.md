# Golden-GRE: technical reference

Source analysed: `/home/user/tunnels-kb/sources/Golden-GRE` (upstream `github.com/LivingG0D/Golden-GRE`, Apache-2.0).
Files read in full: `golden-gre.sh`, `install.sh`, `scripts/*.sh`, `systemd/*`, `sysctl/99-golden-gre.conf`,
`relay/golden-gre-relay.c`, `examples/*`, `docs/FILTER.md`, `docs/WireGuard.md`, `tools/xui-set-outbound-address.sh`,
`.github/workflows/ci.yml`, and the relevant parts of `bench/` and `tests/`. `relay/monocypher.c/.h` is a vendored
crypto library (version string `__git__`). Only its primitives are listed here. Nothing was executed.

---

## 1. Purpose

Golden-GRE builds a **real Linux `greN` point-to-point interface between two servers**. The target is the
Iran to "Kharej" (abroad) case. On the measured IPv4 paths, every ordinary tunnel flow (GRE, IPIP, FOU, GUE,
VXLAN, Geneve, WireGuard, plain UDP and TCP) **gets cut after about 6 packets per 5-tuple**. Only ICMP echo
traffic and UDP/53 carrying a well-formed DNS message got through (`docs/FILTER.md`).

To get past that filter, the GRE packets are not put on the wire directly. They go:

```
inner IP pkt -> gre1 (GRE + key) -> FOU/UDP on 127.0.0.1 -> golden-gre-relay -> wire disguise
          (ICMP echo request | ICMP echo reply | DNS query to UDP/53) -> peer relay -> FOU 127.0.0.1 -> gre1
```

With `FACADE=none` there is no relay and no FOU. It is plain GRE (IP proto 47) between the two public IPv4s.

Other features: BBR/fq tuning, forwarding with MSS clamping, optional Reed-Solomon FEC, optional
XChaCha20-Poly1305 payload encryption, iptables port forwarding (DNAT), a liveness timer, and an
interactive menu.

**Iran and foreign sides are symmetric.** Both run the same install, the same config keys and the same
relay. The only usual difference is that port forwarding (`FORWARD=`) is set on the Iran (client-facing) side.

---

## 2. Architecture and layering

### 2.1 What it is NOT

The project uses **no GRE6, ip6gre, ip6tnl, sit/6to4, IPIP, VXLAN, nftables, haproxy, socat or cron**.
(`socat` and `nft` show up only in docs and benchmark helpers, not in the product.) The underlay is
**IPv4 only** and the overlay is **IPv4 only**. See section 9.

### 2.2 Interfaces and kernel objects created per tunnel

| Object | Default | Notes |
|---|---|---|
| `greN` (`type gre`) | `gre1`, `gre2`, ... (`next_dev`) | IPv4 GRE with key. With a disguise its endpoints are `127.0.0.1` to `127.0.0.1`, encapsulated in FOU. |
| FOU listener | UDP `127.0.0.1:5599`, `ipproto 47` | Decapsulates what the local relay hands back. |
| Relay loopback socket | UDP `127.0.0.1:5601` | `--local`. This is where `greN`'s FOU output is sent. |
| Relay wire sockets | dns: UDP `LOCAL_PUB:53` rx (up to 8 ports), plus a tx socket on `LOCAL_PUB:<ephemeral>`; icmp: one `SOCK_RAW IPPROTO_ICMP` bound to `LOCAL_PUB` | |

### 2.3 Exact `ip` / `ethtool` commands (`scripts/golden-gre-up.sh`)

Disguised mode (`FACADE=dns|icmp`):

```bash
modprobe fou                                   # fou has no alias, cannot autoload
ip fou add port ${FOU_PORT:-5599} ipproto 47 local 127.0.0.1
ip link del ${DEV} 2>/dev/null || true
ip link add ${DEV} type gre local 127.0.0.1 remote 127.0.0.1 ttl 255 key ${GRE_KEY} \
    encap fou encap-sport ${FOU_PORT} encap-dport ${RELAY_PORT}
ip addr add ${TUN_ADDR} dev ${DEV}
ip link set ${DEV} mtu ${MTU:-1380} up
ethtool -K ${DEV} tso off gso off gro off      # one packet per datagram to the relay
```

Plain mode (`FACADE=none`):

```bash
ip link add ${DEV} type gre local ${LOCAL_PUB} remote ${REMOTE_PUB} ttl 255 key ${GRE_KEY}
ip addr add ${TUN_ADDR} dev ${DEV}
ip link set ${DEV} mtu ${MTU} up               # GSO left on
```

Optional: `ip route replace <CIDR> dev ${DEV}` for each entry in `ROUTES`.

How the loopback trick works:
1. `greN` adds a GRE header (with key) and FOU puts that in UDP `127.0.0.1:5599 -> 127.0.0.1:5601`.
2. The relay reads the UDP payload (GRE header plus inner packet) and sends it to the peer inside the disguise.
3. The peer relay unwraps it and `sendmmsg`s it from its `127.0.0.1:5601` socket to `--reply 127.0.0.1:5599`.
4. There the kernel FOU listener decapsulates it as protocol 47. It matches the `127.0.0.1`/`127.0.0.1`/key
   GRE device, and the inner packet appears on `greN`.

### 2.4 Addressing scheme

The menu derives everything from the two public IPs alone. Both ends type the same pair, in any order.
`pair_params()` in `golden-gre.sh`:

```bash
# lo = numerically lower IP, hi = higher
id=$(printf '%s-%s' "$lo" "$hi" | cksum | cut -d' ' -f1)
idx=$(( id % 16384 ))
base=$(( idx % 64 * 4 ))
PAIR_KEY=$(( 1000 + id % 64000 ))                 # GRE key 1000..64999
PAIR_ADDR="10.99.$(( idx / 64 )).$(( base + me ))/30"   # me=1 for lower IP, 2 for higher
PAIR_PEER="10.99.$(( idx / 64 )).$(( base + peer ))"
```

- Overlay: one **/30 inside `10.99.0.0/16`** (RFC 1918). The numerically lower public IP gets `.1` (offset +1) and the higher gets `.2`.
- Manual or README examples use `10.99.99.1/30` and `10.99.99.2/30`, `GRE_KEY=41`.
- The peer address is derived from /30 or /31 (`(last & ~3) + 3 - (last & 3)` or `last ^ 1`). Any other prefix needs `PEER_ADDR`.
- The benchmark harness uses `10.77.61.0/30` on `tb0` (GRE key 91, FOU 5698, relay 5701). The WireGuard docs use `10.200.200.0/30` and `10.200.20N.0/30`.
- The tunnel name is the peer IP: config `/etc/golden-gre/<peerIP>.conf`, unit `golden-gre@<peerIP>`.
- NAT (1:1 cloud NAT): if neither typed IP is on the host, the menu asks "server 1 or 2" and sets
  `LOCAL_PUB=$(ip -4 route get <peer> | src)`, the private address. The pair parameters still come from the public IPs.

### 2.5 MTU / overhead

| Mode | Wire overhead (README) | Default MTU | Recommended if path carries 1500 |
|---|---|---|---|
| icmp | 36 B (IP 20 + ICMP 8 + GRE+key 8) | 1380 | 1464 |
| dns | 75 B (IP 20 + UDP 8 + DNS hdr 39 + GRE 8) | 1380 | 1425 |
| none | 28 B (IP 20 + GRE+key 8) | 1380 | 1472 |

Extra overhead the README table leaves out:
- **FEC** adds a 7-byte header on every frame. Parity frames carry 2 + maxlen.
- **KEYFILE** adds 40 bytes (24-byte nonce + 16-byte tag). See bug B6.

TCP MSS is clamped (`TCPMSS --clamp-mss-to-pmtu`) on forwarded traffic, and `tcp_mtu_probing=1` is set.

---

## 3. The C relay (`relay/golden-gre-relay.c`)

### 3.1 Build and run

`install.sh`:
```bash
gcc -O2 -Wall -pthread -o /usr/local/sbin/golden-gre-relay relay/golden-gre-relay.c relay/monocypher.c
```
CI builds it with `-Wextra -Werror`. Run by `scripts/golden-gre-relay.sh` (the systemd `ExecStart`):

```bash
exec "$RELAY" --facade "${FACADE:-dns}" --bind "${LOCAL_PUB}" --peer "${REMOTE_PUB}" \
  --local "127.0.0.1:${RELAY_PORT:-5601}" --reply "127.0.0.1:${FOU_PORT:-5599}" --port "${DNS_PORTS:-${DNS_PORT:-53}}" \
  --itype "${ICMP_TYPE:-0}" ${FEC:+--fec "$FEC"} ${SPORT_ROTATE:+--rotate "$SPORT_ROTATE"} ${RATE:+--rate "$RATE"} \
  ${KEYFILE:+--keyfile "$KEYFILE"}
```
With `FACADE=none` the script runs `exec sleep infinity` instead, so the unit has a main process.

Full CLI:
`--facade dns|icmp --bind IP --peer IP --local IP:PORT [--reply IP:PORT] [--port 53,853,...] [--itype 0|8] [--fec K:M] [--gso on|off] [--rotate 0..64] [--rate 0..200000] [--keyfile PATH]`.
There is also a separate mode, `--derive-key "<a>,<b>"`, described in 3.5.

### 3.2 Runtime structure

- Two pthreads: `relay-out` (loopback to wire) and `relay-in` (wire to loopback). Both use batched `recvmmsg` and `sendmmsg` (BATCH 64, OUTQ 128, BUF 2048).
- **UDP GSO** (`UDP_SEGMENT` cmsg) coalesces runs of equal-size frames: at most 32 frames or 60000 bytes, and only frames of 1472 bytes or less. It is used on the dns wire socket and on loopback delivery, and falls back automatically on EIO/EINVAL.
- Every 60 s, and on SIGTERM/SIGINT, it prints `tx=… rx=… bad=… rebuilt=… gso=…` to the journal.
- Reply address: when `--reply` is given, delivery works from the first packet. Without it, the relay learns the reply address from the tunnel's first outgoing packet.
- **Source check:** only frames whose IPv4 source equals `--peer` are accepted. In icmp mode a classic BPF filter (`SO_ATTACH_FILTER`) on the raw socket also keeps only packets whose IP source is the peer. This lets many icmp tunnels share one public IP.
- `--rotate N` (dns only): closes and reopens the tx socket every N frames to get a new ephemeral source port, which is a new flow for the filter. With several `--port`s it also rotates the destination port.
- `--rate N`: token bucket, burst capped at `rate/4`.

### 3.3 Wire formats

**DNS facade.** UDP from `LOCAL_PUB:<ephemeral>` to `REMOTE_PUB:53`. Both sides send *queries*; there are no responses.

```
off  len  field
0    2    txid        = per-frame seq (plaintext mode) | random (keyed)
2    10   flags/counts= 01 00 | QD=1 | AN=0 | NS=0 | AR=1    (standard query, RD=1)
12   16   question    = \x05probe\x04test\x00  QTYPE=16 (TXT) QCLASS=1 (IN)
                        keyed: same lengths, random [a-z0-8] label chars
28   1    OPT owner   = 0 (root)
29   2    TYPE=41 (OPT)
31   2    UDP size 4096
33   4    ext-rcode/flags = 0
37   2    RDLEN = payload length
39   ...  payload (RDATA)    -> DNS_HDR = 39
```

**ICMP facade.** Raw IPv4 ICMP (root needed) from `LOCAL_PUB` to `REMOTE_PUB`:

```
type = 0 (unsolicited echo reply, --itype 0) | 8 (echo request, --itype 8)
code 0 | checksum (computed in user space) | ident = 0x7462 ("tb") or random when keyed | seq = per-frame counter
payload
```
The receiver checks the length, the ident (plaintext mode only), and that the ICMP type matches its own `--itype`.
On a type mismatch it warns once.

**Payload.** Plaintext mode carries the frame as-is. Keyed mode carries `nonce(24) || XChaCha20(frame) || Poly1305 tag(16)`.

**Frame**, which is the plaintext before encryption, is one of:
- the raw FOU payload (`GRE header + inner IP packet`), or
- an FEC frame: `0xF5 | block_id u32 BE | idx (data: i, parity: 0x80|j) | k (parity only, data=0) | body`.

### 3.4 FEC

- **Code:** systematic Reed-Solomon over GF(2^8), polynomial `0x11d`, Cauchy matrix `C[j][i] = 1/((0x80|j) xor i)`.
- **Parameters:** K ≤ 32, M ≤ 32. Default in the menu is `10:5` (`FEC_DEFAULT`).
- **Encoding:** each packet is the vector `(2-byte len, payload, zero pad)`. A block is flushed after K packets or 5 ms. A partial block gets `ceil(M*k/K)` parity packets.
- **Decoding:** 64 receive slots, Gauss-Jordan inversion. Multiplication uses AVX2 or SSSE3 split-nibble when available, and is self-checked against a table implementation at startup.
- Only the sender needs `--fec`; every relay decodes FEC frames. Block IDs start at a random value.

### 3.5 Encryption and "key exchange"

There is **no key exchange protocol**. The key is a 32-byte pre-shared `KEYFILE`, which is either:
- **random**: `head -c32 /dev/urandom`, copied to the peer by hand, or
- **derived from a passphrase** typed on both servers (`golden-gre.sh: derive_key_file`):
  ```bash
  ( umask 077; printf '%s' "$pass" | golden-gre-relay --derive-key "$s1,$s2" > /etc/golden-gre/<peer>.key )
  ```
  The C side works like this:
  - The two tokens are sorted with `strcmp`, giving the string `"a,b"`.
  - salt = `BLAKE2b-128("a,b")` (16 bytes).
  - key = `Argon2i(pass, salt, m = 65536 KiB (64 MiB), t = 3 passes, p = 1 lane, out = 32 bytes)`.

**AEAD.** Monocypher `crypto_aead_lock` and `crypto_aead_unlock`, which are XChaCha20-Poly1305 (`crypto_aead_init_x`).
- No associated data.
- Nonce = 16 random bytes per process followed by a 64-bit big-endian counter, written by the single tx thread.
- There is a startup known-answer self-test.
- Receive: a frame that fails the tag is dropped, and the relay warns once.
- Keyed mode also randomizes the markers: the DNS txid per frame, the question per process and per rotation, and the ICMP ident per process.

**Monocypher primitives used:** `crypto_aead_lock`/`crypto_aead_unlock` (XChaCha20-Poly1305), `crypto_blake2b`,
`crypto_argon2` (Argon2i), and `crypto_wipe`.

### 3.6 Ports summary

| Port | Use |
|---|---|
| UDP 53 (or `DNS_PORTS`, up to 8) on `LOCAL_PUB` | dns facade, both directions (rx). tx uses ephemeral source ports. |
| ICMP | icmp facade |
| IP proto 47 | `FACADE=none` |
| UDP 127.0.0.1:5599 | FOU decap listener (`FOU_PORT`) |
| UDP 127.0.0.1:5601 | relay loopback (`RELAY_PORT`) |

The menu chooses the first free ports starting at 5599 and 5601 for each additional tunnel.

---

## 4. Firewall, forwarding and port forwarding (iptables only)

All rules come from `golden-gre-up.sh` and are removed by `golden-gre-down.sh`. Tagged rules are found by
their comment `golden-gre:<name>` or `golden-gre-fwd:<name>`.

```bash
# underlay accept (top of INPUT, so ufw DROP policies don't block it)
iptables -I INPUT -p udp --dport 53 -s $REMOTE_PUB -m comment --comment "golden-gre:$NAME" -j ACCEPT   # dns
#   multiple ports: -p udp -m multiport --dports 53,853,...
#   icmp: -p icmp     none: -p gre
# ICMP_TYPE=8 only: stop the kernel answering the relay's echo requests
iptables -I OUTPUT -s $LOCAL_PUB -d $REMOTE_PUB -p icmp --icmp-type 0 -m comment --comment "golden-gre:$NAME" -j DROP

# forwarding through the tunnel + MSS clamp
iptables -I FORWARD -o $DEV -j ACCEPT
iptables -I FORWARD -i $DEV -j ACCEPT
iptables -t mangle -A FORWARD -o $DEV -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -i $DEV -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# optional exit NAT
iptables -t nat -A POSTROUTING -s $NAT_SRC -o $NAT_OUT -j MASQUERADE     # or: ! -o $DEV
```

**Port forwarding** is `FORWARD="443,1080,2053:2096,8080=80"` in the config, usually on the Iran server.
Each entry is applied to both TCP and UDP:

```bash
iptables -t nat -A PREROUTING -d $LOCAL_PUB ! -s $REMOTE_PUB -p tcp --dport 443 \
    -m comment --comment "golden-gre-fwd:$NAME" -j DNAT --to-destination <peer tunnel IP>
iptables -t nat -A PREROUTING -d $LOCAL_PUB ! -s $REMOTE_PUB -p udp --dport 2053:2096 ... -j DNAT --to-destination <peer tunnel IP>
iptables -t nat -A PREROUTING ... --dport 8080 ... -j DNAT --to-destination <peer tunnel IP>:80
iptables -t nat -I POSTROUTING -o $DEV -m conntrack --ctstate DNAT \
    -m comment --comment "golden-gre-fwd:$NAME" -j MASQUERADE
sysctl -qw net.ipv4.ip_forward=1
```

Guards:
- `up.sh` refuses any entry that includes port 22.
- The menu also refuses the real `sshd -T` port(s), warns about ports a local program listens on, and refuses overlaps with other tunnels on the same `LOCAL_PUB`.

The service on the foreign server must listen on `0.0.0.0` or on its tunnel IP. It sees clients as the
Iran tunnel IP because of the MASQUERADE. With ufw: `ufw allow in on greN`.

---

## 5. Persistence

| Path | Content |
|---|---|
| `/usr/local/bin/golden-gre` | The menu (copy of `golden-gre.sh`) |
| `/usr/local/sbin/golden-gre-relay` | Compiled relay |
| `/usr/local/sbin/golden-gre-{up,down,relay}.sh`, `golden-gre-preflight`, `golden-gre-check` | Helper scripts |
| `/etc/systemd/system/golden-gre@.service` | Template unit |
| `/etc/systemd/system/golden-gre-check@.{service,timer}` | Liveness check |
| `/etc/sysctl.d/99-golden-gre.conf` | Tuning |
| `/etc/golden-gre/` (0750) | `<name>.conf` (shell-sourced KEY=VALUE), `<name>.key` (0600, 32 bytes) |

`golden-gre@.service`:
```ini
[Unit]
Wants=network-online.target
After=network-online.target
ConditionPathExists=/etc/golden-gre/%i.conf
[Service]
Type=simple
Restart=always
RestartSec=5
ExecStartPre=/usr/local/sbin/golden-gre-up.sh %i
ExecStart=/usr/local/sbin/golden-gre-relay.sh %i
ExecStopPost=/usr/local/sbin/golden-gre-down.sh %i
[Install]
WantedBy=multi-user.target
```

`golden-gre-check@.timer` fires `OnActiveSec=1min` and `OnUnitActiveSec=1min`, with `WantedBy=golden-gre@%i.service`
and `PartOf` the tunnel. The service runs `ping -c 3 -W 2 -I $DEV $PEER_ADDR` and exits 1 when there is no
reply, so a dead tunnel shows in `systemctl --failed`. The menu does **not** enable it. You enable it by hand
with `systemctl enable golden-gre-check@<name>.timer`.

There is **no cron job**. Boot persistence is `systemctl enable --now golden-gre@<name>`.
`up.sh` exits early with a non-zero status when `LOCAL_PUB` is not yet configured or there is no route to the
peer, and `Restart=always` retries every 5 s. A failed fresh bringup rolls itself back by calling `down.sh`
from an EXIT trap.

---

## 6. Menu (`golden-gre`) and uninstall

**First run.**
1. `bash <(curl -fsSL https://raw.githubusercontent.com/LivingG0D/Golden-GRE/main/golden-gre.sh)`. `curl | bash` is explicitly refused.
2. Installs packages: `gcc libc6-dev iproute2 iptables ethtool iputils-ping curl tar` via apt, or the dnf/yum equivalents.
3. Downloads the branch tarball from GitHub (`GOLDEN_GRE_BRANCH`, default `main`) unless the script runs from a clone.
4. Runs `install.sh`, copies itself to `/usr/local/bin/golden-gre`, runs preflight, and offers a tunnel setup.

**Main menu:**
1. New tunnel: asks for server 1 and server 2 IPs, then the disguise (1 ICMP requests = default, 2 DNS, 3 ICMP replies, 4 none), then optionally encryption with a passphrase. It writes the conf, starts the tunnel, prints a "pair check" (key, subnet, disguise) and pings the peer.
2. Manage tunnels: a table (tunnel, IPs, state, disguise, FEC, live ping) and then the per-tunnel menu:
   `1 Start, 2 Stop, 3 Restart, 4 Ping test, 5 Recent logs, 6 Live logs, 7 Disguise, 8 FEC toggle (10:5), 9 Encryption toggle, 10 Port forwarding (add/remove/remove all), 11 Show settings, 12 Delete`.
3. Live logs (`journalctl -u golden-gre@<n> -f`).
4. Update: reinstall from GitHub and optionally restart running tunnels.
5. Uninstall.

Other menu behaviour:
- **Disguise mapping:** `icmp-request` writes `FACADE=icmp` and `ICMP_TYPE=8`; `icmp-reply` writes `FACADE=icmp`; `dns` and `none` write `FACADE=dns` and `FACADE=none`.
- **DNS limit:** only one dns tunnel per `LOCAL_PUB`, because the relay owns `:53`.
- **Failed start:** if a start fails, the unit is disabled so it does not loop restarting.

**Uninstall** does the following:
1. Disables and stops every `golden-gre@*` and check timer. `down.sh` removes the device, FOU and iptables rules.
2. Deletes enable symlinks, the binaries and scripts, the unit files and `/etc/sysctl.d/99-golden-gre.conf`, then runs `daemon-reload`.
3. Asks before `rm -rf /etc/golden-gre`.
4. Removes `/usr/local/bin/golden-gre`.

Sysctl values stay live until reboot. Kernel modules stay loaded.

---

## 7. Sysctl and tuning (`/etc/sysctl.d/99-golden-gre.conf`)

```
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 4096 1048576 134217728
net.ipv4.tcp_wmem = 4096 1048576 134217728
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
```
IPv6 forwarding is deliberately **not** enabled, so a SLAAC-learned default route is kept.

Other tuning:
- The relay sets `SO_RCVBUF` and `SO_SNDBUF` to 4 MiB.
- TSO, GSO and GRO are turned off on `greN` in relay mode.
- The relay uses UDP GSO and sendmmsg batching.

---

## 8. Configuration keys (`/etc/golden-gre/<name>.conf`)

`DEV, LOCAL_PUB, REMOTE_PUB, TUN_ADDR` (required); `FACADE` (dns|icmp|none, default dns); `ICMP_TYPE` (0|8);
`MTU` (1380); `GRE_KEY` (41); `FEC` (K:M); `KEYFILE`; `FORWARD`; `ROUTES`; `NAT_SRC`/`NAT_OUT`;
`FOU_PORT` (5599) and `RELAY_PORT` (5601); `DNS_PORT`/`DNS_PORTS` (53); `SPORT_ROTATE` (dns, 0..64);
`RATE` (dns, frames/s); `PEER_ADDR`.

---

## 9. IPv6 / v6-to-v6 support

**There is none.**
- `golden-gre-up.sh` rejects any `LOCAL_PUB` or `REMOTE_PUB` that contains `:` ("must be IPv4 addresses"), and `preflight.sh` does the same.
- `tests/e2e.sh` asserts that IPv6 endpoints are rejected.
- The relay is `AF_INET`-only (`inet_pton(AF_INET…)`, raw `IPPROTO_ICMP`, BPF reads the IPv4 source at offset 12).
- No ip6gre, ip6tnl or sit device is ever created. The overlay is IPv4 /30 only, with no IPv6 address on `greN`.
- The sysctl file explicitly avoids `net.ipv6.conf.*.forwarding`.

A GRE device can carry IPv6 inside it, so you could add `ip -6 addr add fd00::1/64 dev gre1` yourself. That is
unsupported, and the FORWARD, MSS clamp and DNAT logic only uses `iptables`, not `ip6tables`.

---

## 10. Security concerns and bugs

| # | Severity | Issue |
|---|---|---|
| S1 | High | **Plaintext by default.** `KEYFILE` is opt-in. The setup menu offers it with default Y, but hand-written configs have no encryption. Without a key there is **no authentication** either: the receiver only checks the source IP plus a fixed marker. Anyone who can spoof `REMOTE_PUB` can inject arbitrary GRE and IP packets into `greN`, which then forwards them because of `FORWARD -i greN -j ACCEPT`. |
| S2 | Medium | **The GRE key is not secret.** It is `1000 + cksum("lo-hi") % 64000`, computed from the two public IPs, or the constant `41`. It is in cleartext on the wire. It gives no protection against injection by anyone who knows the two endpoints. |
| S3 | Medium | **No anti-replay** (acknowledged in the README). Captured AEAD frames can be replayed indefinitely and across relay restarts. Neither the tag nor the nonce is bound to direction (both ends share the key, with no AD). |
| S4 | Medium | **Passphrase KDF salt is public and deterministic** (BLAKE2b of the IP pair). That allows targeted offline cracking of a captured frame. Argon2i at 64 MiB and t=3 helps, but security depends entirely on passphrase strength. Argon2i rather than Argon2id is a minor point. |
| S5 | Medium | **Easy to fingerprint.** In plaintext mode the DNS QNAME is always `probe.test` TXT, the txid is a sequential counter, and the ICMP ident is always `0x7462`. In both modes: ~1.4 KB one-way DNS *queries* with binary RDATA in a malformed EDNS0 OPT record (RDATA is not option TLVs), no responses, and high sustained rates. These are trivially detectable by DPI. In keyed mode the random label chars use `cs[xrng() % 35]` over a 36-char alphabet, so `'9'` never appears, which is a statistical tell and an off-by-one bug. |
| S6 | Medium | **Supply chain.** It runs as root via `bash <(curl …)` and downloads a `main` branch tarball with no pinning or signature. **Update** does the same. |
| S7 | Low | The relay runs as root with no systemd hardening (no `NoNewPrivileges`, `CapabilityBoundingSet`, `ProtectSystem`, etc.) and never drops privileges after opening its sockets. It parses untrusted wire input (FEC, ICMP IHL) in C. The bounds checks look correct, but a root C parser on the internet is still attack surface. |
| S8 | Low | `FORWARD -i/-o greN -j ACCEPT` is inserted at the top of `FORWARD`, ahead of ufw and Docker rules. The peer can reach anything this host can route to (documented). |
| S9 | Low | Configs are shell-sourced as root (`. "$CONF"`). The directory is 0750 root, so this matters only if someone else can write there. |
| B1 | Bug | **Encryption toggle behind NAT produces a mismatched key.** At setup the salt is the typed public IPs (`derive_key_file "$name" "$s1" "$s2"`). `toggle_enc` instead uses `LOCAL_PUB` and `REMOTE_PUB` from the conf, and behind 1:1 NAT `LOCAL_PUB` is the *private* source address. So turning encryption on later from the menu on a NATed host derives a different key from the peer's, and every frame fails with "payload decrypt failed". |
| B2 | Bug | `tools/xui-set-outbound-address.sh` takes an `outbound_tag` argument but hard-codes `assert changed == ["Turkey-Multipath-GoldenGRE"]`, so it fails for any other tag. It is also tied to one operator's setup (DB path, API port 62789). |
| B3 | Minor | Keyed ICMP mode: every non-tunnel ICMP packet from the peer (for example a normal ping) fails decryption. That bumps `bad` and can print the misleading "both ends must use the same KEYFILE" warning once. |
| B4 | Minor | Port forwarding uses PREROUTING DNAT only, so connections that originate on the Iran host itself to `LOCAL_PUB:port` are not forwarded. Rules placed earlier in nat PREROUTING (Docker) take precedence (documented). |
| B5 | Minor | In `up.sh` the deletion loop for old `golden-gre-fwd` rules runs `iptables -t nat …` without `|| true` under `set -e`, so a failed delete aborts the bringup. |
| B6 | Bug/perf | **MTU arithmetic ignores KEYFILE (+40) and FEC (+7).** At the default MTU 1380 with dns + KEYFILE + FEC, a data frame is 1388 + 7 + 40 + 39 + 8 + 20 = **1502 B** and a parity frame is **1504 B**, which exceeds a 1500 path. The README's "1464/1425/1472" advice is only correct with no key and no FEC. Oversized frames get fragmented locally, and fragments are likely dropped by the filter. |
| B7 | Minor | `ICMP_TYPE=8` mode drops *all* echo replies from this host to the peer's public IP, so ordinary pings from the peer stop working (documented). |
| B8 | Minor | The check timer is never enabled by the menu, and `SPORT_ROTATE`, `RATE` and `DNS_PORTS` are not exposed in the menu (hand-edit only). `--gso` is not exposed at all. |

---

## 11. How to reproduce manually

Placeholders:
- `IR=203.0.113.10` is the Iran server public IP.
- `KH=198.51.100.20` is the foreign (Kharej) server public IP.

`IR` is numerically lower here, so it takes `.1`. Use the same `GRE_KEY` on both servers.

### 11.1 Using the project's scripts (recommended)

Both servers:
```bash
apt-get install -y gcc libc6-dev iproute2 iptables ethtool iputils-ping
git clone https://github.com/LivingG0D/Golden-GRE.git && cd Golden-GRE && sudo ./install.sh
```

Iran (`/etc/golden-gre/kh.conf`):
```bash
cat >/etc/golden-gre/kh.conf <<'EOF'
DEV=gre1
LOCAL_PUB=203.0.113.10
REMOTE_PUB=198.51.100.20
TUN_ADDR=10.99.99.1/30
GRE_KEY=41
FACADE=icmp
ICMP_TYPE=8
MTU=1380
KEYFILE=/etc/golden-gre/kh.key
FORWARD="443,2053:2096,8080=80"
EOF
```

Foreign (`/etc/golden-gre/ir.conf`):
```bash
cat >/etc/golden-gre/ir.conf <<'EOF'
DEV=gre1
LOCAL_PUB=198.51.100.20
REMOTE_PUB=203.0.113.10
TUN_ADDR=10.99.99.2/30
GRE_KEY=41
FACADE=icmp
ICMP_TYPE=8
MTU=1380
KEYFILE=/etc/golden-gre/ir.key
EOF
```

Key: either a random key copied to both servers, or the same passphrase derived on both.
```bash
# Iran
head -c32 /dev/urandom > /etc/golden-gre/kh.key && chmod 600 /etc/golden-gre/kh.key   # then copy it to KH as ir.key
# or, on both (the IP order does not matter):
( umask 077; printf '%s' 'same passphrase' | /usr/local/sbin/golden-gre-relay --derive-key "203.0.113.10,198.51.100.20" > /etc/golden-gre/<name>.key )
```

Start, on each server:
```bash
golden-gre-preflight <name>
systemctl enable --now golden-gre@<name>
systemctl enable golden-gre-check@<name>.timer      # optional
ping 10.99.99.2   # from Iran;  ping 10.99.99.1 from Kharej
```

### 11.2 Fully by hand (no systemd), ICMP-request disguise, encrypted

Iran (IR):
```bash
modprobe fou
ip fou add port 5599 ipproto 47 local 127.0.0.1
ip link add gre1 type gre local 127.0.0.1 remote 127.0.0.1 ttl 255 key 41 \
   encap fou encap-sport 5599 encap-dport 5601
ip addr add 10.99.99.1/30 dev gre1
ip link set gre1 mtu 1380 up
ethtool -K gre1 tso off gso off gro off
iptables -I INPUT -p icmp -s 198.51.100.20 -m comment --comment golden-gre:kh -j ACCEPT
iptables -I OUTPUT -s 203.0.113.10 -d 198.51.100.20 -p icmp --icmp-type 0 -m comment --comment golden-gre:kh -j DROP
for d in -o -i; do
  iptables -I FORWARD $d gre1 -j ACCEPT
  iptables -t mangle -A FORWARD $d gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
done
# port forwarding to the foreign server's tunnel IP
for p in tcp udp; do
  iptables -t nat -A PREROUTING -d 203.0.113.10 ! -s 198.51.100.20 -p $p --dport 443 -j DNAT --to-destination 10.99.99.2
done
iptables -t nat -I POSTROUTING -o gre1 -m conntrack --ctstate DNAT -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1 net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr
/usr/local/sbin/golden-gre-relay --facade icmp --itype 8 --bind 203.0.113.10 --peer 198.51.100.20 \
   --local 127.0.0.1:5601 --reply 127.0.0.1:5599 --keyfile /etc/golden-gre/kh.key   # [--fec 10:5]
```

Foreign (KH):
```bash
modprobe fou
ip fou add port 5599 ipproto 47 local 127.0.0.1
ip link add gre1 type gre local 127.0.0.1 remote 127.0.0.1 ttl 255 key 41 \
   encap fou encap-sport 5599 encap-dport 5601
ip addr add 10.99.99.2/30 dev gre1
ip link set gre1 mtu 1380 up
ethtool -K gre1 tso off gso off gro off
iptables -I INPUT -p icmp -s 203.0.113.10 -m comment --comment golden-gre:ir -j ACCEPT
iptables -I OUTPUT -s 198.51.100.20 -d 203.0.113.10 -p icmp --icmp-type 0 -m comment --comment golden-gre:ir -j DROP
for d in -o -i; do
  iptables -I FORWARD $d gre1 -j ACCEPT
  iptables -t mangle -A FORWARD $d gre1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
done
sysctl -w net.ipv4.ip_forward=1 net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr
/usr/local/sbin/golden-gre-relay --facade icmp --itype 8 --bind 198.51.100.20 --peer 203.0.113.10 \
   --local 127.0.0.1:5601 --reply 127.0.0.1:5599 --keyfile /etc/golden-gre/ir.key
# services must listen on 0.0.0.0 or 10.99.99.2
```

Variants:
- **DNS disguise.** Replace the INPUT rule with `-p udp --dport 53`, drop the OUTPUT rule, and run the relay with
  `--facade dns --port 53` (no `--itype`). Optional: `--rotate 6 --rate N`. Port 53 on `LOCAL_PUB` must be free.
- **ICMP replies** (legacy): `--itype 0` on both sides, and no OUTPUT DROP rule.
- **Plain GRE** (`FACADE=none`): no FOU and no relay.
  ```bash
  ip link add gre1 type gre local <me> remote <peer> ttl 255 key 41
  ip addr add 10.99.99.X/30 dev gre1
  ip link set gre1 mtu 1472 up
  iptables -I INPUT -p gre -s <peer> -j ACCEPT
  ```
  Keep the FORWARD and MSS rules as above.

Teardown, on each server:
```bash
kill <relay pid>
ip link del gre1
ip fou del port 5599 local 127.0.0.1
# delete the iptables rules with -D in place of -I/-A
```

---

## 12. Other repository content

- `bench/` holds the harness that produced `docs/FILTER.md`.
  - `l3.sh` tests gre, gre-fou, gre-gue, ipip, ipip-fou, vxlan, geneve, wg, and the relay variants.
  - `hop.sh` does per-packet UDP source-port hopping with nft `numgen`.
  - `tbrelay.py` is a Python relay prototype.
  - `probe.py`, `carriers.sh` and `filter.sh` probe the path.
- `results/*.tsv` holds the raw measurements.
- `tests/` contains namespace-based end-to-end tests (relay, e2e, systemd, menu, crypto via `crypto_test.py`).
- `docs/WireGuard.md` shows how to run WireGuard through the same relay (`--reply 127.0.0.1:51820`, WG `Endpoint = 127.0.0.1:5601`, MTU 1380), and covers per-flow policer bonding and Xray balancer notes.
- **Reported performance.** Iran–Kharej 2: icmp 512–691 Mbit/s single flow. Iran–Kharej 1: dns 138/153 Mbit/s.
  These are project claims, not verified here.
