# BackPack — technical reference

Source analysed: `/home/user/tunnels-kb/sources/BackPack` (VERSION `v1.9.0`, Go, AGPL-3.0, upstream `github.com/AminMGMT/BackPack`, Go module `github.com/backpack/backpack`). Nothing from the tree was executed; everything below comes from reading the source and docs.

---

## 1. Purpose and overall architecture

BackPack is a tunnel engine between an **Iran** server and a foreign (**kharej**) server. Users connect to the Iran box. The real service (Xray/3x-ui, WireGuard, a proxy and so on) runs on kharej. It ships as one statically built binary (`CGO_ENABLED=0`) that holds the engine, an interactive TUI menu, a non-interactive CLI, a web panel, a monitor/watchdog with a Telegram bot, a built-in SOCKS5/HTTP proxy, and a fleet manager that works over SSH.

Vocabulary from `CONTEXT.md`, which the code uses consistently:

| Term | Meaning |
|---|---|
| Iran side | The machine users connect to. In a reverse tunnel it is the **server** (it listens and exposes the forwarded ports). |
| Kharej side | The machine abroad. In a reverse tunnel it is the **client** (it dials Iran, then dials the real service locally). |
| Tunnel | One TOML file, one systemd unit, one process, one engine. |
| Engine | Picked by which TOML table is present: `[l3]`, then `[direct]`, then `[server]`/`[client]`. |
| Transport | How the reverse engine moves data: `tcp tcpmux stealth ws wss wsmux wssmux kcp quic udp xdi pck`. |
| Carrier | How the L3 engine moves packets: `udp pck sni xdi spoof quic`. |
| Forwarded port | A port on Iran mapped to a target on kharej (`443=127.0.0.1:2096`). |
| Control channel / signal / pool / pairing / generation | Internals of the reverse engine (see §2.1). |
| Snapshot | A JSON metrics file each engine writes every 30 s (`/etc/backpack/<name>.metrics.json`). It is the only interface between an engine and every other process. |

### 1.1 Process modes (`main.go`)

| Invocation | Runs |
|---|---|
| `backpack` | Interactive menu (`internal/menu`) |
| `backpack -c /etc/backpack/<name>.toml` | **Engine mode**: one tunnel (`cmd.Run`) |
| `backpack --webui` | Web panel (`internal/webui`), unit `backpack-webui.service` |
| `backpack --monitor` | Watchdog, Telegram bot, alerts, history (`internal/monitor`), unit `backpack-monitor.service` |
| `backpack --proxy` | Built-in SOCKS5/HTTP proxy, unit `backpack-proxy.service` |
| `backpack --restart-all`, `--telegram-report` | One-shot cron jobs |
| `backpack -v` | Version and source URL |
| `backpack node exec -` | One fleet operation, run by a panel over SSH |
| `backpack short-https init/serve/client` | Experimental standalone relay (§2.8) |
| `backpack tunnel/check/link/proxy/version …` | Non-interactive CLI (§5.2) |

### 1.2 Engine selection (`cmd/cmd.go runEngine`, `config/*.go`)

```
        ┌─ [l3] table present?    ──yes──►  internal/tunnel/l3       layer 3 (TUN)
config ─┼─ [direct] table present? ─yes──►  internal/tunnel/direct   layer 4, Iran dials out
        └─ [server]/[client]      ────────►  internal/server + internal/client (reverse)
```

The three engines share no configuration key and no code. The gates are literally `L3Config.Enabled()`, which is `strings.TrimSpace(l.Mode) != ""`, and `DirectConfig.Enabled()`, which tests `Role`.

Each tunnel runs as its own process under its own systemd unit, so a crash affects only that tunnel.

### 1.3 Package map (main pieces)

- `internal/server/transport`, `internal/client/transport`: the reverse transports. Shared machinery lives in `lifecycle.go`, `controlloop.go`, `forward.go`, `pairing.go`, `pairloop.go`, `poolmaintain.go` and `internal/controlwire`.
- `internal/tunnel/l3`: the L3 tunnel (TUN, Noise session, carriers, FEC, multipath, MTU probe, port forwarder).
- `internal/tunnel/direct`: the legacy L4 direct tunnel (smux over tcp/stealth/ws/wss).
- `internal/tunnel/chain`: transport fallback rotation.
- `internal/tunnel/bridge`: `Join()` copies both directions and keeps a TCP half-close (FIN) until the response has drained. Used by the direct and L3 forwarders.
- `internal/tunnel/portmap`: the shared forwarded-port syntax.
- `internal/tunnel/limits`: max connections plus a bandwidth token bucket (`golang.org/x/time/rate`, burst of one second).
- `internal/tunnel/mssclamp`: iptables TCPMSS rules.
- `internal/tunnel/naive`: managed NaiveProxy/sing-box/Xray helper processes that wrap the TCP reverse engine.
- `internal/utils/network`: Noise, KCP, uTLS, the pck/spoof/ICMP raw carriers, proxy dialers, TLS config.
- `internal/manage` (with `tunnelspec`, `health`, `host`, `backup`, `core`): wizards, edits, panel API, update, migration, Connection Test.
- `internal/webui`, `internal/telegram`, `internal/node`, `internal/monitor`, `internal/optimize`, `internal/metrics`.

---

## 2. Tunnel modes

### 2.1 Reverse tunnel (`[server]` on Iran, `[client]` on kharej): the default

**Direction.** Iran **listens** on `bind_addr` (the tunnel port) and also listens on the forwarded `ports`. Kharej **dials** `remote_addr` and, for each user connection, dials the local backend. Kharej needs no inbound port.

```
users ──▶ [IRAN :443 forwarded] ◀══ tunnel (kharej dials Iran:bind_addr) ══ [KHAREJ] ──▶ 127.0.0.1:443
```

**Runtime model** (docs/architecture.md and the ADRs):
- **Control channel**: one long-lived connection that carries one-byte **signals** (heartbeat, request-a-pool-connection, RTT probe, goodbye `SG_Closed`). It never carries user data.
- **Pool**: the client keeps `connection_pool` warm data connections (default 8, presets 4/8/16). `aggressive_pool` refills the pool in a tight loop.
- **Pairing**: on Iran, an accepted user connection is queued (`channel_size`, default 2048) and matched with a pool connection. The server asks for more over the control channel.
- **Generation**: the listener, the forwarded ports and the pairing workers share one context. A kharej that redials is put back into the same "seat" without rebinding ports (ADR 0005).
- **Auth handshake** (`announce.go`): the client presents the token, checked with `subtle.ConstantTimeCompare`. The server answers with the token plus a fresh **pool nonce** that later pool connections must present, plus the negotiated smux version. An older "legacy" handshake falls back to matching source addresses.
- Heartbeat: the server beats at least every 10 s (default `heartbeat = 40`), so the client notices a dead server in about 30 s.

**Transports** (`config.TransportType`):

| Transport | Wire / implementation | Encryption / auth | Mux | PROXY v2 | Notes |
|---|---|---|---|---|---|
| `tcp` | plain TCP, one connection per user from the pool | **none**; token sent in the clear | no | yes | `zero_copy` (splice) available, Linux only |
| `tcpmux` | TCP + smux | none | smux | yes | many short-lived connections |
| `stealth` | TCP + **Noise NNpsk0** record layer; PSK derived from token | ChaCha20-Poly1305; peer without token gets silence | no | yes | no TLS ClientHello, looks random |
| `pck` | KCP inside hand-built **TCP segments** over an AF_PACKET socket; no kernel TCP state | KCP AES (token key) | KCP/smux | yes | Linux + root/CAP_NET_RAW; installs iptables RST-drop and NOTRACK rules |
| `udp` | raw UDP datagrams (forwarded ports are **UDP-only**); TCP control channel | none | no | no | no reliability |
| `kcp` | KCP over UDP + FEC (Reed-Solomon shards) | AES, key `pbkdf2(token, "backpack-kcp-v1", 100000, 32, sha256)` | smux | yes | the "gaming" transport |
| `quic` | QUIC streams over UDP | TLS 1.3 (self-signed); token proven by **HMAC over TLS exported keying material**, both directions | QUIC streams | yes | "offered, not recommended" on Iran routes |
| `ws` | WebSocket | none; token in the clear | no | no | CDN-capable |
| `wsmux` | WebSocket + smux | none | smux | yes | |
| `wss` | WebSocket over TLS, **Chrome uTLS fingerprint** | TLS; token proven by HMAC bound to the TLS session (unless `simple_auth`) | no | no | decoy nginx site for probes; ACME or self-signed |
| `wssmux` | WSS + smux | same | smux | yes | |
| `xdi` | KCP inside **ICMP echo**; session tag derived from token, echo ID per session | KCP AES | KCP/smux | yes | Linux + root; last resort |

`spoof` is **refused** as a reverse transport (`checkSpoof`). The pooled sessions would all collapse onto one forged address. Spoofing is an L3 carrier only.

**Optional managed HTTPS wrappers** (TCP reverse only, Linux glibc amd64/arm64). `[server.naive]`/`[client.naive]` run a sing-box HTTP/2 inbound on Iran and the official NaiveProxy client on kharej. `[server.xray]`/`[client.xray]` run Xray in either `xhttp` mode (XHTTP over verified TLS, HTTP/2 stream-up) or `reality` mode (RAW + REALITY + Vision, Chrome fingerprint). The rules: `transport = "tcp"`, `bind_addr` and `remote_addr` must be **literal loopback**, the helper listens publicly on a different port, kharej initiates toward Iran, and only TCP forwarding with one endpoint is supported. No UDP, no fallbacks, no proxy/bind settings. Helpers are installed with `BP_HELPERS=naive|xray|naive,xray` (§3). Data inside the helper stream uses 4-byte-header records of at most 64 KiB with an explicit EOF marker.

**IPv4/IPv6.** The wizard offers "Listen On IPv6 As Well", which binds `::` (dual-stack). Port mappings accept bracketed IPv6 (`[::1]:443`); an unbracketed IPv6 address is refused. The kharej wizard warns when the Iran domain has an AAAA record that would send the tunnel over IPv6. `pck` and `xdi` are IPv4-only (`"pck: only IPv4 peers are supported"`; the ICMP code uses `ipv4.PacketConn`).

**Reliability features:**
- `fallback_addrs`: more server addresses, tried in order. `load_balance = true` spreads pool connections across them (the control channel stays on one). `health_failover = true` scores each address by `mean_rtt + 2×jitter + 20×loss%` and switches only when a candidate is at least 15% better for three checks in a row. All addresses must reach the **same** server.
- `fallback_transports` + `fallback_dwell` (default 60 s), via `internal/tunnel/chain`. The server holds each candidate for the full dwell. The client sweeps at `dwell/len(candidates)` (floor 5 s), so the two ends meet within one dwell with no negotiation. After a candidate settles, rotation resumes only if it stays down for 5 min (`regrace`). Both ends must list the same candidates in the same order.
- `edge_ip`: dial a CDN edge while presenting the configured hostname (ws/wss family).
- Client outbound settings: `proxy` (socks5/http URL), `local_addr`, `interface` (SO_BINDTODEVICE), `so_mark` (fwmark). These apply only to TCP-dialer transports; udp/kcp/xdi/pck/quic refuse them.

**Forwarded UDP** (`accept_udp`, **off by default**). Each source address becomes a "flow" over a pooled connection, with length-prefixed datagrams and a 60 s idle timeout. The default flipped back to off because browser QUIC on 443/udp was starving the pooled TCP forwards.

### 2.2 Direct L3 tunnel (`[l3]`): what "Setup → Direct" builds since v1.7.3

**Direction.** `mode = "dial"` reaches out; `mode = "listen"` waits. For Iran⇄kharej the usual choice is **Iran = dial, kharej = listen**, so Iran needs no inbound port. Once the session is up the link is symmetric.

**What it does.** Each host creates a TUN device (`bp0`, `bp1`, …). IP packets the kernel routes into it are GRE-encapsulated in userspace (RFC 2784 with the optional RFC 2890 key; 4 bytes, or 8 with a key), sealed in a Noise session, and handed to a datagram **carrier**. The result is a point-to-point link, for example `10.10.0.1/30 ⇄ 10.10.0.2/30`. Any routed traffic works (ICMP, OSPF, ESP, WireGuard), and there is an optional userspace port forwarder on top. It does **not** interoperate with kernel, Cisco or MikroTik GRE. It needs Linux, `/dev/net/tun` and CAP_NET_ADMIN.

Stack (`l3/doc.go`):
```
[ inner IP packet ]   read from TUN (IPv4 or IPv6, first nibble decides)
[ GRE header      ]   4 B (8 B with gre_key)
[ header + AEAD   ]   13 B clear header (kind|session u32|counter u64) + 16 B Poly1305 tag = 29 B
[ carrier         ]   udp 28 | quic 60 | pck/sni 52 | xdi 33 | spoof 28+
```

**Carriers:**

| `carrier` | On the wire | Overhead | Needs | IP family (outer) |
|---|---|---|---|---|
| `udp` (default) | UDP datagrams; `paths = N` spreads over N consecutive ports | 28 | nothing | v4 or v6 |
| `quic` | a real QUIC connection (TLS 1.3, ALPN `h3`), tunnel carried in RFC 9221 DATAGRAM frames | 60 | nothing (no root) | v4 or v6 |
| `pck` | socketless TCP segments over a packet socket | 52 | root / CAP_NET_RAW | IPv4 only |
| `sni` | `pck`, plus a fake TLS ClientHello for `sni_domain` at the start of the flow (default `mci.ir`) | 52 | root | IPv4 only |
| `xdi` | ICMP echo; installs `u32` iptables rules to drop the kernel's auto-replies and accept its own echoes | 33 | root | IPv4 |
| `spoof` | raw IPv4 with a **forged source** (`spoof_src_ip`/`spoof_src_pool`); profiles `udp`, `icmp`, `tcp`, `icmpv6` (proto 58 inside IPv4), `ipip`, `gre`, set per direction with `spoof_uplink`/`spoof_downlink`; optional XDP receive | 28+ | root; the path must have no BCP38 filtering; `rp_filter` 0 or 2 | IPv4 only |

Reliable carriers (`tcp`, `ws`, `kcp`) are refused on purpose, to avoid the TCP-over-TCP meltdown.

**Crypto** (`l3/session.go`, `wire.go`):
- Noise **NNpsk0**, fixed suite `DH25519 / ChaChaPoly / BLAKE2s`. PSK = `HKDF-SHA256(token, label "backpack-l3-psk-v1")`, prologue `"backpack-l3-v1"`. These are domain-separated from stealth, so neither protocol can decrypt the other.
- The nonce is an explicit 64-bit counter, checked against a **2048-bit sliding replay window**. The header is the AAD.
- Rekey every 2 min. Sessions are rejected after 5 min, or after 2^60 messages.
- The dialler's handshake carries a timestamp, and the listener refuses one that is not newer than the last (WireGuard's rule against handshake replay; added in v1.8.2, with a fallback for older listeners).
- The encap ID (`gre` or `gre:<key>`) travels inside the handshake, so a mismatch is refused by name.
- A peer without the token gets no reply. The peer address is learned only from authenticated packets.
- Liveness: if the peer has been quiet for 15 s, the tunnel probes inside the current session before re-handshaking. If the listener restarts, the dialler notices in about 20 s.

**FEC**: `fec_data`/`fec_parity` (wizard writes 10/3). Pure redundancy with no retransmission. Works over every carrier. Both ends must use the same values, and setting only one of the two is refused. Measured in the doc: 20% path loss became 3.5% application loss with FEC on, against 39% off, for about 33% more traffic.

**Multi-kharej**: one tunnel per kharej, each with its own `10.10.N.0/30`. A shared port can list several backends, `ports = ["443=10.10.0.2:443|10.10.1.2:443"]`. Each new connection goes to the backend with the fewest connections. A dead backend is set aside for 20 s.

Details of TUN, MTU, MSS and routing are in §6.

### 2.3 Direct L4 tunnel (`[direct]`): legacy stream engine

The wizard no longer builds it, but it still runs and can be edited. The same forwarded ports as reverse, with the direction flipped: **Iran (`role = "iran"`/`edge`) dials** kharej (`role = "kharej"`/`origin`), which listens.

- Transport is `tcp` (default), `stealth` (Noise), `ws` or `wss`. KCP and QUIC are reverse-only. For ws/wss, the HTTP upgrade is camouflage only; after it, the raw stream is used.
- **Mux**: Iran opens `sessions` (default 1) smux sessions, and every user connection becomes a stream opened on demand. There is no pool and no control channel.
- **Auth**: the token never travels. It is a mutual HMAC over two nonces:
  ```
  Iran   -> kharej   nonceI
  kharej -> Iran     nonceK, HMAC(token, "origin" || nonceI || nonceK)
  Iran   -> kharej   HMAC(token, "edge"   || nonceI || nonceK)
  ```
- Only Iran needs `ports`. A target with no host means kharej loopback. UDP is per-client streams with a 2 min idle release.
- `server_name` sets SNI and Host (for a CDN) and **turns certificate verification on**. Without it, wss does not verify the certificate; the token is the trust anchor.
- Ports stay bound across reconnects. While the tunnel is down, new connections are refused promptly.

### 2.4 Chain (`internal/tunnel/chain`)

Chain is not a tunnel mode. It is the supervisor behind `fallback_transports` (§2.1). `New(primary, fallbacks, dwell)` removes duplicates. `Run(ctx, sweep, start)` rotates one candidate at a time, with a 3 s teardown pause so the forwarded ports are free before the next candidate binds them, and a 250 ms settle poll. Candidates run one after another because each reverse server binds the same forwarded ports.

### 2.5 Bridge (`internal/tunnel/bridge`)

`Join(ctx, a, b)` is the final splice of the direct and L3 forwarders. It runs two `io.Copy` goroutines. On a clean EOF over plain TCP it calls `CloseWrite()` (half-close, FIN) rather than tearing both sides down. It unwraps metrics and limit wrappers only to reach the underlying `*net.TCPConn`.

### 2.6 Naive / Xray wrappers (`internal/tunnel/naive`)

See §2.1. `StartWithRetry` keeps the reverse engine stopped until its helper starts, retrying every second. Validation (`naive.Validate`) enforces exactly one reverse role, `transport = tcp`, no fallbacks/proxy/bindings, a loopback reverse target, absolute regular-file paths, and credentials without CR/LF. The engine writes generated helper configs with owner-only permissions, embeds the validated TLS material, supervises and restarts the helper, and reloads it when the certificate files change.

### 2.7 Portmap syntax (`internal/tunnel/portmap`)

Shared by all engines:
```
"443"                          :443          -> default:443
"443=8443"                     :443          -> default:8443
"443=10.0.0.5:8443"            :443          -> 10.0.0.5:8443
"127.0.0.1:443=8443"           bind one local address
"10000-10009"                  range, same ports
"10000-10009=20000-20009"      range, offset preserved
"443=10.0.0.1:80|10.0.0.2:80"  several backends (no ranges here)
"[::1]:443"                    IPv6 must be bracketed
```
"default" means kharej loopback for reverse and direct, and `peer_ip` for L3. Limits: 1024 ports per range, 4096 expanded ports in total.

### 2.8 Experimental short-HTTPS relay (`backpack short-https`)

A standalone foreground TCP relay for paths that kill a connection after a few packets. Each logical stream is carried as many small HTTPS/1.1 requests on fresh connections (at most 2 KiB each, with byte offsets and ACKs). Limits: 64 streams, a 7-day private IP certificate, no systemd unit, TCP only.
```
backpack short-https init --ip SERVER_PUBLIC_IP --target 127.0.0.1:PORT --port 8443 --dir /root/short-https-test
backpack short-https serve --config /root/short-https-test/server.json
backpack short-https client --config /root/client.json     # copy client.json over SSH, set its listen address
```

### 2.9 Built-in proxy

`backpack-proxy.service` runs `backpack --proxy`, a loopback SOCKS5 (with UDP) or HTTP proxy, so the kharej box can be its own backend. It refuses loopback, unspecified, link-local (including cloud metadata) and multicast destinations after DNS resolution. The doc warns that it becomes an open proxy without auth, because the tunnel exposes it on a public Iran port.

---

## 3. Install procedure (`install.sh`)

One-liner, run as root:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AminMGMT/BackPack/main/install.sh)
# optionally: ... install.sh) link apply 'backpack://…'   (install, then build the tunnel from a setup link)
```

Constants:
```bash
REPO="AminMGMT/BackPack"
BIN_PATH="/usr/local/bin/backpack"
INSTALL_DIR="/root/BackPack"
```

Steps:
1. Requires `EUID 0`. Accepts no arguments other than `[backpack] link apply '<link>'`.
2. Detects the architecture: `x86_64→amd64`, `aarch64→arm64`, `i?86→386`, `s390x`, `armv5/6/7` (via `uname` or `/proc/cpuinfo`). The asset is `backpack_linux_${ARCH}.tar.gz`.
3. Runs `mkdir -p /etc/backpack /root/BackPack/backups`.
4. `install_release`:
   - A local asset in `./release/`, `./dist/` or the script directory is used first, but only if that directory is **not world-writable** (`trusted_dir` checks the other-write bit). A `SHA256SUMS` beside it is verified; without one, the asset is installed unverified with a warning.
   - Otherwise it fetches `https://github.com/AminMGMT/BackPack/releases/latest/download/<asset>` and `.../SHA256SUMS`. A mismatch or a missing sums file means it **refuses** to install. Third-party GitHub proxies are deliberately not used.
5. `install_binary_from_tar`: extracts `backpack`, runs `install -m 0755` to `/usr/local/bin/backpack`, and writes `/root/BackPack` into `/etc/backpack/install_path` (read by the uninstaller).
6. Fallback, or `BP_BUILD_FROM_SOURCE=1`: builds from a trusted source checkout. It needs Go ≥ the `go.mod` version (`GO_VERSION 1.26.9`). It downloads Go from `go.dev`, `golang.google.cn` or `mirrors.aliyun.com` and checks it against pinned SHA-256 values. The build uses `GOPROXY=https://proxy.golang.org|https://mirror-go.runflare.com|https://goproxy.cn|direct`, `GOSUMDB=off`, `GOTOOLCHAIN=local` and `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`.
7. Optional helpers with `BP_HELPERS=naive|xray|naive,xray` (Linux, amd64/arm64, glibc for naive). Pinned archives are checked against hard-coded SHA-256 values and installed with no-clobber into `/usr/local/lib/backpack/helpers/<tool>/<version>-<arch>/`:
   - NaiveProxy `v154.0.8037.49-4` (klzgrad/naiveproxy)
   - sing-box `v1.14.2` (SagerNet), plus `libcronet.so`
   - Xray-core `v26.3.27` (XTLS)
8. Then `exec`s `backpack link apply …` if a link was given, opens the menu on a TTY, or prints `sudo backpack`.

Offline install (documented in the README):
```bash
scp install.sh SHA256SUMS backpack_linux_amd64.tar.gz root@SERVER:/root/
ssh root@SERVER "cd /root && sudo bash install.sh"
# or by hand:
sha256sum backpack_linux_amd64.tar.gz; tar xzf backpack_linux_amd64.tar.gz
mkdir -p /etc/backpack /root/BackPack/backups
install -m 0755 backpack /usr/local/bin/backpack
echo /root/BackPack > /etc/backpack/install_path
```

**Filesystem layout and systemd units** (`internal/app/app.go`, `internal/manage/core/*.go`):

| Path / unit | What |
|---|---|
| `/usr/local/bin/backpack` | binary |
| `/root/BackPack`, `/root/BackPack/backups` | release bundle, `.tar.gz` backups |
| `/etc/backpack/<name>.toml` | tunnel config (mode `0600`, `TunnelConfigMode`) |
| `/etc/backpack/<name>.metrics.json` | engine snapshot |
| `/etc/backpack/webui.json`, `telegram.json`, `nodes.json`, `audit.json` | panel, bot, fleet and audit state (0600) |
| `/etc/sysctl.d/zz-backpack.conf` | Optimize sysctls (legacy name `99-backpack.conf`) |
| `/usr/local/lib/backpack/helpers/...` | optional helpers |
| `backpack-<name>.service` | one per tunnel |
| `backpack-monitor.service` | `--monitor`, `Type=notify`, `WatchdogSec=120`, `StartLimitBurst=6` per 300 s |
| `backpack-webui.service` | `--webui` |
| `backpack-proxy.service` | `--proxy` |
| `backpack-restart-<name>` .service + .timer | optional scheduled restart (UTC, the same moment on both ends) |

The tunnel unit (`core/systemd.go`):
```ini
[Unit]
Description=Backpack Tunnel (%s)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backpack -c /etc/backpack/<name>.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

**Updates.** Menu option 8 checks an **Ed25519 signature over SHA256SUMS**. `app.ReleasePublicKey = "uDVeC9NUFceAuhg53ZWbBNTVSaMC8tEvtwWmcDZmV9Q="`, and since v1.8.2 an unsigned release is refused. It then checks the archive checksum, takes a restore point (binary plus configs), installs, migrates, restarts and health-checks, and rolls back automatically on failure. Updates can download through a tunnel peer. Channels are stable or beta.

---

## 4. Configuration file format (TOML, `config/*.go`)

One file per tunnel. Exactly one engine table is used. Defaults come from `cmd/defaults.go applyDefaults` unless noted. Presets (`internal/manage/tunnelspec/preset.go`) normally fill every tuning key.

### 4.1 `[server]` (reverse, Iran)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bind_addr` | string | required | tunnel/control listen address, e.g. `0.0.0.0:3080`, `[::]:3080` |
| `transport` | string | — | one of the 12 transports; both ends must match |
| `fallback_transports` | []string | `[]` | fallback chain, the same list on both ends |
| `fallback_dwell` | int s | 60 | seconds each candidate is held |
| `token` | string | `"backpack"` (warns: public default) | shared secret |
| `nodelay` | bool | false (presets: true) | disable Nagle |
| `keepalive_period` | int s | 75 | TCP keepalive / dead-peer timing |
| `channel_size` | int | 2048 | accept→handler queue |
| `log_level` | string | `info` | trace/debug/info/warn/error/fatal |
| `log_format` | string | `""` | `json` for JSON |
| `ports` | []string | — | forwarded mappings (§2.7) |
| `pprof` | bool | false | 127.0.0.1:6060 (heap contains token) |
| `mux_session` | int | 1 | mux sessions |
| `mux_version` | int | auto | 1 / 2 / auto (negotiated) |
| `mux_framesize` | int | 32768 | smux frame |
| `mux_recievebuffer` | int | 4194304 | session window (typo is part of the format) |
| `mux_streambuffer` | int | 65536 | per-stream window (smux v2 only) |
| `mux_con` | int | 8 | streams per mux session |
| `sniffer` | bool | false | per-port traffic log |
| `web_port` | int | 0 | per-tunnel monitor page (no auth) |
| `web_bind` | string | `127.0.0.1` | bind address of that page |
| `sniffer_log` | string | `backpack.json` | |
| `tls_cert`, `tls_key` | path | self-signed | wss/wssmux |
| `acme_domain`, `acme_email` | string | — | Let's Encrypt |
| `simple_auth` | bool | false | raw-token wss auth behind a TLS-terminating proxy |
| `heartbeat` | int s | 40 | control-channel beat |
| `accept_udp` | *bool | off | forward UDP too |
| `skip_optz` | bool | false | skip the engine's own sysctl/rlimit tuning |
| `mss` | int | 0 | TCP MSS on tunnel sockets |
| `so_rcvbuf`, `so_sndbuf` | int | 0 (4 MiB for kcp/xdi/pck/quic/udp) | socket buffers |
| `so_pin_tcp` | bool | false | pin buffers on TCP (disables autotuning) |
| `zero_copy` | bool | false | splice, plain tcp only |
| `proxy_protocol` | bool | false | PROXY v2 header to the backend (ignored on ws/wss/udp) |
| `max_connections`, `bandwidth_mbps` | int | 0 | limits |
| `preset` | string | — | label only: balance/turbo/aggressive/throughput |
| `kcp_mtu` | int | 1350 (1250 with FEC; presets write 1250) | |
| `kcp_interval` | int ms | 20 (presets: 10) | |
| `kcp_resend` | int | 2 | |
| `kcp_nodelay`, `kcp_nocongestion` | int | presets: 1/1 | |
| `kcp_sndwnd`, `kcp_rcvwnd` | int | 1024 | |
| `kcp_acknodelay` | bool | presets: true | |
| `kcp_datashards`, `kcp_parityshards` | int | 0/0 (presets 10/2, 10/3, 10/4, 10/1) | FEC |
| `pck_interface`, `pck_gateway_mac`, `pck_flags` | | auto, `["PA"]` | pck |
| `[server.naive]` | `binary listen username password certificate key` | | sing-box HTTP/2 inbound |
| `[server.xray]` | `binary listen mode uuid server_name path host certificate key private_key target short_id` | | xhttp/reality |

### 4.2 `[client]` (reverse, kharej)

Shares `transport`, `fallback_*`, `token`, `nodelay`, `keepalive_period`, `log_*`, `pprof`, `mux_*`, `sniffer*`, `web_*`, `simple_auth`, `skip_optz`, `mss`, `so_*`, `so_pin_tcp`, `zero_copy`, `preset`, `kcp_*`, `pck_*` with `[server]`. Client-only keys:

| Key | Default | Meaning |
|---|---|---|
| `remote_addr` | required | Iran `host:port` |
| `fallback_addrs` | `[]` | backup addresses for the same server |
| `connection_pool` | 8 | warm pool size |
| `retry_interval` | 3 s | redial wait |
| `dial_timeout` | 10 s | per dial |
| `aggressive_pool` | false | |
| `edge_ip` | — | CDN edge to dial |
| `proxy` | — | `socks5://…` / `http://user:pass@…` |
| `local_addr`, `interface`, `so_mark` | — | egress pinning |
| `load_balance`, `health_failover` | false | multi-address behaviour |
| `[client.naive]` | `binary server username password ca_file` | |
| `[client.xray]` | `binary server mode uuid server_name path host ca_file public_key short_id` | |

### 4.3 `[l3]`

| Key | Default | Meaning |
|---|---|---|
| `mode` | required | `dial` / `listen` (absent means no L3) |
| `addr` | required | peer `host:port` (dial) or bind (listen) |
| `token` | required | |
| `carrier` | `udp` | `udp quic pck sni xdi spoof` |
| `encap` | `gre` | `ipip` is read as GRE |
| `gre_key` | 0 | RFC 2890 key |
| `sni_domain` | `mci.ir` | sni carrier |
| `iface` | `bp0` | TUN name |
| `local_ip` | required | e.g. `10.10.0.1/30` |
| `peer_ip` | — | required if `local_ip` has no prefix |
| `mtu` | 1400 | interface MTU (576–9000) |
| `sockbuf` | 4 MiB | carrier buffers |
| `fec_data`, `fec_parity` | 0, 0 | FEC |
| `paths` | 1 | udp multipath sockets |
| `preset` | — | label |
| `txqueuelen` | 4096 | TUN queue |
| `qdisc` | `fq_codel` | `none` skips it |
| `auto_mtu` | true | path MTU probing |
| `mss_clamp` | 0 (auto) | `-1` off, or a value |
| `ports`, `accept_udp` | none, false | userspace forwarder |
| `max_connections`, `bandwidth_mbps` | 0 | forwarder limits |
| `spoof_profile`, `spoof_uplink`, `spoof_downlink` | `udp` | udp/icmp/tcp/icmpv6/ipip/gre |
| `spoof_src_ip`, `spoof_src_pool` | — | forged source(s), IPv4 |
| `spoof_peer_ip` | — | **required on the listener**: the peer's real IPv4 |
| `spoof_peer_src_ip` | — | pin the expected forged source |
| `spoof_interface`, `spoof_xdp_interface` | — | egress NIC / XDP fast path |
| `spoof_sockbuf` (4 MiB), `spoof_mtu` (1500) | | |
| `spoof_icmp_reply`, `spoof_ttl_jitter`, `spoof_random_dscp`, `spoof_shuffle_port`, `spoof_port_min/max`, `spoof_padding`, `spoof_padding_max`, `spoof_fake_tls` | false | DPI-evasion cosmetics (padding, fake TLS and icmp_reply must match on both ends) |
| `pck_interface`, `pck_gateway_mac`, `pck_flags` | auto | pck/sni |

### 4.4 `[direct]`

`role` (`iran`/`edge` or `kharej`/`origin`), `addr`, `token`, `transport` (`tcp`/`stealth`/`ws`/`wss`, default tcp), `server_name`, `tls_cert`, `tls_key`, `acme_domain`, `acme_email`, `ports`, `accept_udp`, `max_connections`, `bandwidth_mbps`, `preset`, `sessions` (1), `dial_timeout` (10), `retry_interval` (3), `keepalive_period`, `nodelay`, `mss` (set on both ends), `mux_version`, `mux_framesize`, `mux_recievebuffer`, `mux_streambuffer`.

### 4.5 Load-time validation (`cmd/defaults.go validateConfig`)

The checks run in this order: `checkNaive`, `checkXray`, `checkOutbound`, `checkXdi`, `checkSpoof`, `checkPck`, `checkFallbackChain`, `checkEngine`. They enforce:
- root (or CAP_NET_RAW) and Linux for pck/sni/xdi/spoof. The error suggests `setcap cap_net_raw+ep /usr/local/bin/backpack`.
- valid `pck_flags` and MAC address; the interface must exist.
- `spoof_peer_ip` on a spoof listener; IPv4-only pools.
- a warning when `rp_filter` is strict (it takes the maximum of `all` and the interface setting).
- no outbound settings on datagram transports.

On reload, an invalid edit is logged and the running config is kept. `backpack check -c <file>` runs the same checks without starting anything.

### 4.6 Example configs

**Reverse TCP (Turbo-like):**
```toml
# Iran: /etc/backpack/web.toml
[server]
bind_addr        = "0.0.0.0:3080"
transport        = "tcp"
token            = "<64-hex random>"
ports            = ["443", "8443=127.0.0.1:2096"]
accept_udp       = false
nodelay          = true
keepalive_period = 75
heartbeat        = 40
channel_size     = 4096
preset           = "turbo"

# Kharej
[client]
remote_addr      = "IRAN_IP:3080"
transport        = "tcp"
token            = "<same token>"
connection_pool  = 8
retry_interval   = 3
dial_timeout     = 10
nodelay          = true
preset           = "turbo"
```

**Reverse stealth / tcpmux / wss.** Same shape as above, with `transport = "stealth"` (nothing else needed), or `"tcpmux"` (plus `mux_con`, `mux_version = 2`, `mux_recievebuffer`, `mux_streambuffer`), or `"wssmux"` on a CDN port:
```toml
[server]
bind_addr   = "0.0.0.0:443"
transport   = "wssmux"
token       = "<token>"
acme_domain = "tunnel.example.com"      # or tls_cert/tls_key, or nothing for self-signed
ports       = ["2053"]
[client]
remote_addr = "tunnel.example.com:443"
transport   = "wssmux"
token       = "<token>"
edge_ip     = "104.16.x.x"              # optional CDN edge
```

**Reverse KCP + FEC (Turbo values):**
```toml
[server]
bind_addr = "0.0.0.0:4000"
transport = "kcp"
token = "<token>"
ports = ["51820"]
accept_udp = true
so_rcvbuf = 8388608
so_sndbuf = 8388608
kcp_mtu = 1250
kcp_interval = 10
kcp_resend = 2
kcp_nodelay = 1
kcp_nocongestion = 1
kcp_acknodelay = true
kcp_sndwnd = 1024
kcp_rcvwnd = 1024
kcp_datashards = 10
kcp_parityshards = 3
# [client] mirrors these with remote_addr = "IRAN_IP:4000"
```

**Reverse with a fallback chain:**
```toml
[client]
transport           = "wss"
fallback_transports = ["quic", "kcp", "tcpmux"]
fallback_dwell      = 60
fallback_addrs      = ["5.6.7.8:443", "edge.example.com:443"]
health_failover     = true
```

**Reverse Naive (managed helper):** see `docs/transports.md`. Iran uses `[server] bind_addr = "127.0.0.1:3080"`, `transport = "tcp"`, plus `[server.naive] binary=/usr/local/lib/backpack/helpers/sing-box/v1.14.2-amd64/sing-box, listen="0.0.0.0:443", username, password, certificate, key`. Kharej uses `[client] remote_addr="127.0.0.1:3080"` plus `[client.naive] binary=…/naive, server="tunnel.example.com:443", username, password`.

**L3 over UDP (plain TUN):**
```toml
# Iran
[l3]
mode     = "dial"
addr     = "KHAREJ_IP:9000"
token    = "<token>"
local_ip = "10.10.0.1/30"
peer_ip  = "10.10.0.2"
# Kharej
[l3]
mode     = "listen"
addr     = "0.0.0.0:9000"
token    = "<token>"
local_ip = "10.10.0.2/30"
peer_ip  = "10.10.0.1"
```

**L3 over pck with port forwarding and FEC (Iran side):**
```toml
[l3]
mode       = "dial"
addr       = "KHAREJ_IP:9000"
token      = "<token>"
carrier    = "pck"
local_ip   = "10.10.0.1/30"
peer_ip    = "10.10.0.2"
mtu        = 1380
fec_data   = 10
fec_parity = 3
ports      = ["443", "2053-2060", "8080=80"]
accept_udp = true
```

**L3 spoof:**
```toml
# Iran (dial)
[l3]
mode = "dial"
addr = "KHAREJ_IP:9000"
token = "<token>"
carrier = "spoof"
local_ip = "10.10.0.1/30"
peer_ip = "10.10.0.2"
spoof_profile = "udp"
spoof_src_ip = "A.B.C.D"            # forged source that the route lets through
spoof_peer_src_ip = "E.F.G.H"       # what kharej forges
# Kharej (listen)
[l3]
mode = "listen"
addr = "0.0.0.0:9000"
token = "<token>"
carrier = "spoof"
local_ip = "10.10.0.2/30"
peer_ip = "10.10.0.1"
spoof_profile = "udp"
spoof_peer_ip = "IRAN_REAL_IP"      # required
spoof_src_ip = "E.F.G.H"
spoof_peer_src_ip = "A.B.C.D"
```

**L3 quic / xdi / sni.** Same as the UDP pair, with `carrier = "quic"`, `"xdi"`, or `"sni"` (plus `sni_domain = "allowed.example"`).

**Legacy direct L4:**
```toml
# Iran
[direct]
role = "iran"
addr = "KHAREJ_IP:8443"
token = "<token>"
transport = "stealth"
ports = ["443", "2053-2060"]
# Kharej
[direct]
role = "kharej"
addr = "0.0.0.0:8443"
token = "<token>"
transport = "stealth"
```

### 4.7 Setup link (`internal/manage/sharelink.go`)

The link is `backpack://` + v1 JSON, gzipped and base64url-encoded. It is **not encrypted** and carries the token. Fields:

- Identity and transport: `v`, `k` (reverse/direct), `f` (iran/kharej), `n`, `t` (token), `tr` (transport/carrier), `e`, `sni`.
- Endpoint: `p` (port), `h` (host), `hs` (backup hosts).
- Tuning: `pr` (preset), `po` (ports), `u` (udp), `m`, `mt`.
- L3 addressing and FEC: `li`/`pi` (swapped by the receiver), `fd`, `fp`, `pa`, `gk`, `lm`, `am`.
- Spoof: `sp`, `su`, `sd`, `ss`, `sl`, `si`.
- Reverse extras: `sa`, `mv`, `ft`/`fw` (fallback chain).
- Restart schedule: `rh`/`rm`.

It is applied with `backpack link apply '<link>'`. Applying the same link twice is refused.

---

## 5. CLI, menu, web panel, Telegram, fleet

### 5.1 Interactive menu (`sudo backpack`)

| # | Option |
|---|---|
| 0 | **Connection Test.** Iran starts a real engine for every transport and carrier on free ports and prints a link. Kharej joins, and each tunnel must carry 60 one-second echoes plus a bulk transfer. Reverse set: `tcp tcpmux stealth pck ws wss wsmux wssmux kcp quic udp naive xhttp reality`. Direct set: `udp quic pck xdi sni` (plus spoof if a source is given). Nothing is left behind afterwards. |
| 1 | **Setup Iran** (Reverse or Direct) |
| 2 | **Setup Kharej** (Setup Link or Manual) |
| 3 | **Manage**: Manage Tunnels (Edit/Start/Stop/Restart/Live Log/Delete/Setup Link), Status, Health Check, Link Test (latency/jitter/loss, transport recommendation, FEC sizing), Exit Health, IP Spoofing Tester, Tunnel Metrics, Restart ALL, Auto Refresh, Built-in Proxy, File Locations |
| 4 | Backup & Restore (`.tar.gz` of tunnels, panel password, Telegram, certificates, schedules) |
| 5 | Web Panel (port, login code, password, certificate, 2FA, restart/stop) |
| 6 | **Optimize** (sysctl, §7) |
| 7 | Telegram Bot |
| 8 | Update (verified, restore points, channel) |
| 9 | Uninstall |

Reverse Iran wizard order: transport family → variant → Iran IP/domain → backup addresses → tunnel port → listen on IPv6 → forwarded ports → name → token (generated) → carry UDP → transport-specific questions (cert, simple auth, pck flags) → PROXY protocol → preset → fine-tune → scheduled restart → summary with **Setup Link** and a one-line "Install BackPack And Set Up This Tunnel" command.

Direct (L3) Iran wizard order: carrier (xDi, PCK, UDP, Quic, IP Spoofing, SNI Spoofing) → kharej IP → tunnel port `[9000]` → forwarded ports (blank means TUN only) → name → token → UDP → FEC → multipath (UDP, 2–8) → preset → fine-tune (addresses default to a free `10.10.N.0/30`, MTU, interface, GRE key, segment cap) → scheduled restart. Spoof and SNI keep a manual two-sided wizard: kharej suggests the token and Iran pastes it.

Edits are applied atomically and **reverted automatically** if the tunnel does not come back.

### 5.2 Non-interactive CLI (`internal/cli`)

```
backpack tunnel list [--json]
backpack tunnel status <name> [--json]
backpack tunnel reset-usage <name> | --all
backpack check -c <file>
backpack link apply [--name N] [--host IP] '<setup link>'
backpack proxy enable <socks5|http> <port> [--user U --pass P]
backpack proxy disable | status [--json]
backpack version [--json]
```
Exit codes: 0 ok, 1 failed, 2 usage, 3 not found, 4 unhealthy.

### 5.3 Web panel (`internal/webui`)

- Defaults to port **7777** over HTTP. HTTPS can be turned on with self-signed, Let's Encrypt (`tls_domain`), or your own PEM files (renewals are picked up without restart).
- The panel lives under a random **secret base path** (`http://host:7777/<BasePath>/`; `/` disables it).
- Login uses an 8-digit random code or a custom password. Optional TOTP 2FA (RFC 6238) with 10 hashed recovery codes. A pending login dies after 3 wrong codes, and failed logins are rate-limited per address.
- Origin checks on state-changing requests act as CSRF protection, including against sibling subdomains.
- Scopes are `read`, `write` and `admin`. API tokens must have a name and an expiry, only their SHA-256 is stored, and they are sent as `Authorization: Bearer`. `/metrics` serves Prometheus.
- There is a hash-chained **audit record** in `/etc/backpack/audit.json` (last 5000 entries). The chain head is forwarded to Telegram.
- Screens: dashboard and monitoring (CPU/RAM/disk/traffic, tunnel state, real ping, logs), settings, fine-tune drawer, add/edit tunnels, servers (fleet), conntest. The README calls the panel monitoring-focused, but the new panel can also create tunnels on both ends through managed servers.

### 5.4 Telegram bot (`internal/telegram`, inside `backpack-monitor`)

- Status reports, alerts (CPU/mem/disk thresholds, tunnel down/up, new release), and start/stop/restart.
- Roles are owner, admin, and read-only admin (`:ro`). Only the owner can get the panel URL and password or a backup.
- **Relay from Iran.** A loopback port on a live tunnel forwards to `api.telegram.org:443`, and kharej makes the outbound connection. TLS is still verified end-to-end against `api.telegram.org`. The bot picks a live tunnel automatically and fails over. "Diagnose relay" names the broken hop.

### 5.5 Managed servers / SSH node setup (`internal/node`, `nodecmd.go`)

- The panel **dials out over SSH** to each node with address, port, user and **password**. The password is stored in `/etc/backpack/nodes.json` (0600, root) and never sent to the browser.
- Host key: TOFU. The SHA-256 fingerprint is pinned on first contact, a mismatch is refused, and changing the address clears the pin and requires the password again.
- If BackPack is missing on the node, the panel runs `install.sh` there. That path checks SHA-256 only, not the release signature.
- The far side runs one command, `backpack node exec -`. It reads a base64 JSON request from stdin (stdin rather than argv, so the token stays out of `ps`) and performs one op from a closed list: `hello apply list status settings logs linktest delete start stop restart`. There is no generic exec. The panel's delete op deliberately does not remove the far end's tunnel.
- **Add tunnel** writes this end and mirrors the far end. Edits, start, stop and restart reach both ends. "Check the fleet" reports drift (`missing`, `stopped`, `running`, `changed`, `unexpected`) without repairing anything.
- Rolling upgrades are planned in waves with a soak period and pinning (`node/rollout.go`).
- Requirements: sshd must allow password auth, and nodes behind NAT cannot be managed.

---

## 6. L3 tunnel details (`docs/l3-direct-tunnel.md`, `internal/tunnel/l3`)

**TUN and interface setup** (`tun_linux.go configureInterface`):
```
ip addr add <local_ip> dev bp0             # or: ip addr add <local> peer <peer> dev bp0  (bare address)
ip link set dev bp0 mtu <mtu>
ip link set dev bp0 txqueuelen 4096
ip link set dev bp0 up
ip route replace <peer_ip> dev bp0          # only for /32 or /128 local prefixes
tc qdisc replace dev bp0 root fq_codel      # best effort
```

**Addressing.** The wizard allocates a free `10.10.N.0/30`: Iran is `.1`, kharej is `.2`. The setup link carries both addresses and the receiver swaps them. Identical `local_ip`/`peer_ip` is refused. One tunnel carries both IPv4 and IPv6 inner packets, and there is no separate 6in4 mode. For the outer carrier, udp and quic work over v4 or v6; pck, sni, xdi and spoof are IPv4.

**MTU.** The default is 1400 on purpose. The budget is `mtu = path − outer IP − carrier − 29 (session) − encap`, which comes to 1439 for udp on a clean 1500 path. **auto_mtu** (on by default) sends encrypted, padded `typeProbe` messages after the session is up, binary-searches the largest size that gets acknowledged, sets the interface MTU and recomputes the MSS clamp. Each direction is measured separately, and it re-measures every 30 min. Example log line:
```
l3: the path only carries 1371 bytes, not 1400 — interface lowered to 1371.
```
quic DATAGRAMs start at 1232 bytes and grow with QUIC PMTU discovery.

**MSS clamp** (`internal/tunnel/mssclamp`). This is on by default (`mss_clamp = 0` means MTU−40 for IPv4 and MTU−60 for IPv6). It installs four rules: {iptables, ip6tables} × {FORWARD, OUTPUT}:
```
iptables -t mangle -A FORWARD -o bp0 -p tcp --tcp-flags SYN,RST SYN \
  -m comment --comment backpack-l3-mss-bp0 -j TCPMSS --set-mss <mtu-40>
```
Old copies are swept (`-D` in a loop) before adding and on stop. Check with `iptables -t mangle -S | grep backpack-l3-mss`. `-1` turns clamping off.

**Routing.** The interface is an ordinary point-to-point link. To route a LAN or the internet across it, add your own `ip route`/`ip rule`. Optimize sets `net.ipv4.ip_forward=1`. BackPack does not add NAT or MASQUERADE rules itself; the operator does that, for example with iptables DNAT over `bp0` for kernel-speed port forwarding. The optional `ports` forwarder is userspace. Its listeners outlive session rebuilds, and while the tunnel is down it refuses connections ("connections to :PORT are being refused because the tunnel is not up yet").

**Multipath** (`paths`, udp only). Uses N consecutive ports starting at the tunnel port, all of which must be open on the listener. Both ends must use the same N. It helps against per-flow shapers (measured 5.8 → 23.6 Mbit/s with 4 paths against an 8 Mbit/s per-flow cap).

**Carrier side effects.**
- xdi: installs `u32` ACCEPT/DROP rules for its own echo tag.
- pck/sni: install `filter OUTPUT … --tcp-flags RST RST -j DROP` and `raw PREROUTING/OUTPUT … -j NOTRACK`, tagged `backpack-pck-<port>`.
- spoof (tcp profile): installs an RST-drop rule; the icmp profile installs a rule to drop auto-replies.

**Troubleshooting strings.** `a handshake from … did not authenticate` means a token mismatch. `the two ends wrap packets differently` means an encap or GRE key mismatch.

---

## 7. Kernel/sysctl tuning, health checks, diagnostics

**Optimize** (`internal/optimize/optimize.go`) writes `/etc/sysctl.d/zz-backpack.conf` and applies the values live:
```
net.core.rmem_max=268435456            net.core.wmem_max=268435456
net.core.rmem_default=16777216         net.core.wmem_default=16777216
net.core.optmem_max=65536
net.ipv4.tcp_rmem=4096 87380 268435456 net.ipv4.tcp_wmem=4096 65536 268435456
net.core.somaxconn=65536               net.core.netdev_max_backlog=250000
net.ipv4.tcp_max_syn_backlog=20480
net.ipv4.ip_local_port_range=32768 60999   (deliberately NOT widened)
net.ipv4.tcp_tw_reuse=1  tcp_fin_timeout=15  tcp_max_tw_buckets=1440000
net.ipv4.tcp_window_scaling=1  tcp_fastopen=3  tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0  tcp_notsent_lowat=131072
net.core.default_qdisc=fq  net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.ip_local_reserved_ports=<every tunnel/forwarded port>
```
It also writes `/etc/security/limits.conf` nofile 1048576 for `*` and root. Each unit sets `LimitNOFILE=1048576`.

At startup the engine runs `cmd.ApplyTCPTuning` (unless `skip_optz`). It applies a subset (`optimize.EngineStartupTuning`) from the same table, so the two cannot drift apart, and calls setrlimit NOFILE 1048576. A container without the needed privilege only gets a warning.

**Presets** (`tunnelspec/preset.go`):

| Preset | pool | sockbuf | mux_con | mux recv / stream | keepalive/heartbeat | KCP wnd | FEC |
|---|---|---|---|---|---|---|---|
| balance | 4 | 4 MB | 4 | 4 MB / 256 KB | 75/40 | 512 | 10:2 |
| turbo (default) | 8 | 8 MB | 8 | 16 MB / 2 MB | 75/40 | 1024 | 10:3 |
| aggressive | 16 (aggressive_pool) | 32 MB | 16 | 32 MB / 16 MB | 60/25 | 2048 | 10:4 |
| throughput (kcp only) | 16 | 32 MB | 8 | 64 MB / 32 MB | 75/40 | 4096, 20 ms tick, ACKs batched | 10:1 |

All KCP presets use `kcp_mtu = 1250`, a 10 ms tick, resend 2, nodelay 1 and nocongestion 1. `nodelay = true` everywhere.

**Health Check** (Manage → Health Check, `internal/manage/health/diagnose*.go`) checks:
- that the kernel tuning is applied and the panel is running;
- each tunnel's state and its real TCP reachability;
- whether the path carries full-size packets (it names the MSS value to set);
- certificate expiry and token strength;
- that the monitor service is running.

It prints a fix under each problem.

**Watchdog** (`health/watchdog.go`, inside `backpack-monitor`) works from engine snapshots, not the socket table:
- It checks every 25 s and restarts after 2 consecutive unhealthy checks, at most once per 3 min per tunnel.
- 4 restarts within 1 h is reported as "flapping". A fleet-wide flap report also exists.
- It has a throughput-stall ladder (report → engine self-reload → process restart → give up), persisted to disk.
- It follows each restart with a recovery report.

**Connection Test** (`manage/conntest.go`, menu 0). See §5.1. It joins for up to 15 min, allows 60 s to the first echo, soaks 60 echoes, then measures directional goodput. Results are OK, DROPPED or NEVER UP, with RTT and speed. It also covers REALITY cover-endpoint selection (Microsoft → Bing → Apple, verified by a real helper echo).

**Other diagnostics.** Link Test (route latency, jitter and loss; recommends a transport, timers and FEC ratio). Exit Health (scores addresses). IP Spoofing Tester (two-node; finds which forged sources cross the path). Tunnel Metrics (KCP retransmits, loss, FEC repairs; totals survive restarts). Live Log (`journalctl -u backpack-<name> -f`).

---

## 8. Security observations

**Strengths:**
- Release integrity: an Ed25519 signature over SHA256SUMS plus the archive checksum, and unverifiable archives are refused. The installer refuses third-party GitHub mirrors and world-writable local asset or source directories. The Go toolchain and the optional helpers are pinned by SHA-256.
- Tunnel configs are 0600 (since a fix; they used to be 0644). Every other secret file is 0600 as well.
- The token is compared in constant time. Encrypted modes stay silent to unauthenticated peers.
- L3 crypto follows WireGuard closely: NNpsk0, explicit counters, a 2048-bit replay window, header AAD, 2-min rekey, handshake timestamps against replay, domain-separated PSK, and encap ID authenticated in the handshake.
- QUIC and WSS bind the token to TLS exporter material with mutual HMAC proofs. A man in the middle that terminates TLS learns nothing.
- Direct L4 uses mutual HMAC challenge-response with direction labels.
- The panel has a secret base path, a rate limiter, TOTP 2FA, scoped expiring API tokens stored hashed, origin/CSRF checks, and a hash-chained audit log anchored in Telegram.
- The fleet uses a closed op list, passes requests on stdin (keeping tokens out of `ps`), and pins host keys TOFU.
- The built-in proxy blocks loopback, link-local and metadata destinations. pprof binds loopback only. Per-tunnel monitor pages default to 127.0.0.1.

**Weaknesses and risks:**
1. **Plain transports (`tcp`, `tcpmux`, `udp`, `ws`, `wsmux`) send the token in cleartext.** An on-path attacker can steal it, or impersonate the Iran server and steer kharej to dial arbitrary addresses, because Iran tells kharej which target to dial. Use stealth, kcp, pck, quic, wss or xdi on untrusted paths.
2. **The default token is `"backpack"`** when none is set. It only triggers a warning.
3. **KCP family crypto** (kcp, pck, xdi) is kcp-go `NewAESBlockCrypt`, with a key from PBKDF2 of the token and a **fixed salt** (`"backpack-kcp-v1"`). kcp-go's block crypt is AES-CFB with a CRC checksum, which gives no AEAD and no forward secrecy (an inference from kcp-go's known design). Anyone who learns the token can decrypt recorded traffic.
4. **Stealth/L3 "mutual authentication" is PSK-only** (no static keys). Security reduces to token entropy, and the token can be guessed offline from a captured handshake if it is weak. The wizard generates 64 random characters, so it is fine by default.
5. **The L3 header is in the clear**: 13 bytes, with the kind byte in 1..5, a 32-bit session ID and a 64-bit counter. On the plain udp carrier this is a fingerprintable structure for DPI.
6. **Setup links are unencrypted** (gzip + base64) and carry the token and all parameters. They must be shared out-of-band.
7. **The web panel serves plain HTTP on 7777 by default**, so the login code and session cookie cross the network in the clear unless HTTPS is enabled. The 8-digit numeric code is only about 26.6 bits; it depends on the rate limiter and the secret path.
8. **The fleet stores root SSH passwords** in `nodes.json`, and the panel holds root on every node. A compromised panel means every node is compromised. Upgrading a node through the panel runs `install.sh`, which checks the checksum only, not the signature.
9. **`simple_auth`** hands the raw token to whatever terminates TLS. **wss without `server_name`** does not verify certificates; it relies on the token.
10. Raw carriers add iptables rules (RST drop, NOTRACK, ICMP accept, TCPMSS) and require root or CAP_NET_RAW/NET_ADMIN. The engine runs as root.
11. **IP spoofing is intentionally a source-forging feature.** It needs `rp_filter` relaxed and only works on networks without BCP38. Operators should understand the legal and ethical implications. The SNI carrier impersonates allowed domains (default `mci.ir`).
12. The built-in proxy without auth becomes an open proxy through the public Iran port.
13. The decoy nginx on WSS derives its version, date and ETag from the token. This is a fingerprinting countermeasure, but it adds another token-derived artefact.
14. The install one-liner is `curl | bash` as root from GitHub raw. It trusts GitHub TLS for the script itself (the release binary is verified afterwards).

---

## 9. Quick recipes: manual Iran⇄kharej setup

General steps for every mode:
1. Install on both servers (§3).
2. Run `sudo backpack` → 6 (Optimize) on both.
3. Generate a token, e.g. `openssl rand -hex 32`.
4. Write the file to `/etc/backpack/<name>.toml` with mode 0600.
5. Run `backpack check -c /etc/backpack/<name>.toml`.
6. Create the unit (as in §3) at `/etc/systemd/system/backpack-<name>.service`, then `systemctl daemon-reload && systemctl enable --now backpack-<name>`. Creating the tunnel through the menu does all of this for you.
7. Verify with `backpack tunnel status <name>` and `journalctl -u backpack-<name> -f`.

The quickest route is to use the wizard on Iran, copy the `backpack://` link, and run `backpack link apply '<link>'` on kharej. Or, on a fresh kharej: `bash <(curl -fsSL …/install.sh) link apply '<link>'`.

### A. Reverse TCP (simplest; Iran must accept inbound on the tunnel port)
- Iran: `[server] bind_addr="0.0.0.0:3080"`, `transport="tcp"`, `token=T`, `ports=["443"]`. Open 3080/tcp and 443/tcp.
- Kharej: `[client] remote_addr="IRAN:3080"`, `transport="tcp"`, `token=T`. The service listens on `127.0.0.1:443`.
- Users connect to `IRAN:443`.

### B. Reverse TCP Mux / Stealth / PCK
- Same as A, with `transport = "tcpmux"`, `"stealth"` or `"pck"` on **both** ends.
- PCK: both ends root and Linux, IPv4, `iptables` installed. Optional `pck_flags = ["PA","A"]`.
- Stealth is the preferred choice when an encrypted, fingerprint-free TCP transport is needed.

### C. Reverse UDP + KCP + FEC (lossy routes, gaming)
- Iran: `transport="kcp"`, `bind_addr="0.0.0.0:4000"`, plus the KCP keys from §4.6 (or `sudo backpack` → Turbo). Open 4000/udp.
- Kharej: mirror the KCP keys. `kcp_datashards`/`kcp_parityshards` must match.
- Add `accept_udp=true` for WireGuard or Xray UDP, and open those ports for `/udp` on Iran's firewall.

### D. Reverse QUIC
- `transport = "quic"` on both ends; open the UDP port on Iran. Upgrade Iran first, because a new client never sends a plain token.

### E. Reverse WS / WSS (CDN)
- Iran: `transport="wssmux"`, `bind_addr="0.0.0.0:443"`, `acme_domain="t.example.com"` (DNS proxied through the CDN), `ports=[...]`.
- Kharej: `remote_addr="t.example.com:443"`, `transport="wssmux"`, optional `edge_ip`.
- Behind your own NGINX TLS termination: `simple_auth = true` on both ends.

### F. Reverse xDi (only ICMP gets through)
- `transport = "xdi"` on both ends. Root on both. ICMP echo must be allowed. Expect low throughput.

### G. Reverse + Naive / XHTTP / REALITY
1. Install the helpers on both servers: `BP_HELPERS=naive,xray bash install.sh`.
2. Iran: `[server] bind_addr="127.0.0.1:3080"`, `transport="tcp"`, plus `[server.naive]` or `[server.xray]` with a public `listen="0.0.0.0:443"` and the certificate (or REALITY `private_key`, `short_id`, `target`).
3. Kharej: `[client] remote_addr="127.0.0.1:3080"`, plus `[client.naive]`/`[client.xray]` pointing `server` at `IRAN:443`.
4. Using the wizard and its Setup Link is strongly advised here.

### H. Direct L3 over UDP (Iran has no usable inbound port; full private network)
1. Kharej: `[l3] mode="listen"`, `addr="0.0.0.0:9000"`, `token=T`, `local_ip="10.10.0.2/30"`, `peer_ip="10.10.0.1"`. Open 9000/udp.
2. Iran: `[l3] mode="dial"`, `addr="KHAREJ:9000"`, `token=T`, `local_ip="10.10.0.1/30"`, `peer_ip="10.10.0.2"`, optional `ports=["443"]` (target defaults to `10.10.0.2:443`).
3. Test from Iran with `ping 10.10.0.2`.
4. If downloads stall, leave `auto_mtu` and `mss_clamp` at their defaults. For a per-flow-shaped path, add `paths = 4` on both ends and open 9000–9003/udp.

### I. Direct L3 over QUIC / PCK / SNI / xDi
- Same as H with `carrier = "quic"` (no root, looks like HTTP/3), `"pck"` (root, IPv4, looks like an established TCP flow; set `mtu ≈ 1380`), `"sni"` (pck plus `sni_domain` of a domain your route allows), or `"xdi"` (ICMP).
- Add `fec_data = 10` and `fec_parity = 3` on both ends for lossy paths.

### J. Direct L3 over IP spoofing
1. Run Manage → IP Spoofing Tester first, to find a forged source that crosses the route.
2. Relax `rp_filter` on both hosts: `sysctl -w net.ipv4.conf.all.rp_filter=2` and the same on the receiving interface.
3. Kharej (listen): `spoof_peer_ip=IRAN_REAL`, `spoof_src_ip=<its forged src>`, `spoof_peer_src_ip=<Iran's forged src>`.
4. Iran (dial): `spoof_src_ip=<forged>`, `spoof_peer_src_ip=<kharej's forged>`.
5. Both ends use the same `spoof_profile` (and uplink/downlink pair). This mode uses the manual wizard and has no setup link.

### K. Legacy direct L4 (stream)
- Kharej: `[direct] role="kharej"`, `addr="0.0.0.0:8443"`, `token=T`, `transport="stealth"`. Open 8443/tcp.
- Iran: `[direct] role="iran"`, `addr="KHAREJ:8443"`, `token=T`, `transport="stealth"`, `ports=["443"]`.
- Users connect to `IRAN:443`, which reaches kharej `127.0.0.1:443`.

### L. Several kharej behind one Iran
- Build one L3 tunnel per kharej (`bp0`/`bp1`, each with its own `10.10.N.0/30` and token).
- On one of them, set `ports = ["443=10.10.0.2:443|10.10.1.2:443"]`. New connections go to the least-loaded kharej.

---

## 10. Summary (15 lines)

1. BackPack v1.9.0 is a single Go binary for Iran⇄kharej tunnelling. It contains the engine, a TUI menu, a CLI, a web panel (7777), a monitor/Telegram bot, a proxy and an SSH fleet manager.
2. One tunnel is one TOML file in `/etc/backpack`, one `backpack-<name>.service` and one process. The engine is chosen by table, in the order `[l3]`, `[direct]`, `[server]/[client]`.
3. Reverse mode (default): Iran listens and exposes ports; kharej dials in with a control channel plus a pre-warmed pool. It has 12 transports.
4. The plain reverse transports (tcp, tcpmux, udp, ws, wsmux) send the token in cleartext. Stealth (Noise NNpsk0), KCP/PCK/xDi (AES with a PBKDF2 token key), QUIC and WSS (TLS-bound HMAC) protect it.
5. The Direct wizard builds an L3 TUN tunnel. Iran dials and kharej listens, GRE is done in userspace inside Noise NNpsk0 (ChaCha20-Poly1305, 2048-bit replay window, 2-min rekey), and the carrier is one of udp, quic, pck, sni, xdi or spoof.
6. L3 defaults: `bp0`, `10.10.N.0/30`, MTU 1400 with auto-MTU probing, an MSS clamp through iptables TCPMSS (FORWARD and OUTPUT, v4 and v6), fq_codel, txqueuelen 4096, optional FEC and udp multipath.
7. Legacy `[direct]` L4 is Iran dialling smux over tcp, stealth, ws or wss with mutual HMAC nonce auth. Naive, XHTTP and REALITY helpers can wrap TCP reverse on loopback.
8. Reliability features: fallback addresses, health-scored failover or load balancing, a transport fallback chain (rendezvous within one dwell, no negotiation), and a watchdog that restarts tunnels from 30-s metrics snapshots.
9. The installer fetches `github.com/AminMGMT/BackPack` release assets, verifies SHA256SUMS, installs `/usr/local/bin/backpack`, can build from source with pinned Go, and can install pinned helpers.
10. Updates verify an Ed25519 signature over SHA256SUMS, take restore points, and roll back if health checks fail.
11. Optimize writes `/etc/sysctl.d/zz-backpack.conf` (BBR+fq, 256 MB buffer ceilings, ip_forward, reserved ports, no widened ephemeral range) and nofile 1048576.
12. Diagnostics: Connection Test (live matrix of every transport), Link Test, Health Check with fixes, Exit Health, Spoof Tester, and KCP/FEC metrics.
13. Panel security: secret base path, an 8-digit code or password, TOTP, scoped hashed API tokens, a hash-chained audit log. It is HTTP by default.
14. The fleet uses root SSH passwords stored on the panel with TOFU host keys and a closed op list (`node exec -`). The Telegram bot is relayed via kharej from Iran.
15. Main risks: cleartext tokens on plain transports, the "backpack" default token, unencrypted setup links, non-AEAD KCP crypto, a panel holding root on every node, and the spoof/SNI carriers that need root and relaxed filtering.
