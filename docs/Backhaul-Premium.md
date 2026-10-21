# Backhaul Premium (closed-source core + `backhaul.sh` v1.0.0): technical reference

> **Sources analysed** (`/home/user/tunnels-kb/sources/backhaul-premium`): `install.sh`, `backhaul.sh` (obfuscated),
> `backhaul.decoded.sh` (941 lines, its plain text), `backhaul_premium.bin` (the core), `jq.bin`.
> **Everything here comes from static analysis.** No file was executed, sourced or eval'd. The core binary was only parsed
> (`file`, `readelf`, `strings`, byte greps, Mandiant GoReSym, and Mandiant GoStringUngarbler, which emulates code under
> unicorn and never runs it natively). Nothing about the license check was patched or bypassed.
> Upstream comparison: [Backhaul.md](Backhaul.md) (Musixal/Backhaul v0.7.2, open source).
>
> Side files produced: `sources/backhaul-premium/recovered_strings.txt` (categorised plaintext strings) and
> `sources/backhaul-premium/recovered_symbols.txt` (11,648 functions recovered from pclntab by GoReSym).

## 0. TL;DR / red flags

| # | Finding | Severity |
|---|---|---|
| 1 | Installer and core are fetched over **plain HTTP from bare IPs** (`5.145.114.119:8080`, `79.175.167.114:2095`) or `script.backhaul.top:2095`, with **no checksum or signature**, and run as root. | High (supply chain / MITM) |
| 2 | The core is **closed-source, garble-obfuscated Go** with an **online license check**. At start-up it learns the host's public IP from `api.ipify.org` and contacts `https://license1.rocektserver.com`, `https://validator.backhaul-dev.com` and `https://validator.xtreme-cloud.eu.org` (paths `/getip`, `/nonce`, `/validation`, `/vegeta`), sending at least `server_ip`, `backhaul_version`, `transport_type`, `client_id`. Responses carry `license`, `expires_at`, `signature`, `nonce`, **`aes_key`** and `payload`. The tunnel stops on `IP_MISMATCH`, `EXPIRED`, `NOT_EXIST` or `INVALID`. | High (telemetry, remote kill switch, opaque remote data) |
| 3 | The menu script sends the server IP to **`http://ipwhois.app`** (twice, on every launch). | Medium (IP disclosure to a third party, plain HTTP) |
| 4 | **Hard-coded public default secrets**: `psk = "pN9m6m0tH3nE3V8xKZ6Lq5yYcW2K1S7QG9u4cF0A8M4="`, `token = "your_token"`. | High if left unchanged |
| 5 | `prompt_with_default` uses **`eval`** on raw user input, so `$(...)`, backticks or `"` in an answer run as root (local only, but values with `$` are silently mangled). | Low-Medium |
| 6 | `install.sh` overwrites `/usr/local/bin/jq` system-wide. **The supplied jq is genuine**: it is byte-identical to official jq 1.8.1 (§9). | Info |
| 7 | **Not found** in the script or the binary strings: SSH-key injection, `authorized_keys`, `useradd`, `/etc/passwd` edits, cron jobs, a shell spawn (`/bin/sh`, `/bin/bash`), Telegram API calls, extra users. The binary executes only `/usr/sbin/iptables` and `sysctl`. Because the core is obfuscated and phones home, this does **not** prove it is benign (§8). | — |
| 8 | The core links `net/http/pprof` (registers `/debug/pprof/*` on the default mux) and can log the **expected token** on a mismatch (`invalid token: %s, expected: %s from %s`). | Low |

---

## 1. Install flow (`install.sh`) and file layout

```bash
set -e
mkdir -p /root/backhaul-core
cd /root/backhaul-core
pkill -f backhaul_premium || true          # kills every running tunnel
curl -O http://5.145.114.119:8080/backhaul/backhaul_premium
curl -O http://5.145.114.119:8080/backhaul/jq
chmod +x backhaul_premium jq
cp jq /usr/local/bin/jq                    # replaces any jq in PATH precedence
cd /root
curl -O http://5.145.114.119:8080/backhaul/backhaul.sh
chmod +x backhaul.sh
bash /root/backhaul.sh
```

Notes:
* `curl -O` has no `-f`. An HTTP error page would be saved and `chmod +x`'d. There is no hash or signature check.
* All three fetches are plain HTTP to a bare IP. Anyone on-path can swap the binary that later runs as root.

Resulting layout:

| Path | What |
|---|---|
| `/root/backhaul-core/backhaul_premium` | core binary (sha256 `6eec5c5624bdafd47ee4f92a0b2e4c6e89719a2cc471d48c97f47d47997c081f` for the analysed copy) |
| `/root/backhaul-core/jq`, `/usr/local/bin/jq` | jq 1.8.1 |
| `/root/backhaul.sh` | menu script (obfuscated) |
| `/root/backhaul-core/iran<PORT>.toml` / `kharej<PORT>.toml` | one config per tunnel (server = "iran", client = "kharej") |
| `/root/backhaul-core/cert_files/cert.crt`, `cert.key` | self-signed TLS pair (created on demand) |
| `/etc/systemd/system/backhaul-iran<PORT>.service` / `backhaul-kharej<PORT>.service` | one unit per tunnel |

### 1.1 Obfuscation of `backhaul.sh`

`backhaul.sh` is a classic "variable-fragment" obfuscator. Hundreds of assignments like `hCBz='5.16';mVz='5"';…` are
followed by one `eval "$Az$Bz$Cz…"`. I rebuilt the eval string statically with a Python string-substitution script
(no shell). The result matches `backhaul.decoded.sh` line for line, apart from my parser's handling of a single `eval "`
fragment. **The decoded file is a faithful decode, and the obfuscation hides no extra payload.**

### 1.2 What `backhaul.sh` does at start-up (before the menu)

1. Runs `mkdir -p /root/backhaul-core/cert_files` (before the root check) and exits if `$EUID != 0`.
2. `install_jq`: if `jq` is missing, runs `apt-get update && apt-get install -y jq`.
3. `download_and_extract_backhaul`: **does nothing if `/root/backhaul-core/backhaul_premium` exists.** Otherwise:
   ```bash
   x86_64:   PRIMARY_URL="http://script.backhaul.top:2095/backhaul_premium_amd64.tar.gz"
             FALLBACK_URL="http://79.175.167.114:2095/backhaul_premium_amd64.tar.gz"
   aarch64:  ..._arm64.tar.gz on the same two hosts
   curl -sSL --max-time 10 -o "$DOWNLOAD_DIR/backhaul.tar.gz" "$PRIMARY_URL" || curl ... --max-time 30 "$FALLBACK_URL"
   tar -xzf "$DOWNLOAD_DIR/backhaul.tar.gz" -C "$config_dir"     # untrusted tar straight into /root/backhaul-core
   chmod u+x "${config_dir}/backhaul_premium"
   ```
   No checksum. The tarball is extracted as root into the config dir, so it could overwrite TOMLs or certificates.
4. Builds the info banner:
   ```bash
   SERVER_IP=$(hostname -I | awk '{print $1}')
   SERVER_COUNTRY=$(curl -sS --max-time 1 "http://ipwhois.app/json/$SERVER_IP" | jq -r '.country')
   SERVER_ISP=$(curl -sS --max-time 1 "http://ipwhois.app/json/$SERVER_IP" | jq -r '.isp')
   ```
   It also runs `$config_dir/backhaul_premium -v` to print the core version. **That executes the core, and with it any
   start-up code, every time the menu opens.**
5. `check_config_backup`: for every `iran*.toml` / `kharej*.toml` without a unit, it offers to recreate and
   `enable --now` the unit (the "restore from backup" path).
6. Banner: `Telegram Channel: @Gozar_XRay`. The script only prints this. It sends nothing to Telegram.

---

## 2. Menu options (every one)

```
 1. Configure a new tunnel     -> configure_tunnel
 2. Tunnel management          -> tunnel_management
 3. Check tunnel status        -> check_tunnel_status
 4. Update Backhaul Core       -> download_and_extract_backhaul "menu"
 5. Update script              -> update_script   (disabled)
 6. Remove Backhaul Core       -> remove_core
 0. Exit
```

| Option | Behaviour |
|---|---|
| **1 Configure** | Requires `/root/backhaul-core` to exist. Sub-menu: `1) Configure IRAN (Server)` or `2) Configure KHAREJ (Client)`, then the prompt flow in §3. Writes `iran<port>.toml` / `kharej<port>.toml` and creates, enables and starts the unit. |
| **2 Tunnel management** | Lists `iran*.toml` / `kharej*.toml` with port numbers. For the chosen one: `1) Remove` (deletes the TOML, runs `systemctl disable --now` only if active, deletes the unit, runs `daemon-reload`), `2) Restart` (`systemctl restart` if `list-units` greps the name), `3) Logs` (`journalctl -eu <svc> -f -o cat`), `4) Status` (`systemctl status`). |
| **3 Check status** | Runs `systemctl is-active` for each `backhaul-<name>.service` and prints running / not running. |
| **4 Update core** | `rm -rf /root/backhaul-core/backhaul_premium`, then downloads the tarball again from `script.backhaul.top:2095` or `79.175.167.114:2095` (plain HTTP, unverified) and extracts it. Advises "Restart all services after updating to new core". Running services are **not** restarted. |
| **5 Update script** | `update_script() { return; …}`. The function **returns immediately**. Dead code below it would download `http://79.175.167.114/backhaul.sh` to `/usr/bin/backhaul`. |
| **6 Remove core** | Refuses while any `*.toml` exists. Otherwise asks y/n and runs `rm -rf /root/backhaul-core`, which also deletes the binary, jq copy and certs. `/usr/local/bin/jq`, `/root/backhaul.sh` and any leftover units are kept. |
| **0** | exit |

---

## 3. Prompt flow and generated config

Order inside `configure_server <server|client>`:
transport → (tun) TUN → (ipx) IPX → connection (skipped for ipx) → security → accept_udp → mux → TLS → tuning → logging → ports (server only).

### 3.1 Prompts and hard-coded values

| Section | Prompt / value | Default | Notes |
|---|---|---|---|
| transport | `type` | — | one of `tcp tcpmux xtcpmux ws wss wsmux wssmux xwsmux anytls tun` |
| transport | `tun` encapsulation | — | `tcp` or `ipx` |
| transport | `nodelay` | `true` | not asked for ipx |
| transport (server) | `accept_udp` | `false` | `tcp` only |
| transport (server) | `proxy_protocol` | `false` | every type except `tun`, `ws` (and not ipx). Asked for `wss`, `anytls`, `*mux`. |
| transport (client) | `connection_pool` | `8` | not for `tun`; omitted if `0` |
| transport | `heartbeat_interval` / `heartbeat_timeout` | `10` / `25` | fixed |
| transport | `keepalive_period` | `40` | fixed; omitted for ipx |
| connection (server) | `bind_addr` | `:8443` | a bare port gets `:` prepended |
| connection (client) | `remote_addr` | — | must match `^IPv4:port$` or `^[a-zA-Z0-9.-]+:port$` |
| connection (client) | `edge_ip` | empty | asked for ws/wss/wsmux/wssmux/xwsmux |
| connection (client) | `dial_timeout` / `retry_interval` | `10` / `3` | fixed |
| security (non-ipx) | `token` | **`your_token`** | written as `token = "…"` |
| security (ipx) | `enable_encryption` | `true` | |
| security (ipx) | `algorithm` | `aes-256-gcm` | or `chacha20-poly1305`, `aes-128-gcm` |
| security (ipx) | `psk` | **`pN9m6m0tH3nE3V8xKZ6Lq5yYcW2K1S7QG9u4cF0A8M4=`** | public default; "32-char base64" |
| security (ipx) | `kdf_iterations` | `100000` | |
| mux (`*mux`) | `mux_version` | `2` | |
| mux | `mux_concurrency` | `8` | |
| mux | `mux_framesize` / `mux_recievebuffer` / `mux_streambuffer` | `32768` / `4194304` / `2097152` | fixed (upstream streambuffer default is 65536) |
| tun | `name` | `backhaul` | |
| tun | `local_addr` / `remote_addr` | server `10.10.10.1/24` ↔ `10.10.10.2/24`, client the reverse | IPv4 CIDR only |
| tun | `health_port` | `1234` | |
| tun | `mtu` | `1500` (tcp) / `1320` (ipx) | |
| ipx | `mode` | `server` / `client` | taken from the side being configured |
| ipx | `profile` | `tcp` | `icmp ipip udp tcp gre bip` (binary: unknown falls back to `ipip`) |
| ipx | `listen_ip` | first `hostname -I` address | |
| ipx | `dst_ip` | required | peer's public IP |
| ipx | `interface` | default-route device (`ip route show default \| awk '{print $5}'`) | |
| ipx (icmp) | `icmp_type` / `icmp_code` | `0` / `0` | |
| tls (anytls) | `sni` | `www.digikala.com` | server and client |
| tls (server wss/wssmux/anytls) | `tls_cert` / `tls_key` | `/root/backhaul-core/cert_files/cert.{crt,key}` | auto-generated if missing |
| tuning | `auto_tuning` | `true` | |
| tuning | `tuning_profile` | `balanced` | `balanced, fast, latency, resource` |
| tuning | `workers` | `0` (auto) | |
| tuning | `channel_size` | `4096`; **`10_000` for tun (fixed)** | |
| tuning (non-ipx) | `tcp_mss`, `so_rcvbuf`, `so_sndbuf` | `0` (auto) | |
| tuning (ipx) | `batch_size`, `so_sndbuf` | `2048`, `0` | |
| tuning (non-tun) | `buffer_profile` | `balanced` | `extreme_low_cpu (64KB), ultra_low_cpu (48KB), low_cpu (32KB), balanced (16KB), low_memory (8KB)` (sizes from binary strings) |
| tuning (non-tun) | `read_timeout` | `120` | |
| accept_udp (server, tcp, if true) | `ring_size` / `frame_size` / `peer_idle_timeout_s` / `write_timeout_ms` | `64` / `2048` / `120` / `3` | fixed |
| logging | `log_level` | `info` | panic…trace |
| ports (server, non-tun) | `mapping` | — | `443`, `443=5000`, `443-600`, `443-600:5201` (the prompt's examples) |
| ports (server, tun) | `forwarder` | `backhaul` | `backhaul` (TCP only) or `iptables` (TCP+UDP); mapping `443` or `443=5000` |

File name: `iran<port>.toml` / `kharej<port>.toml`, where `<port>` comes from `bind_addr` / `remote_addr`. For **ipx**
there is no address, so `<port>` = `health_port` (e.g. `iran1234.toml`). Two tunnels with the same port **silently
overwrite** each other's TOML and unit.

### 3.2 Section order emitted by `generate_toml_config`

`[listener]` (server, non-ipx) or `[dialer]` (client, non-ipx) → `[transport]` → `[tun]` → `[ipx]` → `[mux]` →
`[security]` → `[tls]` → `[tuning]` → `[accept_udp]` → `[logging]` → `[ports]` (server only).

### 3.3 Full templates (as the script writes them, with defaults)

**tcp, server** (`/root/backhaul-core/iran8443.toml`)
```toml
[listener]
bind_addr = ":8443"

[transport]
type = "tcp"
nodelay = true
keepalive_period = 40
accept_udp = true            # only offered for tcp
proxy_protocol = false
heartbeat_interval = 10
heartbeat_timeout = 25

[security]
token = "your_token"         # CHANGE

[tuning]
auto_tuning = true
tuning_profile = "balanced"
workers = 0
channel_size = 4096
tcp_mss = 0
so_rcvbuf = 0
so_sndbuf = 0
buffer_profile = "balanced"
read_timeout = 120

[accept_udp]                 # only when accept_udp = true
ring_size = 64
frame_size = 2048
peer_idle_timeout_s = 120
write_timeout_ms = 3

[logging]
log_level = "info"

[ports]
mapping = [
    "443",
    "2053=2096",
]
```

**tcp, client** (`/root/backhaul-core/kharej8443.toml`)
```toml
[dialer]
remote_addr = "203.0.113.10:8443"
dial_timeout = 10
retry_interval = 3

[transport]
type = "tcp"
nodelay = true
keepalive_period = 40
connection_pool = 8
heartbeat_interval = 10
heartbeat_timeout = 25

[security]
token = "your_token"

[tuning]
auto_tuning = true
tuning_profile = "balanced"
workers = 0
channel_size = 4096
tcp_mss = 0
so_rcvbuf = 0
so_sndbuf = 0
buffer_profile = "balanced"
read_timeout = 120

[logging]
log_level = "info"
```

**tcpmux / xtcpmux / wsmux / xwsmux / wssmux**: same as tcp with `type` changed, no `accept_udp`, plus:
```toml
[mux]
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 4194304      # sic (upstream misspelling kept)
mux_streambuffer = 2097152
mux_concurrency = 8
```
(Server: `proxy_protocol` is asked. Client: `connection_pool` plus, for ws-family, optional `edge_ip`.)

**ws / wss / wssmux / xwsmux, client**: `[dialer]` gains `edge_ip = "104.16.0.1"` when given.
```toml
[dialer]
remote_addr = "tunnel.example.com:443"
edge_ip = "104.16.0.1"
dial_timeout = 10
retry_interval = 3
```

**wss / wssmux, server**: adds (`proxy_protocol` is asked for wss, never for ws)
```toml
[tls]
tls_cert = "/root/backhaul-core/cert_files/cert.crt"
tls_key = "/root/backhaul-core/cert_files/cert.key"
```
The client gets **no `[tls]` section** for wss/wssmux. Certificate verification behaviour is unknown (the self-signed
default implies the client skips verification).

**anytls, server**
```toml
[listener]
bind_addr = ":443"

[transport]
type = "anytls"
nodelay = true
keepalive_period = 40
proxy_protocol = false
heartbeat_interval = 10
heartbeat_timeout = 25

[security]
token = "your_token"

[tls]
sni = "www.digikala.com"
tls_cert = "/root/backhaul-core/cert_files/cert.crt"
tls_key = "/root/backhaul-core/cert_files/cert.key"

[tuning]
# as tcp

[logging]
log_level = "info"

[ports]
mapping = [ "443=8443", ]
```
**anytls, client**: `[dialer]`, `[transport] type = "anytls" … connection_pool = 8`, `[security] token`,
`[tls] sni = "www.digikala.com"`, `[tuning]`, `[logging]`. The binary links **uTLS** (strings `InitializeByUtls`,
`Chrome115_PQ`, `Safari`, `QQBrowser`, `360Browser`), so the client presumably sends a browser-fingerprinted ClientHello.

**tun (encapsulation tcp), server**
```toml
[listener]
bind_addr = ":8443"

[transport]
type = "tun"
nodelay = true
keepalive_period = 40
heartbeat_interval = 10
heartbeat_timeout = 25

[tun]
encapsulation = "tcp"
name = "backhaul"
local_addr = "10.10.10.1/24"
remote_addr = "10.10.10.2/24"
health_port = 1234
mtu = 1500

[security]
token = "your_token"

[tuning]
auto_tuning = true
tuning_profile = "balanced"
workers = 0
channel_size = 10_000
tcp_mss = 0
so_rcvbuf = 0
so_sndbuf = 0

[logging]
log_level = "info"

[ports]
forwarder = "backhaul"       # or "iptables" (TCP+UDP via DNAT)
mapping = [
    "443",
    "8080=80",
]
```
**tun (tcp), client**: `[dialer]` (remote_addr, dial_timeout, retry_interval), `[transport] type="tun" nodelay keepalive
heartbeat` (no pool), `[tun]` with `local_addr = "10.10.10.2/24"`, `remote_addr = "10.10.10.1/24"`, the same
`[security]` / `[tuning]` / `[logging]`, and no `[ports]`.

**tun (encapsulation ipx), server**: no `[listener]`, the core uses raw packets (file `iran1234.toml`)
```toml
[transport]
type = "tun"
heartbeat_interval = 10
heartbeat_timeout = 25

[tun]
encapsulation = "ipx"
name = "backhaul"
local_addr = "10.10.10.1/24"
remote_addr = "10.10.10.2/24"
health_port = 1234
mtu = 1320

[ipx]
mode = "server"
profile = "tcp"              # icmp | ipip | udp | tcp | gre | bip
listen_ip = "203.0.113.10"   # this host's public IP
dst_ip = "198.51.100.20"     # peer's public IP
interface = "eth0"
# icmp_type = 0              # only for profile = "icmp"
# icmp_code = 0

[security]
enable_encryption = true
algorithm = "aes-256-gcm"
psk = "pN9m6m0tH3nE3V8xKZ6Lq5yYcW2K1S7QG9u4cF0A8M4="   # PUBLIC DEFAULT: CHANGE
kdf_iterations = 100000

[tuning]
auto_tuning = true
tuning_profile = "balanced"
workers = 0
channel_size = 10_000
so_sndbuf = 0
batch_size = 2048

[logging]
log_level = "info"

[ports]
forwarder = "backhaul"
mapping = [ "443", ]
```
**tun (ipx), client** (`kharej1234.toml`): identical except `mode = "client"`, swapped `local_addr` / `remote_addr`
and `listen_ip` / `dst_ip`, and no `[ports]`.

### 3.4 Keys the core understands but the script never writes

From the binary's TOML struct tags: `bind_addrs`, `remote_addrs`, `local_addrs` (multi-address lists),
`max_connections`, `protocol`, `tpacket_profile` (AF_PACKET TPACKET ring), `custom_packet`, `spoof_src_ip`,
`spoof_dst_ip` (log string `spoofing enabled, srcIP: %s, dstIP: %s`). The section/table names are `listener`, `dialer`,
`transport`, `tun`, `ipx`, `mux`, `security`, `tls`, `tuning`, `accept_udp`, `logging`, `ports`. The value
`quic` also appears in the same inline string-compare switch as `wsmux` and `anytls`, and quic-go is linked, so there is
probably a **hidden `quic` transport** (inferred, untested). Exact semantics of these keys are unknown.

---

## 4. systemd units

Written by `create_systemd_service`, and identically by `check_config_backup`:
```ini
# /etc/systemd/system/backhaul-iran8443.service   (or backhaul-kharej8443.service)
[Unit]
Description=Backhaul Iran Port 8443
After=network.target
[Service]
Type=simple
User=root
ExecStart=/root/backhaul-core/backhaul_premium -c /root/backhaul-core/iran8443.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
TasksMax=infinity
LimitMEMLOCK=infinity
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
```
Then `systemctl daemon-reload && systemctl enable --now backhaul-<type><port>.service`. The unit runs as root with no
sandboxing (`ProtectSystem`, `NoNewPrivileges` etc. absent). With `Restart=always`, a license failure means a 3-second
restart loop that **calls the license servers again on every restart**.

## 5. Certificate generation

```bash
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -x509 -days 365 -sha256 \
  -keyout /root/backhaul-core/cert_files/cert.key -out /root/backhaul-core/cert_files/cert.crt -subj "/CN=backhaul.com"
```
The message says "Ed25519", but the key is actually **ECDSA P-256**. It is self-signed, valid for 365 days with no
renewal, `CN=backhaul.com` (a fingerprintable constant), and has no SAN. The cert is generated only on the **server**
when it is missing. All TLS tunnels on the host share it.

## 6. IPv6 handling

* **Server `bind_addr`**: any string containing `:` is accepted, so `[::]:8443` works. `:8443` is dual-stack under the
  default `bindv6only=0`. The port extraction (`grep -oP ':\K[0-9]+$'`) works with brackets.
* **Client `remote_addr`**: the regex accepts only `IPv4:port` or `[A-Za-z0-9.-]+:port`, so **IPv6 literals such as
  `[2001:db8::1]:8443` are rejected.** Use a hostname with an AAAA record, or edit the TOML by hand.
* `edge_ip` is free text. Upstream required brackets for v6, and that probably still applies.
* **TUN and IPX are IPv4-only**: `validate_cidr` accepts only dotted-quad CIDR, and the binary has
  `IPv4 addresses required`, `not IPv4 packet`, `non-IPv4 address`, `unsupported IP version`.
* `SERVER_IP` (banner, ipwhois lookup, ipx `listen_ip` default) is the **first** `hostname -I` address. That may be a
  private, Docker or IPv6 address, so check it on multi-homed hosts.
* `validate_cidr` rejects the network and broadcast addresses, and with them every `/31` and `/32` (it compares
  `ip == network`). Its "Network address should be: …" hint is always empty.

## 7. Tuning, sysctl and iptables

**The script itself never runs sysctl or iptables.** The core does it at runtime (`auto_tuning = true` by default).
Evidence from the binary:

* `Applying kernel tuning profile: %s`, `Applied %s=%s`, `Failed to set %s=%s: %v`, `sysctl binary not found`, so the
  core shells out to `sysctl`. Keys: `net.core.{rmem_max,wmem_max,rmem_default,wmem_default,somaxconn,netdev_max_backlog,
  default_qdisc,busy_read,busy_poll}`, `net.ipv4.{tcp_rmem,tcp_wmem,tcp_mem,tcp_congestion_control (bbr),
  tcp_window_scaling,tcp_timestamps,tcp_slow_start_after_idle,tcp_notsent_lowat,tcp_mtu_probing,tcp_fastopen,
  tcp_tw_reuse,tcp_fin_timeout,tcp_max_syn_backlog,ip_local_port_range}`. Profiles `balanced/fast/latency/resource`
  (also `high_throughput`, `low_latency` internally). An unknown profile falls back to balanced. These are **persistent
  host-wide changes**, and upstream's `skip_optz` is absent.
* `Enabling net.ipv4.ip_forward` writes `/proc/sys/net/ipv4/ip_forward` (TUN).
* `Raised RLIMIT_NOFILE to %d`.
* iptables (`/usr/sbin/iptables`): the `forwarder = "iptables"` TUN helper adds `PREROUTING … --dport … -j DNAT
  --to-destination` plus `POSTROUTING … MASQUERADE` for tcp and udp, tagged with `-m comment` (`adding iptables forwarder
  %s -> %s:%s (id=%s)`, `iptables forwarder rules removed (tcp + udp)`). For raw/IPX tcp mode it adds
  `iptables rule added to drop RST to %s` (`--tcp-flags … RST -j DROP`) so the kernel's RSTs do not kill the fake-TCP
  flow. The rules are removed on clean shutdown. After a crash or SIGKILL they may remain (`iptables -t nat -S`,
  `iptables -S | grep RST`).

---

## 8. Network calls, licensing and telemetry

### 8.1 From the shell scripts

| When | Destination | Data sent |
|---|---|---|
| install | `http://5.145.114.119:8080/backhaul/{backhaul_premium,jq,backhaul.sh}` | none (GET) |
| first run / menu 4 | `http://script.backhaul.top:2095/backhaul_premium_{amd64,arm64}.tar.gz`, fallback `http://79.175.167.114:2095/…` | none |
| every menu launch | `http://ipwhois.app/json/<SERVER_IP>` ×2 | **the server's IP** (in the URL, plain HTTP) |
| (dead code) | `http://79.175.167.114/backhaul.sh` → `/usr/bin/backhaul` | — |
| if jq missing | apt mirrors | — |

### 8.2 From the core binary (license system)

The plaintext strings show a mandatory online license tied to the server's public IP:
```
https://api.ipify.org?format=json        ipify request failed / ipify bad status: %d / no public IP address found
https://license1.rocektserver.com
https://validator.backhaul-dev.com
https://validator.xtreme-cloud.eu.org
/getip  /nonce  /validation  /vegeta  license.validation.service   X-User-Id   Bearer %s
failed to get nonce / invalid nonce format / failed to base64 decode nonce / failed to parse nonce JSON
invalid HMAC signature / expected an RSA public key  (+ embedded RSA-2048 PUBLIC KEY, see recovered_strings.txt)
License is valid | License IP mismatch | License does not exist | License has expired | License is invalid
License rejected | License server returned failure | License verification API failed | Unknown license status
statuses: IP_MISMATCH NOT_EXIST EXPIRED INVALID UNKNOWN API_CALL_FAILED
JSON: server_ip license nonce signature expires_at aes_key client_id payload data backhaul_version transport_type
```
Reconstructed flow (inferred from strings, not observed): get the public IP from ipify, get a nonce from a validator,
POST `{server_ip, backhaul_version, transport_type, client_id, …}`, then verify the response's RSA signature or HMAC
and `expires_at`. Any of the "License …" failures stops the tunnel. Implications:
* The vendor (and ipify) learns **every host's public IP, version and transport choice** on every start or restart.
* The vendor can **disable any tunnel remotely** and log who runs it. In censorship contexts that is a deanonymisation
  and availability risk.
* The response carries `aes_key` and `payload`, so remote data influences runtime behaviour. What it is used for is
  unknown (it could be config, crypto keys or a feature flag). **This is opaque remotely supplied data in a root process.**
* The three validator domains are unrelated to the download hosts (`backhaul.top`, the bare IPs). "rocektserver" looks
  like a misspelling of "rocketserver".

No strings were found for `authorized_keys`, `ssh-rsa`/`ssh-ed25519` keys, `useradd`, `/etc/passwd`, `crontab`,
`/bin/sh`, `/bin/bash`, `api.telegram.org`, `machine-id` or DMI reads. The only external program paths are
`/usr/sbin/iptables` and `sysctl`. **Caveat:** the binary is obfuscated, and because the license response includes
`payload`/`aes_key`, remote-driven behaviour cannot be excluded by static strings. Treat it as untrusted.

---

## 9. Binary findings

### 9.1 `backhaul_premium.bin`
* ELF64 x86-64, **dynamically linked to libc.so.6 only** (cgo enabled), stripped, BuildID
  `8220f3d9d4de904997c423a55776ea849d9b1237`, `.comment`: `GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0`, so it was
  built on Ubuntu 22.04.
* **Go**, with sections `.gopclntab`, `.go.buildinfo`, `.go.fipsinfo`. Buildinfo is blanked (`GoVersion = "unknown"`,
  no module or deps), as garble does. The GODEBUG table contains `containermaxprocs`, `updatemaxprocs`,
  `decoratemappings`, `tlssha1`, `httpcookiemaxnum`, which means **Go 1.25.x (probably ≥ 1.25.2)**. GoReSym reports
  the pclntab format as 1.20+.
* **garble-obfuscated**: GoReSym recovered 9,149 "user" and 2,499 std functions across 235 packages with random names
  (`V4s_1skT`, `_eOU0CNbcRX`, `E6k1wNq`, `fGu6jyOVbyUS`, …) and 50,650 random file names. A few exported method names
  survive (`EstablishControlChannel`, `StartTunnelListener`, `HandleTunnel`, `GetSessionCounter`, `GetMuxConValue`,
  `GetTransportName`, `InitializeByUtls`, `ZeroCopyReadPacketData`, gopacket `LayerType/DecodeFromBytes`). Full list in
  `recovered_symbols.txt`.
* **GoStringUngarbler** found only 6 trivial candidates, so `-literals` was **not** used and all strings are plaintext
  (that is why the license URLs are greppable).
* Identifiable libraries (from strings): BurntSushi/toml (`BURNTSUSHI_TOML_110`), logrus, smux (or a smux fork),
  gorilla-style websocket, quic-go, uTLS (refraction-networking), gopacket + afpacket (TPACKET), netlink,
  x/crypto chacha20poly1305, HPKE/ML-KEM (Go std), net/http/pprof.
* CLI: `Usage: %s -c /path/to/config.toml`, and `-v` prints the version (used by the script).
* Transports (inline compares and strings): `tcp`, `tcpmux`, `xtcpmux`, `ws`, `wss`, `wsmux`, `wssmux`, `xwsmux`,
  `anytls`, `tun` (encapsulations `tcp`, `ipx`), IPX profiles `icmp ipip udp tcp gre bip`, and a likely hidden `quic`.
  Upstream's `udp` transport is not offered by the script.
* Other runtime strings: `health service listening on %s` (TUN `health_port`), `received http request from %s`,
  `invalid token: %s, expected: %s from %s` (**logs the real token to the journal**), `invalid allowed client IP: %s`
  (a client IP allow-list exists internally), `failed to create TX/RX crypto engine`, `NetToTun channel full`.

### 9.2 `jq.bin`: verified genuine
* Static ELF, `GCC: (Ubuntu 13.3.0-6ubuntu2~24.04)`, configure line `--with-oniguruma=builtin --enable-all-static`,
  version string **1.8.1**.
* sha256 `020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d` = official
  `jq-1.8.1/jq-linux-amd64` (= `jq-linux64`) in `https://github.com/jqlang/jq/releases/download/jq-1.8.1/sha256sum.txt`.
  I downloaded the official binary and `cmp` found it **byte-identical**.
* For reference: 1.8.0 `8926c333…605c`, 1.7.1 `5942c9b0…8ff5`, 1.7 `2f312b95…9716`, 1.6 `af986793…4c44`. The supplied
  file is not 1.6 or 1.7.x.

---

## 10. Premium vs upstream (Musixal/Backhaul v0.7.2)

| Area | Upstream (open source, AGPL) | Premium |
|---|---|---|
| Config schema | flat `[server]` / `[client]` | sectioned `[listener]/[dialer]/[transport]/[tun]/[ipx]/[mux]/[security]/[tls]/[tuning]/[accept_udp]/[logging]/[ports]` (**not compatible**) |
| Transports | tcp, tcpmux, ws, wss, wsmux, wssmux, udp | + **xtcpmux, xwsmux, anytls, tun (tcp / ipx raw: icmp/ipip/udp/tcp/gre/bip)**, likely quic; udp not exposed |
| Heartbeat | `heartbeat` | `heartbeat_interval` + `heartbeat_timeout` |
| Mux | `mux_con`, `mux_session` | `mux_concurrency`; streambuffer default 2 MiB in script |
| Crypto | token only (TLS for wss) | token, plus for IPX **AEAD (aes-256-gcm / chacha20 / aes-128-gcm) with PSK + PBKDF iterations** |
| TLS | cert/key | + `sni`, uTLS fingerprints (anytls) |
| Tuning | `skip_optz`, `mss`, `so_*` | `auto_tuning`, `tuning_profile`, `workers`, `buffer_profile`, `read_timeout`, `batch_size`, `tpacket_profile` |
| Port forwarding | built-in listeners | + TUN `forwarder = "iptables"` (kernel DNAT, TCP+UDP) |
| Multi-address | no | `bind_addrs`, `remote_addrs`, `local_addrs` |
| Spoofing | no | `spoof_src_ip`, `spoof_dst_ip`, `custom_packet` |
| Web UI / sniffer / pprof flag | `web_port`, `sniffer`, `pprof` (0.0.0.0:6060) | no such keys; pprof handlers still linked |
| UDP over TCP | `accept_udp` | same + `[accept_udp]` ring tuning |
| License | none | **mandatory online, IP-bound, remote-revocable** |
| Distribution | GitHub releases | plain-HTTP bare IPs, obfuscated script, garbled binary |

---

## 11. Security risks (summary)

1. Unverified plain-HTTP downloads of root-executed code (installer, core, update path). The tarball is extracted into
   the config directory.
2. A closed, obfuscated core with **phone-home licensing**: it discloses IPs to three vendor domains and ipify, can be
   remotely disabled, and receives an opaque `payload`/`aes_key`.
3. The script leaks the server IP to ipwhois.app over HTTP on every launch.
4. Public default token and PSK.
5. A self-signed cert with a constant `CN=backhaul.com` is a fingerprinting aid, and the client probably skips
   verification.
6. Runs as root, unsandboxed, changes kernel sysctls and iptables host-wide, and may leave rules after a crash.
7. `eval` on user input in the script.
8. The journal can contain the real token (`expected: %s`).
9. pprof handlers are linked. If the core serves `http.DefaultServeMux` on any port (the health port, for example), they
   would be exposed. Verify with `curl http://<host>:<health_port>/debug/pprof/` from outside.
10. Same-port tunnels silently overwrite each other's files.

Mitigations if you must run it: run it on throwaway hosts; fetch the core over a trusted channel and pin its sha256;
replace every default secret; firewall egress so you know (and can log) the license traffic (`api.ipify.org`,
`license1.rocektserver.com`, `validator.backhaul-dev.com`, `validator.xtreme-cloud.eu.org`). Note that blocking it will
stop the tunnel. Add systemd hardening (`NoNewPrivileges=yes`, `ProtectHome=read-only` with `ReadWritePaths=`,
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_RESOURCE`). Prefer upstream open-source
Backhaul when its transports suffice.

---

## 12. Manual setup recipe (no menu script)

```bash
# 1. Get the core from a source you trust; record and pin its hash.
mkdir -p /root/backhaul-core/cert_files && cd /root/backhaul-core
# (copy backhaul_premium here), then:
sha256sum backhaul_premium      # compare with a known-good value
chmod 700 backhaul_premium

# 2. Secrets
TOKEN=$(openssl rand -hex 24)
PSK=$(openssl rand -base64 32)   # for IPX only

# 3. TLS (server, for wss/wssmux/anytls) - prefer a real cert; otherwise:
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -x509 -days 365 -sha256 \
  -keyout cert_files/cert.key -out cert_files/cert.crt -subj "/CN=$(hostname -f)"

# 4. Write iran<port>.toml (server) / kharej<port>.toml (client) from §3.3 with your values.
#    Token/PSK, transport type and mux settings must match on both sides.

# 5. Unit (copy §4, adjust name/port), then:
systemctl daemon-reload
systemctl enable --now backhaul-iran8443.service
journalctl -u backhaul-iran8443 -f -o cat     # expect "... License is valid ..."

# 6. Firewall: open bind_addr port (server) and mapped ports; for ipx, allow the chosen IP protocol
#    (icmp / 4 ipip / 47 gre / udp / tcp) between the two public IPs.

# 7. Clean-up check after stopping: iptables -t nat -S; iptables -S | grep -i rst; sysctl net.ipv4.tcp_congestion_control
```
