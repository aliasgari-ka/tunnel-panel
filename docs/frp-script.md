# frp-script ("Easy FRP" / `frp-manager`) — Technical Reference

Source analysed: `/home/user/tunnels-kb/sources/frp-script`, read only and never executed.
Files: `frp-setup.sh` (670 lines, everything is here), `README.md` (Persian), `README-en.md`, `LICENSE` (MIT, "Copyright (c) 2024 Mehrad"), `.gitignore`.
Upstream: `https://github.com/mikeesierrah/frp-script`. It wraps [fatedier/frp](https://github.com/fatedier/frp) and uses the TOML config format (frp >= v0.52).

---

## 1. Purpose and architecture

This is an interactive bash menu that does the following:

1. Installs the latest upstream `frps` and `frpc` binaries.
2. Creates systemd *template* units (`frps@.service` and `frpc@.service`).
3. Writes a minimal `frps` (server) or `frpc` (client) TOML config, then enables and starts the matching instance.
4. Offers some extra "optimization" utilities: BBR+FQ, a SIGUSR1 cron job, volatile journald, and log wiping.

### Roles (from the Persian README)

| Machine | FRP role | Config | Systemd instance |
|---|---|---|---|
| **Iran relay server** | `frps` (server, listener) | `/root/frp/server/server-<bindPort>.toml` | `frps@server-<bindPort>` |
| **Foreign server** (the one with the real service, e.g. Xray or SSH) | `frpc` (client, dialer) | `/root/frp/client/client-<serverPort>.toml` | `frpc@client-<serverPort>` |

The README says it outright: "(ایران) راه‌اندازی سرور" = *(Iran) server setup*, and "(خارج) راه‌اندازی کلاینت" = *(Foreign) client setup*.

### Who dials whom: a reverse tunnel

```
End user ──TCP──▶ IRAN:remotePort (frps listens on [::]:remotePort)
                         │
                         │  frps hands the user conn to a "work connection"
                         ▼
             control/work conns, opened FROM foreign TO Iran
             (tcp | websocket | kcp(UDP) | quic(UDP)  on IRAN:bindPort)
                         ▲
                         │
FOREIGN frpc ────────────┘ ──▶ 127.0.0.1:localPort (the real service on foreign)
```

- The **foreign** host (`frpc`) opens the connection **to Iran** at `serverAddr:serverPort`. That makes this a **reverse** tunnel: Iran never dials out.
- Iran opens a public listener for every proxy (`remotePort`). User traffic coming in on that port goes over the client-initiated connections to `127.0.0.1:localPort` on the foreign host.
- Each proxy uses `localPort == remotePort`, because the port list is mirrored (see §6).
- The README's "server-to-server tunnel" means the relay pattern: users only ever touch the Iranian IP.

---

## 2. Entry and self-install flow

Startup order matters, because `set -e` is active from line 2:

```bash
INSTALL_PATH="/usr/local/bin/frp-manager"
SCRIPT_PATH="$(readlink -f "$0")"
...
# Force installation as frp-manager command
install_script            # line 165, top level, runs BEFORE the root check
...
if [[ $EUID -ne 0 ]]; then print_error "This script must be run as root (use sudo)"; exit 1; fi
optimize                  # line 668, runs on every launch of the first copy
main_menu
```

`install_script`:

```bash
curl -L https://raw.githubusercontent.com/mikeesierrah/frp-script/main/frp-setup.sh -o "$INSTALL_PATH"
sudo chmod +x "$INSTALL_PATH"
sed -i 's/^install_script$/# install_script/' "$INSTALL_PATH"
sed -i 's/^optimize$/# optimize/' "$INSTALL_PATH"
```

- It re-downloads the script from the unpinned `main` branch to `/usr/local/bin/frp-manager`. It does not copy the running file.
- The installed copy has the top-level `install_script` and `optimize` calls commented out. The indented `optimize` call inside the utilities menu does not match `^optimize$`, so it still works.
- Documented launch: `bash <(curl -Ls https://raw.githubusercontent.com/mikeesierrah/frp-script/main/frp-setup.sh)`. After that you run `frp-manager`.

There are **no CLI flags**. Everything is driven by the interactive menu and `read -p` prompts.

---

## 3. Menus (every option)

### Main menu
| # | Label | Function | What it does |
|---|---|---|---|
| 1 | Install FRP | `install_frp` | Downloads the latest frp release and installs both binaries plus both template units (§4) |
| 2 | Setup FRP Server | `setup_server` | Prompts, writes `server-<port>.toml`, runs `systemctl enable --now frps@server-<port>` |
| 3 | Setup FRP Client | `setup_client` | Prompts, writes `client-<serverPort>.toml`, runs `systemctl enable --now frpc@client-<serverPort>` |
| 4 | Advanced Configuration | `advanced_config` | Lists `*.toml` under server/ or client/ and cats the chosen one. It can open it in `${EDITOR:-nano}`, and restarts the matching instance if it is **active** |
| 5 | Show Status | `show_status` | `frps --version`, the running `frp[sc]@` units, "enabled" units (broken, §10), `ls -la` of the config dirs |
| 6 | Stop All Services | `stop_services` | `systemctl stop` on each running `frps@*` / `frpc@*`. It does **not** disable them, so they come back on reboot. The menu has no "start" option |
| 7 | Optimization Utilities | `utilities_menu` | Submenu, see below |
| 8 | Remove FRP | `remove_frp` | Uninstall, after a literal `yes` confirmation (§9) |
| 9 | Exit | | |

### Utilities submenu
| # | Label | Function |
|---|---|---|
| 1 | Optimize System (BBR, FQ) | `optimize` (§7) |
| 2 | OS logs Only In Memory (Reduce disk I/O) | `reduce_io` (§7) |
| 3 | Remove All System logs (Clears Storage) | `remove_logs` (§7), after a literal `yes` confirmation |
| 4 | Back | |

### Prompts in Setup Server (option 2)
| Prompt | Default | Effect |
|---|---|---|
| `bindPort` | `7000` | TCP listen port. Also the file and instance name |
| Protocol `1) none 2) quic 3) kcp` | **`2` (quic)** | Adds `quicBindPort = bindPort` or `kcpBindPort = bindPort` (UDP, same number) |
| Enable TCP Mux | `n` | `transport.tcpMux = true/false` |
| auth token | **`mikeesierrah`** | `auth.token` |

### Prompts in Setup Client (option 3)
| Prompt | Default | Effect |
|---|---|---|
| Server IP (v4 or v6) | none | `serverAddr` (written raw, so a v6 literal works without brackets) |
| Server port | `7000` | `serverPort`, also the file and instance name |
| Auth token | `mikeesierrah` | `auth.token` |
| Transport `1) tcp 2) websocket 3) quic 4) kcp` | `1` (tcp). Invalid input also gives tcp | `transport.protocol` |
| Enable TCP Mux | `n` | `transport.tcpMux` |
| Enable Compression | `n` (warns about RAM) | `transport.useCompression` on every proxy |
| Local ports to expose | none (e.g. `22,6000-6006,6007`) | Fed into the Go-template range (§6) |

---

## 4. Install steps (exact)

```bash
arch=$(uname -m)
case "$arch" in
    x86_64) arch="amd64" ;;
    aarch64) arch="arm64" ;;
    armv7l|armv6l) arch="arm" ;;
    *) print_error "Unsupported arch: $arch"; exit 1 ;;
esac
os=$(uname -s | tr '[:upper:]' '[:lower:]')     # "linux"
platform="${os}_${arch}"
version=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
url="https://github.com/fatedier/frp/releases/download/v${version}/frp_${version}_${platform}.tar.gz"
curl -L "$url" -o "/tmp/frp.tar.gz"
tar -xzf /tmp/frp.tar.gz -C /tmp
cp /tmp/frp_${version}_${platform}/frpc /usr/local/bin/
cp /tmp/frp_${version}_${platform}/frps /usr/local/bin/
chmod +x /usr/local/bin/frpc /usr/local/bin/frps
mkdir -p /root/frp/server
mkdir -p /root/frp/client
```

- **Version:** whatever GitHub "latest" is at install time. Nothing is pinned and nothing is checksummed.
- **Download URL pattern:** `https://github.com/fatedier/frp/releases/download/v<VER>/frp_<VER>_linux_<amd64|arm64|arm>.tar.gz`
- **Binaries:** `/usr/local/bin/frps` and `/usr/local/bin/frpc`. The tarball and extracted directory are left in `/tmp`.
- **Config dirs:** `/root/frp/server/` and `/root/frp/client/`.

### `/etc/systemd/system/frps@.service` (verbatim; the heredoc's `\$MAINPID` becomes `$MAINPID`)

```ini
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/frpc@.service`
This is the same file except for `Description=FRP Client Service (%i)` and `ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml`.

Notes on the units:
- There is no `User=`, so the services run as **root**. That makes `AmbientCapabilities` pointless, and the bounding set still grants `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`.
- `After=network-online.target` appears without `Wants=network-online.target`, so the ordering is not guaranteed.
- `ExecReload` sends HUP. frpc has no SIGHUP hot-reload (that needs the admin API, `frpc reload`), and frps does not handle HUP either. Since Go exits on an unhandled SIGHUP, `systemctl reload` effectively kills the process and `Restart=on-failure` brings it back.
- At the end: `systemctl daemon-reload`.

---

## 5. Generated config files

### 5.1 Server: `/root/frp/server/server-<bindPort>.toml`

Generator:
```bash
echo 'bindAddr = "::"'
echo "bindPort = $bindPort"
if [[ $proto_choice == 2 ]]; then echo "quicBindPort = $bindPort"
elif [[ $proto_choice == 3 ]]; then echo "kcpBindPort = $bindPort"; fi
...
echo "transport.heartbeatTimeout = 90"
echo "transport.maxPoolCount = 65535"
echo "transport.tcpMux = $( [[ $use_mux =~ ^[Yy]$ ]] && echo true || echo false )"
echo "transport.tcpMuxKeepaliveInterval = 10"
echo "transport.tcpKeepalive = 120"
echo 'auth.method = "token"'
echo "auth.token = \"$token\""
```

Example output with all defaults (port 7000, quic, no mux):
```toml
# Auto-generated frps config
bindAddr = "::"
bindPort = 7000
quicBindPort = 7000

transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

transport.heartbeatTimeout = 90
transport.maxPoolCount = 65535
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.tcpKeepalive = 120

auth.method = "token"
auth.token = "mikeesierrah"
```
With KCP chosen, you get `kcpBindPort = 7000` instead, and the three `transport.quic.*` lines are emitted commented out (`# ...`). With "none", only TCP and WebSocket work. frps always serves WebSocket on `bindPort` with no option needed.

Server fields:
| Field | Value | Meaning |
|---|---|---|
| `bindAddr` | `"::"` | Listen on all v6 addresses and, through dual-stack, v4 |
| `bindPort` | user (7000) | TCP control port. WebSocket clients also use it |
| `quicBindPort` / `kcpBindPort` | = bindPort | UDP port for QUIC/KCP. The same number is fine because TCP and UDP don't collide |
| `transport.quic.keepalivePeriod` | 10 s | QUIC keepalive |
| `transport.quic.maxIdleTimeout` | 30 s | QUIC idle timeout |
| `transport.quic.maxIncomingStreams` | 100000 | QUIC stream limit |
| `transport.heartbeatTimeout` | 90 s | Drops a client with no heartbeat |
| `transport.maxPoolCount` | 65535 | Max work-connection pool a client may request (default 5). Lets the client's `poolCount = 20` actually apply |
| `transport.tcpMux` | true/false | yamux multiplexing. **Must match the client** |
| `transport.tcpMuxKeepaliveInterval` | 10 s | yamux keepalive |
| `transport.tcpKeepalive` | 120 s | TCP keepalive on accepted conns |
| `auth.method`/`auth.token` | token | Shared secret |

The script **does not set** these: `allowPorts`, `proxyBindAddr` (defaults to bindAddr, i.e. `::`), `webServer` (dashboard), `transport.tls.force`, `log.*`, `maxPortsPerClient`.

### 5.2 Client: `/root/frp/client/client-<serverPort>.toml`

The heredoc is reproduced verbatim (inside the heredoc `\$` is a literal `$`; `$server_ip` and similar are expanded by bash):
```toml
serverAddr = "$server_ip"
serverPort = $server_port

loginFailExit = false

auth.method = "token"
auth.token = "$auth_token"

transport.protocol = "$transport"
transport.tcpMux = <true|false>
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = false
transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

{{- range $_, $v := parseNumberRangePair "$port_input" "$port_input" }}
[[proxies]]
name = "tcp-{{ $v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ $v.First }}
remotePort = {{ $v.Second }}
transport.useEncryption = false
transport.useCompression = $compression_enabled
{{- end }}
```

Example output (server `2001:db8::10`, port 7000, tcp, ports `443,8080-8081`):
```toml
serverAddr = "2001:db8::10"
serverPort = 7000

loginFailExit = false

auth.method = "token"
auth.token = "mikeesierrah"

transport.protocol = "tcp"
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = false
transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

{{- range $_, $v := parseNumberRangePair "443,8080-8081" "443,8080-8081" }}
[[proxies]]
name = "tcp-{{ $v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ $v.First }}
remotePort = {{ $v.Second }}
transport.useEncryption = false
transport.useCompression = false
{{- end }}
```
frpc renders the Go template when it loads the file. The example expands to three proxies: `tcp-443`, `tcp-8080` and `tcp-8081`.

Client fields:
| Field | Value | Meaning |
|---|---|---|
| `serverAddr` | user input | Iran server IPv4, IPv6 or hostname |
| `serverPort` | 7000 | Server bindPort (also the UDP port for kcp/quic) |
| `loginFailExit` | false | Keep retrying if the first login fails, instead of exiting |
| `transport.protocol` | tcp / websocket / quic / kcp | Control and work connection transport |
| `transport.tcpMux` | false (default) | yamux. The README advises keeping it **off** under high load |
| `transport.tcpMuxKeepaliveInterval` | 10 | |
| `transport.dialServerTimeout` | 10 s | |
| `transport.dialServerKeepalive` | 120 s | TCP keepalive toward the server (frp default 7200) |
| `transport.poolCount` | 20 | Pre-opened work connections. With mux off, each user connection takes one pooled TCP/QUIC/KCP connection and frpc refills the pool by dialing Iran again |
| `transport.heartbeatInterval` / `heartbeatTimeout` | 30 / 90 | App-level heartbeat |
| `transport.tls.enable` | **false** | Turns off frp's TLS wrapper, which has been on by default since v0.50. On tcp, websocket and kcp the control channel and data then travel **in clear** (only QUIC has built-in TLS) |
| `transport.quic.*` | 10 / 30 / 100000 | Only used when protocol = quic |
| Proxy `type` | tcp | TCP only. No UDP proxies, so UDP services such as WireGuard or Hysteria are not tunnelled |
| Proxy `localIP` | 127.0.0.1 | The service must listen on foreign's loopback or on all interfaces |
| `transport.useEncryption` | false | No per-proxy AES |
| `transport.useCompression` | prompt | Per-proxy snappy compression |

### 5.3 Transport compatibility matrix
| Client `transport.protocol` | Works if server option was |
|---|---|
| tcp | any (1/2/3) |
| websocket | any. frps serves WS on bindPort automatically |
| quic | only 2 (quic), which is the server default |
| kcp | only 3 (kcp) |

`tcpMux` must be identical on both sides. Both default to `n`.

The script offers **no TLS option**: no certificates and no `transport.tls.force`. There is also no wss.

---

## 6. Port forwarding model

- There is one prompt, a comma list of single ports and `a-b` ranges, e.g. `22,6000-6006,6007`.
- frp's template helper `parseNumberRangePair "<list>" "<list>"` zips two lists of the same length into `{First, Second}` pairs. Both arguments are the same string, so the result is always `localPort == remotePort`. **There is no port remapping** unless you hand-edit the file, e.g. to `parseNumberRangePair "443" "8443"`.
- Each port becomes its own `[[proxies]]` entry named `tcp-<port>`, with type tcp, going `IRAN:[::]:<port>` → `FOREIGN:127.0.0.1:<port>`.
- One client config is written per server port. You can add ports later by editing the string through option 4.
- Several servers on one Iran host work fine: each bindPort gets its own `frps@server-<port>` instance.
- On the foreign side, the client file name is keyed only by `serverPort`. **Two clients pointing at two different Iran servers that both use port 7000 overwrite each other's file** (see bugs).

---

## 7. Tuning and optimizations

### `optimize` (runs automatically at first launch, and from Utilities 1)
```bash
local -r cron_job="0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps"
sudo crontab -l 2>/dev/null | grep -Fq "${cron_job}" || {
    (sudo crontab -l 2>/dev/null; echo "${cron_job}") | sudo crontab -
}
[[ "$(sysctl -n net.core.default_qdisc)" == "fq" &&
   "$(sysctl -n net.ipv4.tcp_congestion_control)" == "bbr" ]] && return
{ echo "net.core.default_qdisc=fq"; echo "net.ipv4.tcp_congestion_control=bbr"; } | sudo tee -a /etc/sysctl.conf >/dev/null
echo "tcp_bbr" | sudo tee /etc/modules-load.d/bbr.conf >/dev/null
sudo modprobe tcp_bbr 2>/dev/null || true
sudo sysctl -p >/dev/null
```
- **Root crontab:** every 3 hours it sends SIGUSR1 (`-10`) to `frpc` and `frps`. The comment says this "triggers Garbage Collection". Go's runtime catches SIGUSR1 and ignores it unless the program registers a handler. I'm not aware of frp handling SIGUSR1, so this is probably a no-op. It doesn't kill anything, but check it against the installed frp version.
- **sysctl:** sets `net.core.default_qdisc=fq` and `net.ipv4.tcp_congestion_control=bbr`, appended to `/etc/sysctl.conf`. It also writes `/etc/modules-load.d/bbr.conf` = `tcp_bbr`.
- There are no other sysctls: no buffer sizes, no `somaxconn`, no `ip_local_port_range`, no file-max. `LimitNOFILE=infinity` in the units is the only fd tuning.

### `reduce_io` (Utilities 2)
```bash
sudo systemctl disable --now rsyslog && \
sudo sed -i 's/^#Storage=.*/Storage=volatile/' /etc/systemd/journald.conf && \
sudo sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=50M/' /etc/systemd/journald.conf && \
sudo sed -i 's/^#SystemKeepFree=.*/SystemKeepFree=5M/' /etc/systemd/journald.conf && \
sudo systemctl restart systemd-journald
```
This disables rsyslog and switches journald to RAM-only storage. Note that `SystemMaxUse` is ignored under volatile storage (that is `RuntimeMaxUse`). The sed only edits lines that are still commented out (`#...`).

### `remove_logs` (Utilities 3)
This runs `journalctl --vacuum-time=1s`, truncates every `/var/log/**/*.log`, and deletes `*.log.*`, `*.gz` and `*.1`…`*.9`. It also truncates `/var/log/wtmp` and `/var/log/btmp`, which wipes login and audit history.

---

## 8. IPv6 support

- **Server binds v6:** `bindAddr = "::"`. On Linux with the default `net.ipv6.bindv6only=0`, this one socket also accepts IPv4, as v4-mapped addresses. The quic and kcp UDP listeners use the same bindAddr.
- **Proxy listeners:** `proxyBindAddr` is unset, so it defaults to `bindAddr` (`::`). Every `remotePort` on Iran is therefore reachable over both IPv4 and IPv6.
- **Client dials v6:** the prompt reads "Server IP (v4 or v6)", and the value goes straight into `serverAddr = "2001:db8::1"` with no brackets. frp joins host and port with `net.JoinHostPort`, so an IPv6 literal works, and so does a hostname with AAAA records. The protocol choice doesn't matter for this: tcp, ws, kcp and quic all work over v6.
- **Local side:** `localIP = "127.0.0.1"` is always IPv4 loopback. A foreign service listening only on `::1` would not be reached.
- The script never configures IPv6 itself: no addresses, no routes, no 6to4 or local-v6 tunnels. It just uses whatever addressing the hosts already have. A common pattern is to run it over a private v6 created by another tool; it doesn't do that.

---

## 9. Uninstall / cleanup (`remove_frp`, menu 8)

```bash
stop_services
enabled_servers=$(systemctl list-unit-files | grep "frps@" | awk '{print $1}' || true)
for service in $enabled_servers; do systemctl disable "$service" 2>/dev/null || true; done
# same for frpc@
rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service
rm -f /usr/local/bin/frpc /usr/local/bin/frps
rm -rf /root/frp/
systemctl daemon-reload
```

Things it **leaves behind**:
- Enabled-instance symlinks in `/etc/systemd/system/multi-user.target.wants/frps@server-*.service` and `frpc@client-*.service`. `list-unit-files` only lists the template `frps@.service`, and disabling the bare template doesn't remove instance links, so these become dangling links.
- `/usr/local/bin/frp-manager`
- The root crontab line `0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps`
- The BBR/FQ lines in `/etc/sysctl.conf` and `/etc/modules-load.d/bbr.conf`
- The journald changes and the disabled rsyslog, if Utilities 2 was used
- `/tmp/frp.tar.gz` and `/tmp/frp_<ver>_<platform>/`

Full manual cleanup:
```bash
systemctl disable --now 'frps@*' 'frpc@*' 2>/dev/null
rm -f /etc/systemd/system/multi-user.target.wants/frp[sc]@*.service
rm -f /etc/systemd/system/frps@.service /etc/systemd/system/frpc@.service
rm -f /usr/local/bin/frps /usr/local/bin/frpc /usr/local/bin/frp-manager
rm -rf /root/frp /tmp/frp.tar.gz /tmp/frp_*_linux_*
crontab -l | grep -vF 'pkill -10 -x frpc; pkill -10 -x frps' | crontab -
sed -i '/^net.core.default_qdisc=fq$/d;/^net.ipv4.tcp_congestion_control=bbr$/d' /etc/sysctl.conf   # optional
rm -f /etc/modules-load.d/bbr.conf                                                                 # optional
systemctl daemon-reload
```

---

## 10. Security concerns and bugs

### Security
1. **Hard-coded public default token `mikeesierrah`** on both sides. Combined with point 2, any Iran server installed with defaults lets anyone on the internet log in as a client and open arbitrary public ports on it, i.e. an open relay or abuse platform.
2. **No `allowPorts` and no `maxPortsPerClient`** on frps. An authenticated client can bind any port, including below 1024 (frps runs as root), and can shadow `22` or `80` if they are free.
3. **No transport encryption:** `transport.tls.enable = false` plus `useEncryption = false`. On tcp, websocket and kcp, both the auth handshake and the tunnelled payload cross the Iranian border in plaintext frp framing, which DPI can fingerprint easily. Only QUIC is encrypted by its own TLS. The token itself is sent as an MD5 hash with a timestamp, not in clear, but the hash can still be observed.
4. **Supply chain:** `install_script` fetches and installs whatever is on `main` of the repo, with `curl -L` and no `-f`, pin or hash. frp itself is "latest" with no checksum or signature check.
5. **Unescaped input interpolated into TOML/templates:** token, server IP and port list. A `"` in the token breaks the config. The port string sits inside a Go-template string literal, which is template injection, though only by root against themselves.
6. **Overbroad capabilities:** `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` on an internet-facing daemon that already runs as root, with no hardening (`NoNewPrivileges`, `ProtectSystem`, and so on).
7. **`remove_logs`** wipes wtmp/btmp and all logs. It is anti-forensic and destroys audit trails. `reduce_io` also removes persistent logs.
8. No frps dashboard and no admin API, which is good: nothing extra is exposed.

### Bugs and fragility
1. **`install_script` runs before the root check** (line 165 vs line 662). If you're not root, the `curl -o /usr/local/bin/...` fails and `set -e` kills the script with a curl error before the friendly "must be run as root" message appears.
2. When launched through `bash <(curl ...)`, `$0` is `/dev/fd/63`, so the script always reinstalls itself. If `raw.githubusercontent.com` is blocked or slow (common in Iran), the whole run aborts.
3. **`sudo` is used everywhere even though the script already runs as root.** On minimal images without `sudo`, `optimize` fails, and so does the whole script at startup under `set -e`. A missing `cron`/`crontab` has the same effect.
4. `optimize` appends to `/etc/sysctl.conf` whenever *either* value differs, which can leave duplicate lines. On distros where systemd-sysctl doesn't read `/etc/sysctl.conf` (e.g. Debian 13 dropped the `99-sysctl.conf` symlink), the setting may not survive a reboot. The `modules-load` file still loads the module.
5. **The GitHub API call is unauthenticated** and limited to 60 requests per hour per IP; Iranian NAT/shared IPs hit this often. On failure, `version` is empty, `curl -L` without `-f` saves an HTML or JSON error page, `tar` fails, and the script aborts. There is no mirror or proxy option.
6. **Re-running Install while services are up:** `cp` over a running binary fails with "Text file busy" and the script aborts. There is no stop-and-replace upgrade path.
7. **Client config name collision:** `client-<serverPort>.toml` is keyed only by port. Two Iran servers on 7000 overwrite each other, and `enable --now` on an already-running instance doesn't restart it, so the new config isn't applied until a manual restart. The same goes for re-running server setup on an existing port.
8. **`show_status` "Enabled services"** greps `list-unit-files` for `frp[sc]@.*enabled`, but instances never show up there. It always prints "No FRP services enabled".
9. **`remove_frp`** leaves dangling instance symlinks (§9).
10. **Server/client protocol mismatch isn't validated.** The server defaults to quic and the client to tcp, which happens to work. A client choosing kcp against a quic server fails silently, retrying forever because `loginFailExit=false`.
11. **The port list isn't validated.** An empty input produces `parseNumberRangePair "" ""`, which fails at frpc start, and the service flaps every 10 s.
12. `reduce_io` prints success even if the `&&` chain stopped early, e.g. when rsyslog isn't installed. `SystemMaxUse` has no effect with volatile storage.
13. `remove_logs`: under `set -e`, a failing `truncate` on a missing `/var/log/btmp` aborts the whole script.
14. `ExecReload` sends HUP, which kills the process (frp doesn't handle it) rather than reloading. `Restart=on-failure` may or may not restart it, depending on the exit status.
15. In `advanced_config`, `${EDITOR:-nano}` is unquoted, there is no check that nano exists, and the service is only restarted if it was active (editing a stopped or failed instance doesn't start it).
16. The SIGUSR1 "GC" cron job is probably ineffective (§7).
17. `heartbeatInterval = 30` is forced even with `tcpMux = true`. frp normally disables app heartbeats under mux; this is harmless.

---

## 11. How to reproduce manually without the script

Assumptions: Iran = `IR` (public IP `IR_IP`, v4 or v6), Foreign = `FR`. Tunnel port 7000. Forwarded ports 443 and 8080-8081. Run as root.

### 11.1 Both hosts: install the binaries and units
```bash
VER=$(curl -fsSL https://api.github.com/repos/fatedier/frp/releases/latest | grep -m1 tag_name | cut -d '"' -f4 | sed 's/^v//')
# or pin explicitly, e.g. VER=0.61.1
case "$(uname -m)" in x86_64) A=amd64;; aarch64) A=arm64;; armv7l|armv6l) A=arm;; esac
curl -fL "https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${A}.tar.gz" -o /tmp/frp.tar.gz
tar -xzf /tmp/frp.tar.gz -C /tmp
install -m 0755 /tmp/frp_${VER}_linux_${A}/frps /tmp/frp_${VER}_linux_${A}/frpc /usr/local/bin/
mkdir -p /root/frp/server /root/frp/client

for R in s c; do
  [ $R = s ] && D=server N=Server || { D=client; N=Client; }
  cat > /etc/systemd/system/frp${R}@.service <<EOF
[Unit]
Description=FRP ${N} Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frp${R} -c /root/frp/${D}/%i.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
done
systemctl daemon-reload
```

### 11.2 Optional: what `optimize` does
```bash
grep -q '^net.core.default_qdisc=fq' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
grep -q '^net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
echo tcp_bbr > /etc/modules-load.d/bbr.conf
modprobe tcp_bbr; sysctl -p
(crontab -l 2>/dev/null; echo '0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps') | crontab -   # script's "GC" cron (likely no-op)
```

### 11.3 Iran (server)
```bash
TOKEN=$(openssl rand -hex 24)   # do NOT use the default "mikeesierrah"
cat > /root/frp/server/server-7000.toml <<EOF
# Auto-generated frps config
bindAddr = "::"
bindPort = 7000
quicBindPort = 7000

transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

transport.heartbeatTimeout = 90
transport.maxPoolCount = 65535
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.tcpKeepalive = 120

auth.method = "token"
auth.token = "${TOKEN}"
EOF
# Recommended hardening the script omits:
#   allowPorts = [ { single = 443 }, { start = 8080, end = 8081 } ]
systemctl enable --now frps@server-7000
# firewall: open TCP 7000 (+UDP 7000 for quic/kcp) and the forwarded TCP ports
```
For KCP, replace `quicBindPort` with `kcpBindPort = 7000` and comment out the quic lines. For "none", drop both.

### 11.4 Foreign (client)
```bash
cat > /root/frp/client/client-7000.toml <<'EOF'
serverAddr = "IR_IP"
serverPort = 7000

loginFailExit = false

auth.method = "token"
auth.token = "SAME_TOKEN"

transport.protocol = "tcp"
transport.tcpMux = false
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = false
transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

{{- range $_, $v := parseNumberRangePair "443,8080-8081" "443,8080-8081" }}
[[proxies]]
name = "tcp-{{ $v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ $v.First }}
remotePort = {{ $v.Second }}
transport.useEncryption = false
transport.useCompression = false
{{- end }}
EOF
sed -i "s/IR_IP/<iran-ip-or-v6>/; s/SAME_TOKEN/<token>/" /root/frp/client/client-7000.toml
systemctl enable --now frpc@client-7000
journalctl -u frpc@client-7000 -f    # expect "login to server success" and "start proxy success"
```
`transport.protocol` can be `"tcp"`, `"websocket"`, `"quic"` (needs `quicBindPort` on the server) or `"kcp"` (needs `kcpBindPort`). Consider `transport.tls.enable = true`, the frp default, unless you have a reason to disable it.

### 11.5 Verify
```bash
# Iran
ss -tlnp | grep frps          # [::]:7000 and [::]:443, [::]:8080, [::]:8081
ss -ulnp | grep frps          # [::]:7000 if quic/kcp
# from anywhere
curl -vk https://IR_IP:443/   # should reach FOREIGN 127.0.0.1:443
```
