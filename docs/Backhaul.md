# Backhaul (Musixal/Backhaul) — technical reference

> Source analysed: upstream tree at `/home/user/tunnels-kb/sources/backhaul-upstream`
> (`main.go`: `const version = "v0.7.2"`, module `github.com/musix/backhaul`, Go 1.23, AGPL-3.0).
> Everything below was read from the code. Nothing from the tree was built or executed.
> Where the upstream README and the code disagree, the **code wins** and the difference is noted.

> **About the installer the user was given**
> `bash <(curl -fsSL http://5.75.204.246:7864/backhaul/install.sh)` timed out from this environment, so
> **its contents could not be checked**. It is *probably* a community wrapper that downloads and configures
> Backhaul, but that is an assumption. See [Security notes](#10-security-notes): it is fetched over plain HTTP from a
> bare IP and piped into a root shell, which is a textbook MITM / supply-chain risk.

---

## 1. Purpose and architecture

Backhaul is a **reverse TCP/UDP port-forwarding tunnel**. It has one binary and one TOML file per instance, and the
role comes from the config section that is set:

```go
// cmd/cmd.go
if cfg.Server.BindAddr != "" {
    configType = "server"
} else if cfg.Client.RemoteAddr != "" {
    configType = "client"
}
```

Typical deployment (the Iranian community's "reverse tunnel"):

```
 end users ──► IRAN VPS  ([server])                 FOREIGN VPS ([client])
               listens on bind_addr (tunnel port)  ◄── dials out to IRAN:bind_addr
               listens on every "ports" entry           (control channel + pool of data conns)
               │                                        │
               └── user conn on port P ──tunnel──►  client dials target (default 127.0.0.1:P)
                                                        e.g. Xray/V2Ray/WireGuard-over-tcp, etc.
```

* **Server = Iran side.** It owns the public listening ports (`ports = [...]`) and the tunnel listener
  (`bind_addr`).
* **Client = foreign side.** It sits behind NAT or a firewall, or just does not accept inbound connections. It **dials out** to the
  server, so only outbound traffic leaves the foreign box. That is the "reverse" part. The client then opens
  connections to the real service locally (or to any `host:port` the server tells it).
* **Control channel.** The first connection the client opens is authenticated with `token` and becomes the control
  channel. Over it the server sends 1-byte signals (`internal/utils/signals.go`):

```go
const (
    SG_HB     byte = iota // 0 heartbeat
    SG_Chan               // 1 request a new data connection / handshake marker
    SG_Ping               // 2 ping (ws/udp data conns)
    SG_Closed             // 3 peer closing
    SG_TCP                // 4 data conn carries TCP
    SG_UDP                // 5 data conn carries UDP (accept_udp)
    SG_RTT                // 6 RTT probe
)
```

* **Data path (non-mux).** For each user connection accepted on a server port, the server queues it
  (`localChannel`) and sends `SG_Chan` on the control channel. The client answers by dialing a **fresh data
  connection** (or one is already waiting in the pool). The server writes a framed target address
  (`[uint16 len][1 byte type][addr]`, `utils.SendBinaryTransportString`) into it, and from then on it is a raw byte pipe
  (`handlers.TCPConnectionHandler`, 16 KiB copy buffer).
* **Data path (mux).** The client keeps TCP (or WS) connections that the server turns into **smux sessions**
  (`github.com/xtaci/smux v1.5.27`). Note that the **server is the smux *client*** (`smux.Client(conn, …)`) and opens
  streams. The foreign client is the smux *server* and accepts streams. Each user connection becomes one stream.
* **Client pool.** The client pre-dials `connection_pool` idle data connections and resizes the pool dynamically
  every 10 s according to load (`poolMaintainer`; `aggressive_pool` changes the factors).
* **Server timeouts.** A user connection that does not get a tunnel connection within **3000 ms** is dropped
  (`handleLoop`: `if time.Now().UnixMilli()-localConn.timeCreated > 3000`).
* **Restart model.** If the control channel fails, either side tears everything down and restarts the transport
  in-process after 2 s. The client keeps retrying every `retry_interval`.
* **Hot reload.** `main.go` polls the config file's mtime every 2 s. When it changes, it cancels the running instance and
  starts a new one with the new config, without a process restart.
* **Startup host tuning.** Unless `skip_optz = true`, every start runs `sysctl -w` (see §8) and raises
  `RLIMIT_NOFILE` to 1048576.

CLI:

```
backhaul -c /path/to/config.toml   # run
backhaul -v                        # print version (v0.7.2 in this tree)
```

Release artefacts (`.goreleaser.yaml`): `backhaul_{linux,darwin}_{amd64,arm64}.tar.gz` plus `checksums.txt`,
built with `CGO_ENABLED=0` (static).

---

## 2. Transports (how each one works internally)

Valid `transport` values in this tree (`config/config.go`):

```go
TCP    = "tcp";  TCPMUX = "tcpmux"
WS     = "ws";   WSS    = "wss"
WSMUX  = "wsmux"; WSSMUX = "wssmux"
UDP    = "udp"
```

> **There is no `utcp`, `udpmux`, `kcp`, `quic`, `anytls`, etc. in this source.** Any other value makes the binary
> exit with `invalid transport type`. Later or closed builds distributed by the author or third parties may have
> more transports. If an installer writes such values, check what the installed binary actually supports
> (`backhaul -v`, plus test-start it).

| transport | Tunnel socket | Multiplexing | Encryption | Server-side ports carry | Notes |
|---|---|---|---|---|---|
| `tcp` | TCP to `bind_addr` | none (1 user conn = 1 tunnel TCP conn) | **none** | TCP (+ UDP if `accept_udp`) | lowest latency; most TCP handshakes |
| `tcpmux` | TCP to `bind_addr` | smux streams over pooled TCP conns | **none** | TCP | fewer sockets, head-of-line blocking per session |
| `ws` | HTTP/1.1 WebSocket (`ws://`) | none | **none** | TCP | each data conn = WS conn; WS-framed throughout (CDN-friendly) |
| `wss` | WebSocket over TLS | none | TLS (cert unverified by client) | TCP | needs `tls_cert`/`tls_key` on the server |
| `wsmux` | WS handshake, then **raw smux on the underlying socket** | smux | **none** | TCP | see caveat below |
| `wssmux` | WSS handshake, then raw smux inside TLS | smux | TLS (unverified) | TCP | |
| `udp` | TCP control channel + **raw UDP** datagrams to the same `bind_addr` | none | **none** | UDP | forwards UDP services (WireGuard, Hysteria, etc.) |

### 2.1 `tcp`
* The server listens with `network.ListenWithBuffers` (SO_REUSEADDR + SO_REUSEPORT, optional SO_RCVBUF/SO_SNDBUF/
  TCP_MAXSEG, TCP_NODELAY on or off).
* Handshake: the client sends `[len][SG_Chan][token]`, the server checks it and echoes the token back. The read deadline is 2 s.
* Once a control channel exists, the server **only accepts further tunnel connections from the same source IP**:

```go
// server/transport/tcp.go
if s.controlChannel != nil && s.controlChannel.RemoteAddr().(*net.TCPAddr).IP.String() != tcpConn.RemoteAddr().(*net.TCPAddr).IP.String() {
    s.logger.Debugf("suspicious packet from %v ...")
    tcpConn.Close()
```

  Data connections carry **no token**. The source-IP check is the only thing protecting them.
* The server runs `min(NumCPU,4)` handle loops that pair queued user connections with pooled tunnel connections.
* RTT is measured once on the control channel (`SG_RTT`) and logged (`Round Trip Time (RTT): N ms`). It is also used by
  the `accept_udp` congestion heuristic.
* `accept_udp = true` (tcp transport only) also opens a **UDP listener on every mapped port**. UDP datagrams are
  carried over the TCP tunnel connections with a 2-byte length prefix (plus a timestamp header for congestion detection,
  so stale packets older than 3×RTT mark the flow as congested and get dropped). Flows idle for more than 60 s are closed.

### 2.2 `tcpmux`
* Same handshake and source-IP filter as `tcp`. Every later client TCP connection is wrapped as an smux session:

```go
session, err := smux.Client(conn, s.smuxConfig)   // server side
// client side: smux.Server(tunnelConn, c.smuxConfig) + session.AcceptStream()
```

* smux config: `Version=mux_version`, `MaxFrameSize=mux_framesize`, `MaxReceiveBuffer=mux_recievebuffer`,
  `MaxStreamBuffer=mux_streambuffer`. **KeepAliveInterval 20 s and KeepAliveTimeout 40 s are hard-coded.**
* `mux_con` (server only) sets the number of concurrent streams per session. When
  `streamCounter >= sessionCounter*mux_con`, the server asks the client for another session (`SG_Chan`).
* Each stream begins with `[uint16 len][target addr]` (`SendBinaryString`).

### 2.3 `ws` / `wss`
* The server is a Go `net/http` server on `bind_addr` (`ListenAndServeTLS(tls_cert, tls_key)` for wss).
* **Every HTTP request** must carry `Authorization: Bearer <token>`, otherwise the server answers `401`.
* Paths: `/channel` is the control channel. `/tunnel/<random int>` is a data connection. The client also sends a random
  `X-User-Id` and a random browser `User-Agent` (30 hard-coded UAs) as light camouflage.
* A **second `/channel` request** (from anyone holding the token) closes the existing one and restarts the server.
* Data: the server sends the target address as a WS text message, then the payload flows as binary WS messages
  (`handlers.WSConnectionHandler`). The server pings idle pooled data connections every `heartbeat` with `SG_Ping`.
* The client's `edge_ip` lets you set the TCP destination (a CDN edge) separately from the Host/SNI in `remote_addr`:

```go
// internal/utils/network/ws_dialer.go
if edgeIP != "" { _, port, _ := net.SplitHostPort(addr); edgeIP = fmt.Sprintf("%s:%s", edgeIP, port) } else { edgeIP = addr }
wsURL = fmt.Sprintf("wss://%s%s", addr, path)      // Host/SNI = remote_addr host
NetDial: TcpDialer(ctx, edgeIP, ...)               // actual TCP dial = edge_ip:port
```

* **TLS verification is disabled on the client** (`InsecureSkipVerify: true`), so any certificate is accepted,
  self-signed ones included.
* The `ws`/`wss` server has **no source-IP filter**, but each request is token-checked.

### 2.4 `wsmux` / `wssmux`
* Same HTTP endpoint, token check and paths as ws/wss. After the upgrade both sides run smux over the
  **underlying net.Conn**, not over WebSocket frames:

```go
session, err := smux.Client(conn.NetConn(), s.smuxConfig)        // server/transport/wsmux.go
session, err := smux.Server(tunnelConn.NetConn(), c.smuxConfig)  // client/transport/wsmux.go
```

  Consequence (inferred from the code): after the `101 Switching Protocols` the bytes on the wire are raw smux frames,
  not valid WebSocket frames. A CDN or reverse proxy that parses WS frames (e.g. Cloudflare) is therefore likely to
  break `wsmux`/`wssmux`. If you need to go through a CDN, use framed `ws`/`wss`. Direct connections are fine.
* `mux_con` and the `mux_*` fields apply as in tcpmux.

### 2.5 `udp`
* The **control channel is TCP** on `bind_addr` (same token handshake). The data tunnel uses **UDP datagrams to the same
  `bind_addr`**, so you must open **both TCP and UDP** on that port in firewalls.
* A new UDP tunnel flow starts with a datagram whose payload is exactly the token (plaintext), and the server keys flows by
  `addr.String()`. The server's `ports` are **UDP listeners**, and payloads are forwarded as raw datagrams (read buffer 16 KiB).
  Flows idle for more than 60 s are closed. The server sends `SG_Ping` keep-alives every `heartbeat`.
* There is no reliability, ordering, or encryption. The README's "UDP over TCP" wording refers to `accept_udp` on the tcp
  transport, not to this transport.

---

## 3. Configuration schema (from `config/config.go` + `cmd/defaults.go`)

Exactly one of `[server]` or `[client]` should be filled. Unknown keys are silently ignored by `BurntSushi/toml`, so
**typos do not raise errors**. Note the upstream misspelling `mux_recievebuffer`. The correctly spelled key does nothing.

### 3.1 `[server]` (Iran side)

| key | type | default (code) | meaning / where used |
|---|---|---|---|
| `bind_addr` | string | **required** | Tunnel listen address, e.g. `"0.0.0.0:3080"`, `"[::]:3080"`. A non-empty value selects server mode. |
| `transport` | string | **required** | `tcp`, `tcpmux`, `ws`, `wss`, `wsmux`, `wssmux`, or `udp`. Must match the client. |
| `token` | string | `"musix"` | Shared secret. **Change it**, because the default is public. |
| `ports` | []string | `[]` | Port mappings, see §4. |
| `nodelay` | bool | `false` | TCP_NODELAY on tunnel and user sockets (`false` means Nagle on). |
| `keepalive_period` | int s | `75` | TCP keep-alive interval (`KeepAliveConfig{Interval, Count: 9}`). |
| `heartbeat` | int s | `40` (min 1) | Control-channel heartbeat (`SG_HB`) and ping interval for ws/udp data connections. |
| `channel_size` | int | `2048` | Capacity of the internal queues (pending user connections, pooled tunnel connections, new-connection requests). Overflow causes the connection to be **dropped** with a warning. |
| `mux_con` | int | `8` | (mux only) Concurrent streams per smux session before another session is requested. |
| `mux_version` | int | `1` (1 or 2, else reset to 1) | smux protocol version. Must match the client. |
| `mux_framesize` | int B | `32768` | smux MaxFrameSize. |
| `mux_recievebuffer` | int B | `4194304` | smux MaxReceiveBuffer (per session). |
| `mux_streambuffer` | int B | `65536` | smux MaxStreamBuffer (per stream). The README comment says "256KB", but the value is 64 KiB. |
| `mux_session` | int | `1` | **Parsed but unused** in v0.7.2. |
| `accept_udp` | bool | `false` | (tcp transport only) Also listen on UDP for every mapped port and carry UDP over the TCP tunnel. |
| `proxy_protocol` | bool | `false` | (tcp, tcpmux, wsmux, wssmux; **not** ws/wss/udp) Prepend a **PROXY protocol v2** header to every forwarded TCP stream so the foreign-side service sees the real user IP. The service must expect PROXY v2. |
| `tls_cert` / `tls_key` | path | none | Required for `wss`/`wssmux`. |
| `web_port` | int | `0` (disabled) | Status web UI port (binds `:<port>` on **all interfaces**, no auth). |
| `sniffer` | bool | `false` | Count per-port traffic and expose `/data`. Persisted to `sniffer_log` every 15 s. |
| `sniffer_log` | path | `"backhaul.json"` (relative to the CWD) | JSON per-port usage file. |
| `log_level` | string | `"info"` | `panic`, `fatal`, `error`, `warn`, `info`, `debug`, or `trace`. Invalid values fall back to info. |
| `pprof` | bool | `false` | Starts `net/http/pprof` on **0.0.0.0:6060** (no auth). |
| `skip_optz` | bool | `false` | `true` skips the startup `sysctl` tuning and the rlimit change. |
| `mss` | int B | system | TCP_MAXSEG on the tunnel listener (tcp/tcpmux). |
| `so_rcvbuf` / `so_sndbuf` | int B | system | SO_RCVBUF/SO_SNDBUF on the tunnel listener (tcp/tcpmux). |

### 3.2 `[client]` (foreign side)

| key | type | default | meaning |
|---|---|---|---|
| `remote_addr` | string | **required** | Server `host:port`. IPv4, `[IPv6]:port` or a domain. For ws/wss it is also the Host header and SNI. |
| `transport` | string | **required** | Must equal the server's. |
| `token` | string | `"musix"` | Must equal the server's. |
| `connection_pool` | int | `8` | Initial number of pre-dialed idle data connections (minimum pool size). |
| `aggressive_pool` | bool | `false` | Grows the pool faster and shrinks it sooner (factors `a,b,x,y` = `1,2,0,0.75` vs `4,5,3,4.0`). |
| `retry_interval` | int s | `3` | Wait between control-channel dial attempts. |
| `dial_timeout` | int s | `10` (min 1) | Timeout for each TCP dial (tunnel and local target). |
| `nodelay` | bool | `false` | TCP_NODELAY on data connections. The control channel always uses nodelay. |
| `keepalive_period` | int s | `75` | TCP keep-alive interval. |
| `mux_version` / `mux_framesize` / `mux_recievebuffer` / `mux_streambuffer` | | `1` / `32768` / `4194304` / `65536` | smux settings. Keep them identical to the server. |
| `mux_session` | int | `1` | Unused. |
| `edge_ip` | string | `""` | (ws/wss/wsmux/wssmux) TCP-dial this IP instead of resolving `remote_addr` (CDN edge / domain fronting). Port is taken from `remote_addr`. |
| `web_port`, `sniffer`, `sniffer_log`, `log_level`, `skip_optz` | | as server | Same meaning. `pprof` on the client binds **0.0.0.0:6061**. |
| `mss`, `so_rcvbuf`, `so_sndbuf` | | system | Applied to tunnel dials (tcp/tcpmux) and to local target dials (localhost targets are forced to 32 KiB buffers). |

There is **no `heartbeat`, `channel_size`, `mux_con`, `ports`, `accept_udp`, `proxy_protocol`, or TLS field on the client**.
The ports and the target addresses all come from the server.

---

## 4. Port-mapping syntax (`ports = [...]`, server only)

The parser (`parsePortMappings`, identical in every transport) splits **on `=`**:

| entry | server listens on | client dials | notes |
|---|---|---|---|
| `"443"` | `:443` (all IPs, v4+v6) | `127.0.0.1:443` | Single port. Target defaults to localhost on the same port. |
| `"443-600"` | `:443` … `:600` | `127.0.0.1:<same port>` | Range. One listener per port, started 1 ms apart. |
| `"443-600=5201"` | `:443` … `:600` | `127.0.0.1:5201` | Range funnelled to one port. |
| `"443-600=1.1.1.1:5201"` | `:443` … `:600` | `1.1.1.1:5201` | |
| `"4000=5000"` | `:4000` | `127.0.0.1:5000` | |
| `"443=1.1.1.1:5201"` | `:443` | `1.1.1.1:5201` | The target is resolved **by the client** (foreign side). |
| `"127.0.0.2:443=5201"` | `127.0.0.2:443` | `127.0.0.1:5201` | Local IP binding (left side is not a bare port, so it is used verbatim). |
| `"127.0.0.2:443=1.1.1.1:5201"` | `127.0.0.2:443` | `1.1.1.1:5201` | |
| `"[::1]:443=5201"` | `[::1]:443` | `127.0.0.1:5201` | IPv6 local bind works (the left side goes to `net.Listen` as-is). |
| `"443=example.com:8443"` | `:443` | `example.com:8443` | Hostnames are fine and can resolve to AAAA. |

How the client resolves a target (`internal/utils/network/resolver.go`):

```go
parts := strings.Split(remoteAddr, ":")
if len(parts) < 2 { ... return port, fmt.Sprintf("127.0.0.1:%d", port), nil }
port, err = strconv.Atoi(parts[1])   // 2nd colon-separated field must be the port
```

Gotchas found in the code:
* **The README's `"443-600:5201"` (colon) form does not parse in v0.7.2.** The range parser runs `Atoi("600:5201")`,
  which fails, and the process exits fatally. Use `"443-600=5201"`.
* In the `local=remote` single-port form the check is `port > 1 && port < 65535`, so local ports **1 and 65535** fall into the
  "ip:port" branch and the listen fails. Avoid them.
* A bad entry is **fatal** (`logger.Fatalf`) and kills the whole process.
* For ranges the left side cannot carry a bind IP (`"127.0.0.2:443-600"` is invalid).
* With the `udp` transport the listeners are UDP, and with `accept_udp` on tcp they are TCP and UDP.

---

## 5. IPv6 support

* **Tunnel endpoints work over IPv6.** Server `bind_addr = "[::]:3080"` (or `":3080"`, which on Linux with
  `net.ipv6.bindv6only=0` is dual-stack). Client `remote_addr = "[2001:db8::1]:3080"` or a domain with an AAAA record.
  The dialers use `net.ResolveTCPAddr("tcp", …)`, which accepts both families. ws/wss build `ws://[v6]:port/…`
  correctly because the address string is reused verbatim.
* **Mapped user ports** without a bind IP listen on `:port`, so IPv4 and IPv6 users are both accepted.
  An explicit `[v6]:port=…` bind works.
* **IPv6 literal targets on the right side of a mapping do not work.** `"443=[2001:db8::10]:443"` fails in
  `ResolveRemoteAddr` because splitting on `:` gives the port field `"db8"`, and the connection is closed with
  `failed to resolve remote port`. Workaround: use a **hostname** (e.g. an `/etc/hosts` entry on the foreign box that
  maps to the v6 address) or an IPv4 target.
* **`edge_ip` with an IPv6 literal** must be written **with brackets** (`edge_ip = "[2606:4700::1]"`). The code does
  `fmt.Sprintf("%s:%s", edgeIP, port)` without adding brackets.
* `proxy_protocol` emits AF_INET6 (`0x21`) headers when both addresses are v6 and AF_INET otherwise.
* The tcp/tcpmux source-IP filter compares `IP.String()`. A client that switches address family (v4 vs v6) between
  the control channel and data connections will have its data connections dropped as "suspicious". Pin one family, either
  with a literal in `remote_addr` or with a single-family DNS name.

---

## 6. Web UI, sniffer, stats, logs

* `web_port > 0` starts an HTTP server on `:<web_port>` with **no authentication**:
  * `/` is an HTML dashboard (embedded `internal/web/index.html`) that polls the JSON endpoints.
  * `/stats` returns JSON `{tunnelStatus, cpuUsage, ramUsage, diskUsage, swapUsage, networkTraffic, uploadSpeed,
    downloadSpeed, backhaulTraffic, sniffer, allConnections}` (gopsutil).
  * `/data` (only with `sniffer = true`) returns per-port usage `[{Port, ReadableUsage}]`.
* `sniffer = true` makes every copy loop call `usage.AddOrUpdatePort(port, bytes)`. Counters are merged into
  `sniffer_log` (JSON `[{"Port":443,"Usage":12345}]`, mode 0644) every 15 s. The default `backhaul.json` is
  **relative to the working directory**, so set an absolute path under systemd.
* `tunnelStatus` strings: `"Connected (TCP)"`, `"Disconnected (TCPMux)"`, `"Connected (wss)"`, and so on.
* Logs go to **stdout** through logrus with a custom colourised formatter (`02-Jan 15:04:05 [LEVEL] msg`), so under systemd
  they end up in the journal with ANSI colour codes. Useful lines: `control channel established successfully`,
  `Round Trip Time (RTT): N ms`, `listener started successfully, listening on address: …`,
  `channel … is full, discarding …` (raise `channel_size` or the pool), `invalid security token received: <token>`.
* `pprof = true` opens Go pprof on `0.0.0.0:6060` (server) or `0.0.0.0:6061` (client).

---

## 7. Install layout and systemd

### 7.1 Upstream recommendation (README)

```ini
[Unit]
Description=Backhaul Reverse Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=/root/backhaul -c /root/config.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

### 7.2 Conventional community-installer layout (**typical, not verified** for the user's script)

Popular Persian installer scripts usually install like this:
* binary: `/root/backhaul/backhaul`
* configs: `/root/backhaul/*.toml`, e.g. `iran<PORT>.toml` / `kharej<PORT>.toml` or `server.toml` / `client.toml`
* units: `/etc/systemd/system/backhaul-*.service`, e.g. `backhaul-iran3080.service`, `backhaul-kharej3080.service`
  (one unit per tunnel instance), often with a cron or timer that restarts them periodically.

Because the user's installer could not be fetched, check what it actually created with
`ls /root/backhaul; systemctl list-units 'backhaul*'; cat /etc/systemd/system/backhaul*.service`.

### 7.3 Recommended unit (one per tunnel)

```ini
# /etc/systemd/system/backhaul-iran.service   (or backhaul-kharej.service on the foreign box)
[Unit]
Description=Backhaul tunnel (%N)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/backhaul
ExecStart=/root/backhaul/backhaul -c /root/backhaul/iran.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
# sysctl tuning and setrlimit need root. Set skip_optz=true and drop root only if you tune the host yourself.

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now backhaul-iran.service
journalctl -u backhaul-iran.service -f
```

Do not combine hot reload and systemd edits carelessly. Saving the TOML already restarts the tunnel in-process,
so `systemctl restart` is only needed after a binary upgrade.

---

## 8. Tuning

What `ApplyTCPTuning()` changes on every start unless `skip_optz = true` (these are **global, persistent until
reboot** host changes):

```
net.core.rmem_max / wmem_max = first of 256/128/64/32/16 MiB that succeeds
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse=1   net.ipv4.tcp_fin_timeout=15
net.core.somaxconn=65536  net.ipv4.tcp_max_syn_backlog=20480
net.ipv4.tcp_window_scaling=1  net.ipv4.tcp_fastopen=3
net.ipv4.tcp_notsent_lowat=32768
net.core.rmem_default=1048576  net.core.wmem_default=1048576
RLIMIT_NOFILE = 1048576
```

`ip_local_port_range=1024 65535` can collide with services that bind high ports. If you manage sysctl yourself
(e.g. alongside BBR, `fq`, IPsec or other tunnels), set `skip_optz = true`.

Recommendations:

| knob | guidance |
|---|---|
| `transport` | Use `tcp` for lowest latency and simplicity on a clean path. Use `tcpmux` when many short connections or SYN rate-limiting hurt. Use `ws`/`wss` when DPI blocks raw TCP or when you need a CDN (`edge_ip`). Use `wssmux` for TLS-looking direct links with many connections. Use `udp` only for UDP services. |
| `nodelay` | `true` for interactive or proxy traffic (VLESS/VMess, SSH, gaming). `false` (default) for bulk throughput. Set it the same on both sides. |
| `keepalive_period` | 75 s is fine. Lower it (20–30 s) if a middlebox or NAT drops idle connections. |
| `heartbeat` | 40 s default. Lower it (10–20 s) to detect a dead control channel faster on lossy links. Each heartbeat is 1 byte. |
| `channel_size` | 2048 is enough for most cases. Raise it (4096–8192) if the logs show `channel is full, discarding`. |
| `connection_pool` | 8 default. Raise it to 16–64 for bursty high-concurrency loads on non-mux transports (each pooled connection is one idle TCP connection). Try `aggressive_pool = true` if you see first-byte latency spikes under bursts. |
| `mux_con` | 8 default. Lower it (1–4) to cut head-of-line blocking, which means more TCP sessions. Raise it (16–32) to minimise connections. |
| `mux_version` | 1 (default) or 2. smux v2 adds per-stream window flow control. **Must match on both sides.** v2 is usually better for fairness between streams. |
| `mux_framesize` | 32 KiB default. Leave it unless MTU or DPI issues appear. smux caps frames at 65535. |
| `mux_recievebuffer` / `mux_streambuffer` | 4 MiB / 64 KiB defaults. For high-BDP links (e.g. 100 Mbit/s × 150 ms ≈ 1.9 MB) raise the stream buffer to 256 KiB–1 MiB and the session buffer to 8–16 MiB. Watch RAM: buffers are allocated per session/stream. |
| `mss` | Set ~1360–1400 when the path has a lower MTU (PPPoE, IPsec/GRE underneath) to avoid PMTU blackholes (tcp/tcpmux only). |
| `so_rcvbuf` / `so_sndbuf` | Increase on high-BDP links (4–16 MiB). They are capped by `net.core.rmem_max`/`wmem_max`. |
| `dial_timeout`, `retry_interval` | Defaults 10 s / 3 s are sane. |

---

## 9. Complete example configs (one pair per transport)

Replace `IRAN_IP`, ports and the token. Generate a token with `openssl rand -hex 16`.

### 9.1 tcp (+ UDP over TCP)

```toml
# /root/backhaul/iran.toml
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcp"
accept_udp = true
token = "CHANGE_ME_32_HEX"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
log_level = "info"
web_port = 2060
sniffer = false
sniffer_log = "/root/backhaul/backhaul.json"
ports = ["443", "8443=2053", "20000-20010=10000"]
```

```toml
# /root/backhaul/kharej.toml
[client]
remote_addr = "IRAN_IP:3080"
transport = "tcp"
token = "CHANGE_ME_32_HEX"
connection_pool = 16
aggressive_pool = false
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = true
log_level = "info"
web_port = 2060
```

### 9.2 tcpmux

```toml
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcpmux"
token = "CHANGE_ME"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
mux_con = 8
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
log_level = "info"
ports = ["443", "2053"]
```

```toml
[client]
remote_addr = "IRAN_IP:3080"
transport = "tcpmux"
token = "CHANGE_ME"
connection_pool = 8
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = true
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
log_level = "info"
```

### 9.3 udp (forward UDP services, e.g. WireGuard 51820)

```toml
[server]
bind_addr = "0.0.0.0:3080"      # open TCP *and* UDP 3080
transport = "udp"
token = "CHANGE_ME"
heartbeat = 20
channel_size = 2048
log_level = "info"
ports = ["51820"]
```

```toml
[client]
remote_addr = "IRAN_IP:3080"
transport = "udp"
token = "CHANGE_ME"
connection_pool = 8
retry_interval = 3
dial_timeout = 10
log_level = "info"
```

### 9.4 ws (optionally through a CDN)

```toml
[server]
bind_addr = "0.0.0.0:8080"
transport = "ws"
token = "CHANGE_ME"
channel_size = 2048
keepalive_period = 75
heartbeat = 40
nodelay = true
log_level = "info"
ports = ["443"]
```

```toml
[client]
remote_addr = "tunnel.example.com:8080"   # Host header; must point (or be proxied) to the server
edge_ip = ""                               # e.g. "188.114.96.0" to dial a CDN edge directly
transport = "ws"
token = "CHANGE_ME"
connection_pool = 8
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = true
log_level = "info"
```

### 9.5 wss

```toml
[server]
bind_addr = "0.0.0.0:8443"
transport = "wss"
token = "CHANGE_ME"
channel_size = 2048
keepalive_period = 75
heartbeat = 40
nodelay = true
tls_cert = "/root/backhaul/server.crt"
tls_key  = "/root/backhaul/server.key"
log_level = "info"
ports = ["443"]
```

```toml
[client]
remote_addr = "IRAN_IP:8443"      # or a domain (it becomes the SNI)
edge_ip = ""
transport = "wss"
token = "CHANGE_ME"
connection_pool = 8
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = true
log_level = "info"
```

### 9.6 wsmux

```toml
[server]
bind_addr = "0.0.0.0:8080"
transport = "wsmux"
token = "CHANGE_ME"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
mux_con = 8
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
proxy_protocol = false
log_level = "info"
ports = ["443"]
```

```toml
[client]
remote_addr = "IRAN_IP:8080"
edge_ip = ""
transport = "wsmux"
token = "CHANGE_ME"
connection_pool = 8
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = true
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
log_level = "info"
```

### 9.7 wssmux

```toml
[server]
bind_addr = "0.0.0.0:443"
transport = "wssmux"
token = "CHANGE_ME"
keepalive_period = 75
nodelay = true
heartbeat = 40
channel_size = 2048
mux_con = 8
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
tls_cert = "/root/backhaul/server.crt"
tls_key  = "/root/backhaul/server.key"
log_level = "info"
ports = ["8443=443", "2096"]
```

```toml
[client]
remote_addr = "IRAN_IP:443"
edge_ip = ""
transport = "wssmux"
token = "CHANGE_ME"
connection_pool = 8
keepalive_period = 75
dial_timeout = 10
retry_interval = 3
nodelay = true
mux_version = 1
mux_framesize = 32768
mux_recievebuffer = 4194304
mux_streambuffer = 65536
log_level = "info"
```

### 9.8 IPv6 tunnel endpoints (any transport)

```toml
[server]
bind_addr = "[::]:3080"
transport = "tcpmux"
token = "CHANGE_ME"
ports = ["443", "[2001:db8:1::10]:8443=443"]
```

```toml
[client]
remote_addr = "[2001:db8:1::10]:3080"
transport = "tcpmux"
token = "CHANGE_ME"
```

---

## 10. Security notes

1. **Installer provenance.** The given command fetches over **plain HTTP from a bare IP** (`http://5.75.204.246:7864`)
   and pipes it straight into `bash` as root. Anyone on the path (ISP, national DPI, hijacked route, compromised host)
   can swap the script or the binary it downloads. Its content **could not be verified** here (connection timed out).
   Prefer this: download the release from `https://github.com/Musixal/Backhaul/releases`, check it against
   `checksums.txt` (`sha256sum -c`), copy it to the Iran box with `scp` if GitHub is blocked there, and write the TOML
   and unit yourself (§11). If you must use the script, download it to a file first, read it, then run it.
2. **No encryption on `tcp`, `tcpmux`, `ws`, `wsmux`, or `udp`.** The token and all tunnelled bytes are cleartext. Run an
   encrypted protocol inside (VLESS+Reality/TLS, WireGuard, SSH), or use `wss`/`wssmux`.
3. **`wss`/`wssmux` do not authenticate the server.** The client sets `InsecureSkipVerify: true`, so an active MITM can terminate
   TLS, learn the token and read or alter traffic. Inner encryption is still recommended.
4. **Token handling.** The default token is `"musix"`. Comparison is a plain `!=` (not constant-time). The server **logs the
   received wrong token** (`invalid security token received: %s`) and the client logs `Expected: <token>` on a mismatch,
   so treat the journal as sensitive. On tcp/tcpmux only the control channel carries the token. Data connections are accepted
   based on **source IP equal to the control channel's IP**, which is weak if the attacker shares that IP (CGNAT) or can spoof it.
5. **Takeover/DoS.** On ws/wss(mux) a second `/channel` request with a valid token restarts the server. Overflowing
   `channel_size` drops connections by design.
6. **Exposed admin surfaces.** `web_port` (all interfaces, no auth, shows CPU, RAM and traffic) and `pprof` (6060/6061 on
   0.0.0.0). Firewall them, or leave `web_port = 0` and `pprof = false`.
7. **Open-relay potential.** The server decides the target `host:port` and the client dials it from the foreign network.
   Anyone who can edit the Iran-side config can make the foreign box reach arbitrary hosts. Protect `/root/backhaul/*.toml`
   (mode 600). Hot reload applies edits within 2 s.
8. **Host changes.** It runs as root, and the startup `sysctl` changes are global (§8). `sniffer_log` is written with mode 0644.
9. **Firewall.** On Iran, allow inbound `bind_addr` (TCP, plus UDP for the `udp` transport) only from the foreign IP if possible,
   and the user-facing `ports`. On the foreign box no inbound is needed except for services you use locally.

---

## 11. Manual setup recipe (no third-party installer)

Download and verify (do this on a machine that can reach GitHub, then copy):

```bash
VER=v0.7.2            # or the latest tag you have reviewed
ARCH=amd64            # or arm64
mkdir -p /root/backhaul && cd /root/backhaul
curl -fsSLO https://github.com/Musixal/Backhaul/releases/download/$VER/backhaul_linux_$ARCH.tar.gz
curl -fsSLO https://github.com/Musixal/Backhaul/releases/download/$VER/checksums.txt
sha256sum -c --ignore-missing checksums.txt
tar -xzf backhaul_linux_$ARCH.tar.gz && chmod 755 backhaul && ./backhaul -v
# Iran box without GitHub access: scp /root/backhaul/backhaul root@IRAN_IP:/root/backhaul/
```

**Iran (server):**

```bash
TOKEN=$(openssl rand -hex 16); echo "$TOKEN"
cat > /root/backhaul/iran.toml <<EOF
[server]
bind_addr = "0.0.0.0:3080"
transport = "tcpmux"
token = "$TOKEN"
nodelay = true
heartbeat = 40
mux_con = 8
mux_version = 1
log_level = "info"
ports = ["443"]
EOF
chmod 600 /root/backhaul/iran.toml
# For wss/wssmux only:
# openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=example.com" \
#   -keyout /root/backhaul/server.key -out /root/backhaul/server.crt
# Install the unit from §7.3 as backhaul-iran.service, then:
systemctl daemon-reload && systemctl enable --now backhaul-iran
ss -ltnp | grep -E ':3080|:443'          # tunnel and user listeners
```

**Foreign (client):**

```bash
cat > /root/backhaul/kharej.toml <<EOF
[client]
remote_addr = "IRAN_IP:3080"
transport = "tcpmux"
token = "PASTE_TOKEN"
connection_pool = 8
nodelay = true
mux_version = 1
log_level = "info"
EOF
chmod 600 /root/backhaul/kharej.toml
# Unit as backhaul-kharej.service with ExecStart=/root/backhaul/backhaul -c /root/backhaul/kharej.toml
systemctl daemon-reload && systemctl enable --now backhaul-kharej
journalctl -u backhaul-kharej -f      # expect "control channel established successfully" and the RTT line
```

**Check end to end:** run a service on the foreign box at `127.0.0.1:443` (or map to another target). From outside,
connect to `IRAN_IP:443`. On the Iran side, `journalctl -u backhaul-iran` should show `control channel successfully
established.` and the `listener started successfully …` lines.

Troubleshooting checklist:
* `invalid transport type`: unsupported transport string (e.g. `utcp` in this version).
* `failed to listen on :443`: the port is already in use (`ss -ltnp`), or the mapping is malformed (fatal).
* `failed to resolve remote port`: an IPv6 literal target in `ports`. Use a hostname.
* `channel … is full`: raise `channel_size` or `connection_pool`.
* The client keeps reconnecting: token, transport or mux_version mismatch, or a firewall on `bind_addr` (UDP too for `udp`).
