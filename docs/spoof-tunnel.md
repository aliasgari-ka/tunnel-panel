# Spoof Tunnel (ParsaKSH/spoof-tunnel)

Knowledge-base entry for integrating Spoof Tunnel as one method in a Go tunnel panel
that deploys configs + systemd units to an Iran server and a foreign server over SSH.

Source analyzed: repo `ParsaKSH/spoof-tunnel`, core version **`3.1.0`**
(`var Version = "3.1.0"` in `cmd/spoof/main.go`). Static analysis only; nothing built/run.

---

## 1. Purpose & Architecture

Spoof Tunnel is an **L3/L4 server-to-server tunnel** built to bypass a whitelist-based
Layer-3 firewall (the Iran blackout scenario where only whitelisted srcIP/dstIP pairs pass).
It works by **mutual bidirectional source-IP spoofing**: each endpoint forges the
`Source IP` field in the IP header of the packets it sends, pretending to be a
whitelisted address, while the peer is pre-configured to expect that forged address.

### What "spoof" means
Pure **source IP spoofing** at the IP header. There is no NAT, no routing trick in the
core itself — it crafts raw packets whose source address is a value you choose
(`spoof_ip`). Because a spoofed packet's reply would normally be routed to the forged
address, the design is *mutual*: both sides spoof, and both sides know each other's REAL
IP so they can keep aiming packets at the real peer while the source field stays forged.

### Roles & data flow (connectionless — nobody "dials")
There is **no handshake and no TCP connection**. Both sides statelessly blast crafted
packets at the other side's REAL IP. Two roles:

- **`local`** = CLIENT. Runs on the **Iran** server. Listens on a local **UDP** socket
  (default `127.0.0.1:5000`) for your application traffic.
- **`remote`** = SERVER. Runs on the **foreign** server. Forwards the tunneled payload to
  a configurable UDP endpoint (`forward`, default `127.0.0.1:51820` — i.e. a local
  WireGuard).

Uplink (app → Iran `local` → foreign `remote` → `forward`):
```
app --UDP--> local(listen) --[spoofed src=spoof_ip, dst=remote:remote_port, send_transport]--> remote
remote --[raw recv on listen_port, recv_transport]--> UDP forward endpoint
```
Downlink (reverse):
```
forward-reply --UDP--> remote --[spoofed src=spoof_ip, dst=client_ip:client_port, send_transport]--> local
local --[raw recv on recv_port, recv_transport]--> back to last app UDP addr
```

The core is a **plain UDP pipe** (v2 rewrite). All the v1.0.3 features — ChaCha20 crypto,
SOCKS5, Reed-Solomon FEC, TCP-like reliability/ACK, session mux — were **removed**. The
README's v1 config tables and crypto/reliability sections are DEPRECATED and do not apply
to v3.x. Encryption is expected to come from WireGuard run *inside* the pipe.

High-load packet building / IP-header manipulation is implemented in **Rust**
(`rust/spoof-transport`, linked into the Go binary via CGo/FFI). XDP/eBPF
(`rust/xdp-loader`, `rust/xdp-ebpf`) is an optional kernel-bypass receive accelerator.

### Transports (chosen independently per direction)
`internal/transport/factory.go`:
| name     | wire | notes |
|----------|------|-------|
| `tcp`    | bare TCP packets (no real handshake), IP proto 6 | last protocol censors block |
| `udp`    | UDP datagrams, proto 17 | DNS-like |
| `icmp`   | ICMP Echo Request type 8, proto 1 | looks like ping |
| `icmpv6` | ICMPv6 type 128, **IP protocol 58 carried inside an IPv4 packet** | proto-58-over-IPv4 |

Each side has a `send_transport` and a `recv_transport`. They can be asymmetric (e.g.
client sends TCP, server replies UDP) but **must be paired across the two hosts**:
`local.send_transport == remote.recv_transport` and
`local.recv_transport == remote.send_transport`.

---

## 2. CONFIG FORMAT (the part you generate programmatically)

The core uses a **single flat JSON schema** for both sides — `internal/config/config.go`
`Config` struct. There is NO separate nested "server-config"/"client-config" schema; the
two example files are just the same struct with different `mode`. Every field:

| JSON key          | Go type | used by     | meaning |
|-------------------|---------|-------------|---------|
| `mode`            | string  | both        | `"local"` (client) or `"remote"` (server). Required. |
| `listen`          | string  | local       | UDP `host:port` the client listens on for your app traffic. |
| `remote`          | string  | local       | REAL IP of the foreign server. |
| `remote_port`     | int     | local       | Dest port placed in uplink packets (must equal remote `listen_port`). |
| `recv_port`       | int     | local       | Dest port the server aims downlink packets at; client filters on it. |
| `listen_port`     | int     | remote      | Port the server filters inbound client packets on (must equal local `remote_port`). |
| `forward`         | string  | remote      | UDP `host:port` the server forwards decapsulated payload to (e.g. WireGuard). |
| `client_ip`       | string  | remote      | REAL IP of the Iran/client server. |
| `client_port`     | int     | remote      | Dest port for downlink packets (must equal local `recv_port`). |
| `spoof_ip`        | string  | both        | Single forged source IP placed in outgoing packets. |
| `spoof_ip_file`   | string  | both        | Path to a file of forged source IPs, one per line (`#` comments ok); used round-robin. Use INSTEAD of `spoof_ip`. **IPv4 only** — IPv6 lines are rejected. |
| `spoof_port`      | int     | both        | Source port of outgoing TCP/UDP packets; for ICMP/ICMPv6 it is reused as the ICMP **identifier**. NOT used for filtering. |
| `peer_spoof_ip`   | string  | both        | Expected forged source IP of INBOUND packets (receive filter). Optional — if empty, accept any source. |
| `send_transport`  | string  | both        | `tcp`/`udp`/`icmp`/`icmpv6`. |
| `recv_transport`  | string  | both        | `tcp`/`udp`/`icmp`/`icmpv6`. |
| `xdp_interface`   | string  | both (`run`)| NIC name to attach XDP receive accel (e.g. `eth0`). Empty = raw-socket receive. **Only read from JSON in `run` mode**, not in `local`/`remote` flag mode. |

JSON tags (exact, from `config.go`): `mode, listen, remote, remote_port, recv_port,
spoof_ip, spoof_port, peer_spoof_ip, listen_port, forward, client_ip, client_port,
spoof_ip_file, send_transport, recv_transport, xdp_interface`. All except `mode` are
`,omitempty`.

### Defaults (from `MergeLocal`/`MergeRemote` and `runLocal`/`runRemote`)
Important: defaults differ by side, and **send/recv transports default asymmetrically**.

Local (client): `listen=127.0.0.1:5000`, `remote_port=8090`, `recv_port=5001`,
`spoof_port=443`, `send_transport=tcp`, `recv_transport=udp`.

Remote (server): `listen_port=8090`, `forward=127.0.0.1:51820`, `client_port=5001`,
`spoof_port=8090`, `send_transport=udp`, `recv_transport=tcp`.

Hardcoded (not configurable via JSON): sender **MTU = 1400**
(`senderCfg.MTU = 1400` in `relay/local.go` & `relay/remote.go`); receive `BufferSize =
4 MiB`; stats log every 30s.

### Verbatim example files
`client-config.json.example` (note: the `(or ...)` text is an inline annotation — NOT
valid JSON; strip it when generating):
```json
{
    "mode": "local",
    "listen": "127.0.0.1:533",
    "remote": "[IP_ADDRESS]",
    "remote_port": 8090,
    "recv_port": 5001,
    "spoof_ip": "[IP_ADDRESS]", (or "spoof_ip_file": "/path/to/ips.txt")
    "spoof_port": 443,
    "peer_spoof_ip": "[IP_ADDRESS]"
}
```
`server-config.json.example`:
```json
{
    "mode": "remote",
    "listen_port": 8090,
    "forward": "[IP_ADDRESS]",
    "client_ip": "[IP_ADDRESS]",
    "client_port": 5001,
    "spoof_ip": "[IP_ADDRESS]", (or "spoof_ip_file": "/path/to/ips.txt")
    "spoof_port": 8090,
    "peer_spoof_ip": "[IP_ADDRESS]"
}
```
The examples omit `send_transport`/`recv_transport` — they then fall to the asymmetric
defaults above. For clarity when generating, write them explicitly.

### Port-matching rules (critical, derived from code)
Receivers filter on **destination port = `ListenPort`**; `spoof_port` is only the *source*
port and is cosmetic for filtering. So the pairs that MUST align:
- `local.remote_port` == `remote.listen_port`  (uplink dst)
- `remote.client_port` == `local.recv_port`     (downlink dst)

The panel generates the same flat JSON (`panel/.../manager/tunnel.go generateConfig`),
confirming this is the canonical format. When a spoof IP list is used it writes the IPs to
a sidecar file and sets `spoof_ip_file` to that path.

---

## 3. Binary / CLI

- Binary name: **`spoof`** (built from `./cmd/spoof/`). Cobra-based.
- Subcommands: `local`, `remote`, `run`, `tester`. Also `--version`.
- **Mode selection:**
  - `spoof run -c config.json` → mode taken from the JSON `mode` field (`local`/`remote`).
    This is the mode the panel uses and the one to use for config-driven deploys.
  - `spoof local ...` / `spoof remote ...` → mode fixed by the subcommand; accepts flags,
    optionally `-c file` (flags override file, file overrides default:
    `firstStr(flag, file, default)`).
- Config path flag: **`-c` / `--config`** (default `config.json` for `run`; empty for
  `local`/`remote`).
- **Must run as root** (`requireRoot()` → `CAP_NET_RAW` for raw sockets); exits otherwise.
- Key `local` flags: `-l/--listen`, `-r/--remote`, `-p/--remote-port`, `--recv-port`,
  `-s/--spoof-ip`, `--spoof-port`, `--peer-spoof-ip`, `--spoof-ip-file`,
  `--send-transport`, `--recv-transport`, `--xdp-interface`, `-c/--config`.
- Key `remote` flags: `-l/--listen-port`, `-f/--forward`, `--client-ip`, `--client-port`,
  `-s/--spoof-ip`, `--spoof-port`, `--peer-spoof-ip`, `--spoof-ip-file`,
  `--send-transport`, `--recv-transport`, `--xdp-interface`, `-c/--config`.
- `tester` flags: `--mode sender|receiver`, `--protocol tcp|icmp`, `--src-list FILE`,
  `--dst-ip`, `--dst-port` (default 80), `--timeout` (s, default 30),
  `--packet-count` (default 10), `--max-loss` (%, default 20), `--concurrency` (100).

The old README `./spoof keygen` and `-c server-config.json` top-level form are v1-only and
no longer exist in v3.

---

## 4. Network interface / TUN / MTU / port forwarding

**There is NO TUN/TAP device and NO interface creation.** Grep confirms no `/dev/net/tun`,
no `iptables`, no `ip route`, no WireGuard automation anywhere in the Go/Rust/shell code.
The core is purely:
- a normal UDP socket (`net.ListenUDP("udp4", ...)`) for the app side / forward side, and
- a Linux **raw socket** (Rust) for the spoofed wire side:
  send socket = `AF_INET, SOCK_RAW, IPPROTO_RAW` with `IP_HDRINCL` (builds the entire IPv4
  header by hand, software checksums); recv socket = `AF_INET, SOCK_RAW, proto`
  (`IPPROTO_TCP/UDP/ICMP`) with a 1s `SO_RCVTIMEO`, filtered in userspace by peer IP + port.

MTU: sender MTU is hardcoded to **1400**; large payloads are IP-fragmented. The README
recommends running WireGuard inside with **MTU 1280**.

"Port forwarding" = just the `forward` UDP destination the server writes payloads to; you
wire up the actual service (e.g. WireGuard listening on `127.0.0.1:51820`) yourself.

---

## 5. XDP / eBPF requirements

- **XDP is OPTIONAL and receive-path only.** It is opt-in via `xdp_interface`
  (JSON, `run` mode) / `--xdp-interface`. Empty = plain raw-socket receiver (the default
  and the safe choice).
- If XDP is requested but attach fails, the factory **logs and falls back to the raw
  socket receiver** (`NewReceiver` in `factory.go`). So nothing *requires* XDP.
- XDP only supports `tcp`/`udp`/`icmp` (proto 6/17/1). `icmpv6` maps to proto 0 =
  unsupported → always uses raw socket.
- Requirements (from `xdp-loader/src/lib.rs` and error strings): **root** and **kernel
  ≥ 5.8**. The eBPF object is embedded in the binary at build time (`include_bytes!` of
  `xdp-ebpf/target/bpfel-unknown-none/release/xdp-ebpf`). Uses the `aya` crate + a BPF
  ring buffer (`PAYLOADS`) and a `CONFIG` hash map.
- Attach order: tries **`XdpFlags::SKB_MODE` (generic XDP) first**, then native driver
  mode. Generic/SKB mode works on essentially any NIC, so attach generally succeeds even
  on virtual NICs.
- **VPS / virtio caveat:** native (driver/offload) XDP is usually NOT supported on
  `virtio-net` and many cloud NICs; only the SKB generic path works there (slower, no real
  kernel-bypass benefit). If even SKB mode fails (old kernel, restricted container,
  missing BPF), it falls back to the raw socket and keeps working. **Recommendation for
  your VPS deploys: leave `xdp_interface` empty** — raw-socket mode is always functional
  and portable; only set it on a dedicated box with a known XDP-capable NIC and kernel ≥5.8.

---

## 6. Install / build / release

### Build (from source)
`Makefile`:
- `make core` → builds Rust (`cargo build --release` in `rust/`, which pulls in
  `xdp-loader` via `extern crate xdp_loader`) then `CGO_ENABLED=1 go build -o spoof
  ./cmd/spoof/`. Needs both Go and Rust toolchains (and nightly + `bpf-linker` for the
  eBPF object: `make xdp-ebpf`).
- `make all` → core + panel (panel needs Node/npm; frontend embedded into the Go panel
  binary).

### Release workflow (`.github/workflows/release.yml`)
Triggered on tags `v*` (excludes `panel-v*`). Linux only, `CGO_ENABLED=1`. Jobs:
1. `build-ebpf` — nightly Rust, target `bpfel-unknown-none`, uploads `xdp-ebpf` artifact.
2. `test-rust`.
3. `build-tunnel` — matrix amd64 (`x86_64-unknown-linux-gnu`, cc gcc) + arm64
   (`aarch64-unknown-linux-gnu`, cc `aarch64-linux-gnu-gcc`). Downloads the eBPF object
   into the expected path, builds the Rust static lib, then
   `go build -ldflags="-s -w" -o spoof-linux-<arch>`.
4. `build-frontend` + `build-panel` (pure Go, `CGO_ENABLED=0`).
5. `release` — generates `checksums.txt` and publishes.

### Release asset names (exact)
- Tunnel core: **`spoof-linux-amd64`**, **`spoof-linux-arm64`**
- Panel: **`spoof-panel-linux-amd64`**, **`spoof-panel-linux-arm64`**
- Plus **`checksums.txt`** (`sha256sum spoof-*`).

No Windows/macOS/386 builds; Linux amd64 + arm64 only.

### Install script & systemd (`panel/install.sh`)
- Detects arch (`x86_64`→amd64, `aarch64`→arm64), downloads latest release.
- Installs **panel** → `/usr/local/bin/spoof-panel`; **spoof core** → `/etc/spoof-panel/spoof`.
- Data dir **`/etc/spoof-panel`** (override with env `SPOOF_DATA_DIR`); SQLite DB at
  `/etc/spoof-panel/panel.db`.
- Creates a systemd unit **only for the panel** (`spoof-panel.service`):
  ```ini
  [Service]
  Type=simple
  ExecStart=/usr/local/bin/spoof-panel -port <PORT>
  Environment=SPOOF_DATA_DIR=/etc/spoof-panel
  Restart=on-failure
  LimitNOFILE=65535
  ```
- **Individual tunnels are NOT systemd units.** The panel runs each tunnel as a child
  process (`exec.Command(binary, "run", "--config", configPath)`), writing
  `tunnel-config-<id>.json` (mode 0600) and `spoof-ips-<id>.txt` into the data dir.
  **For your own SSH+systemd integration you supply your own unit**, e.g.
  `ExecStart=/usr/local/bin/spoof run -c /etc/spoof/<name>.json` with `User=root` /
  `AmbientCapabilities=CAP_NET_RAW`.

---

## 7. IPv4 vs IPv6

- **Wire/transport is effectively IPv4-only.** All raw sockets are `AF_INET`; all FFI
  destination addresses are 4-byte (`[u8;4]`); Go resolves `udp4`; `spoof_ip_file`
  explicitly rejects IPv6 lines (`"IPv6 not supported at ..."`).
- `icmpv6` is NOT IPv6 transport — it is **IP protocol number 58 encapsulated in an IPv4
  packet** (to exploit middleboxes that under-filter the ICMPv6 proto number).
- The README v1 server table's `source_ipv6` / `client_real_ipv6` fields are from the
  deprecated v1 schema and are **not present** in the v3 `Config` struct.
- To carry IPv6 *application* traffic, run WireGuard with IPv6 addresses inside the UDP
  pipe (README points at the TAQ-BOSTAN wireguard.sh script).

---

## 8. Security notes & failure modes

- **No encryption in the core (v2+).** The pipe is plaintext; the only inbound check is the
  optional `peer_spoof_ip` source filter + dst-port match. Anyone able to spoof that source
  IP toward the listen port can inject into the pipe. **Run WireGuard inside for
  confidentiality/authentication.**
- **Both hosts must be allowed to emit spoofed-source packets.** Many providers/ISPs apply
  BCP38 egress filtering and will silently drop spoofed packets — then the tunnel is dead.
  Verify FIRST with the built-in `spoof tester` (sender/receiver on both directions) or the
  README's quick `iptables SNAT + ping + tcpdump` test. The receiver-side valid IP list of
  one direction becomes the `spoof_ip`/`spoof_ip_file` of the OTHER side.
- ICMP/ICMPv6 receive sets `sysctl net.ipv4.icmp_echo_ignore_all=1` on start (so the kernel
  does not auto-reply to the echo requests it is sniffing) and restores it on clean
  shutdown — a hard kill leaves ICMP echo replies disabled host-wide. (`relay/utils.go`.)
- Stateless/connectionless: packet loss shows up directly as app loss (no core
  retransmit since v2). Use a reliable protocol (WireGuard/TCP) on top.
- Spoof-IP round-robin (`spoof_ip_file`) spreads traffic across whitelisted IPs to dodge
  per-IP bandwidth caps the censor's firewall imposes.
- Requires root; raw-socket creation failures surface as "need root/CAP_NET_RAW".

---

## 9. Manual Iran <-> Foreign setup recipe

Assume: Iran server real IP `IRAN_REAL`, foreign server real IP `FOREIGN_REAL`. Pick a
whitelisted/valid spoof IP for each direction (validate with `spoof tester` first):
`SPOOF_A` = source the Iran client forges, `SPOOF_B` = source the foreign server forges.
Transport pairing here: client sends TCP, server sends UDP.

### Iran server (`local` / client) — `/etc/spoof/client.json`
```json
{
  "mode": "local",
  "listen": "127.0.0.1:5000",
  "remote": "FOREIGN_REAL",
  "remote_port": 8090,
  "recv_port": 5001,
  "spoof_ip": "SPOOF_A",
  "spoof_port": 443,
  "peer_spoof_ip": "SPOOF_B",
  "send_transport": "tcp",
  "recv_transport": "udp"
}
```

### Foreign server (`remote` / server) — `/etc/spoof/server.json`
```json
{
  "mode": "remote",
  "listen_port": 8090,
  "forward": "127.0.0.1:51820",
  "client_ip": "IRAN_REAL",
  "client_port": 5001,
  "spoof_ip": "SPOOF_B",
  "spoof_port": 8090,
  "peer_spoof_ip": "SPOOF_A",
  "send_transport": "udp",
  "recv_transport": "tcp"
}
```
Port alignment check: `local.remote_port(8090)==remote.listen_port(8090)` and
`remote.client_port(5001)==local.recv_port(5001)`. Transport pairing:
`local.send(tcp)==remote.recv(tcp)`, `local.recv(udp)==remote.send(udp)`. Good.

### Validate spoofing works (do this before trusting the tunnel)
On foreign (receiver), then Iran (sender) — repeat with roles reversed:
```bash
# foreign:
spoof tester --mode receiver --protocol icmp --src-list candidates.txt --timeout 30
# iran:
spoof tester --mode sender --protocol icmp --src-list candidates.txt --dst-ip FOREIGN_REAL --packet-count 10 --max-loss 20
```
The receiver prints the IPs whose spoofed packets arrived; those become the OTHER side's
spoof list.

### Run (both as root)
```bash
spoof run -c /etc/spoof/server.json    # foreign, start first
spoof run -c /etc/spoof/client.json    # iran
```

### Systemd unit (your own, per host)
```ini
[Unit]
Description=Spoof Tunnel (client)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/spoof run -c /etc/spoof/client.json
Restart=on-failure
RestartSec=3
User=root
AmbientCapabilities=CAP_NET_RAW
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### WireGuard inside the pipe (recommended — provides the actual encryption/reliability)
- Foreign: WireGuard listens on `127.0.0.1:51820` (= `forward`).
- Iran: set the WireGuard peer `Endpoint = 127.0.0.1:5000` (= client `listen`), `MTU = 1280`.
- Your app traffic then rides WireGuard, which rides the spoof UDP pipe.

---

## 10. Quick integration notes for a Go deploy panel

- Generate the flat JSON above per host; `mode` decides everything. Write to a 0600 file,
  push via SSH, run `spoof run -c <path>` under a root systemd unit with `CAP_NET_RAW`.
- Use `spoof_ip_file` (one IPv4 per line) for round-robin; ship that file alongside.
- Keep `send_transport`/`recv_transport` explicit and mirrored across the two hosts.
- Default `xdp_interface` empty on VPSes; only set it where kernel ≥5.8 + XDP-capable NIC.
- Expect plaintext — layer WireGuard yourself. Always gate deploy on a `spoof tester` pass.
- Asset download: `spoof-linux-amd64` / `spoof-linux-arm64` from the GitHub release
  matching the tag; verify against `checksums.txt`.
