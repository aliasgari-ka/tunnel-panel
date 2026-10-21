# Easy-Mesh — Analysis

Source: https://github.com/Musixal/Easy-Mesh
Local clone: /tmp/claude-0/-home-user/19ef19a0-d8ad-5ba8-adb4-22953c965705/scratchpad/easymesh
Analysed: 2026-10-21 (do-not-execute; static read only)

## 1. What it actually is

Easy-Mesh is **not** its own networking engine. It is a ~780-line interactive Bash
menu (`easymesh.sh` / `easymesh_v2.sh`, identical except core version 1.2.0 vs 2.0.3)
that wraps **EasyTier** (https://github.com/EasyTier/EasyTier), a Rust decentralized
**P2P mesh VPN** (comparable to Tailscale/ZeroTier/n2n). The repo ships prebuilt
`easytier-core` + `easytier-cli` binaries under `core/v1.2.0/` and `core/v2.0.3/` for
x86_64, armv7 (soft-float) and armv7hf.

Architecture per node:
- `easytier-core` builds an **overlay L3 network** over a TUN interface. Each node gets a
  stable virtual IP (the script suggests `10.144.144.1`, `.2`, ...).
- Transport runs over **tcp / udp / ws / wss** (default port **2090**). Nodes authenticate
  to a network via a shared `--network-secret`.
- It is a **true mesh**: nodes relay/forward for each other and do NAT hole-punching.
- **No SSH, no WireGuard, no iptables, no socat/gost.** The only extra primitives used by
  the wrapper are `ping`/`bc` (watchdog) and `systemd`/`cron`.

So "what does it build" = a self-healing encrypted mesh overlay; you then run your real
traffic (SSH, proxies, tunnels) *on top* of the overlay IPs.

## 2. How nodes reach each other (the important part)

EasyTier's connection model is asymmetric and this is what enables NAT/blocked-inbound
traversal:

- Every node has `--listeners` (where it accepts connections) and optionally `--peers`
  (addresses it **dials out to**).
- A node with a public IP can just listen. A node behind NAT / with no open inbound port
  sets `--peers` to the public node and **dials outbound** to it. Once that outbound
  session is up, the mesh is bidirectional over it.

The wrapper exposes this as **"reverse mode"**. From the connect prompt (line 145):

```
Leave the peer addresses blank to enable reverse mode.
Ws and wss modes are not recommended for iran's network environment.
Try disable multi-thread mode if your mesh network is unstable.
UDP mode is more stable rather than tcp mode.
```

- **Public/relay node (reverse mode):** leave "Peer addresses" blank -> no `--peers`,
  only `--listeners`. It waits for inbound.
- **Restricted node:** enter the public node's address -> it dials outbound.

Beyond that, EasyTier adds:
- **NAT traversal / hole punching** so two restricted nodes can sometimes reach each other
  directly (P2P).
- **Relay / peer-center:** if a direct path is impossible, traffic is forwarded through an
  intermediate peer. The wrapper surfaces `easytier-cli peer-center` and
  `easytier-cli route`.

## 3. SSH-specific mechanics

**None.** Easy-Mesh contains no SSH, no jump hosts, no reverse-SSH, no autossh, no key
distribution, no ProxyJump/ProxyCommand. The relevance is indirect: once the mesh is up,
every node is reachable at a stable overlay IP (10.144.144.x) *regardless of NAT or blocked
inbound ports*, so you can SSH to that overlay IP from any meshed node.

## 4. Install / bootstrap command

Users run (as root, Debian/Ubuntu):

```
bash <(curl -Ls --ipv4 https://github.com/Musixal/easy-mesh/raw/main/easymesh_v2.sh)
```

What the script does on each node:
1. Requires root (`$EUID -ne 0` -> exit).
2. `install_easytier()`: detects arch via `uname -m` / `ldd /bin/ls | grep armhf`, then
   `curl -Ls` downloads `easytier-cli` and `easytier-core` from the repo's `core/<ver>/...`
   dir into `/root/easytier/`, `chmod +x` both.
3. Loops an interactive menu.

## 5. Config format, ports, systemd, persistence

- **No config file.** All settings are baked as CLI flags into the systemd unit's
  `ExecStart` line. Written by `connect_network_pool()` to
  `/etc/systemd/system/easymesh.service`:

```
[Unit]
Description=EasyMesh Network Service
After=network.target

[Service]
ExecStart=/root/easytier/easytier-core -i $IP_ADDRESS $PEER_ADDRESS --hostname $HOSTNAME --network-secret $NETWORK_SECRET --default-protocol $DEFAULT_PROTOCOL $LISTENERS $MULTI_THREAD $ENCRYPTION_OPTION $IPV6_MODE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

  where, e.g.:
```
PEER_ADDRESS="--peers tcp://1.2.3.4:2090"           # omitted entirely in reverse mode
LISTENERS="--listeners tcp://[::]:2090 tcp://0.0.0.0:2090"
```
- **Port:** default **2090** (tcp/udp/ws/wss), user-overridable.
- **Secret:** `openssl rand -hex 6` suggested; stored in the unit, read back with
  `grep -oP '(?<=--network-secret )[^ ]+'`.
- Options: `--disable-encryption`, `--multi-thread`, `--disable-ipv6`.
- **Persistence:** `systemctl enable --now easymesh.service` + `Restart=on-failure`.
- **Watchdog** (`/etc/monitor.sh` + `easymesh-watchdog.service`): pings the overlay IP every
  N seconds (`ping -c 3 -W 2`), computes avg latency with `bc`, and
  `systemctl restart easymesh.service` if ping fails or latency > threshold. Recommended to
  run only on the foreign (Kharej) node.
- **Cron** (`add_cron_job`): optional periodic hard restart via `/root/easytier/reset.sh`
  (`pgrep easytier` -> `kill -9` -> `systemctl restart`).

## 6. "Try another node if direct fails" (multi-path)

Yes — inherent to EasyTier being a mesh. It automatically forwards through intermediate
peers when no direct path exists, and `peer-center` designates a coordination/relay node.
The Bash wrapper adds no routing logic of its own; it just exposes `peer`, `route`,
`peer-center` views (`watch -n1 easytier-cli <cmd>`).

## 7. Menu options & primitives

```
[1] Connect to the Mesh Network   -> writes systemd unit, starts easytier-core
[2] Display Peers                 -> watch easytier-cli peer
[3] Display Routes                -> watch easytier-cli route
[4] Peer-Center                   -> watch easytier-cli peer-center
[5] Display Secret Key            -> grep secret from unit
[6] View Service Status           -> systemctl status
[7] Set Watchdog [Auto-Restarter] -> ping-based monitor.sh service
[8] Cron-job setting              -> periodic restart
[9] Restart Service / [10] Remove Service / [11] Remove Core
```
Primitives: `easytier-core` (TUN overlay), `easytier-cli`, `systemd`, `cron`, `curl`,
`ping`, `bc`, `openssl`. No `ip`/`iptables`/`wireguard`/`socat`/`gost`.

## Takeaways for an SSH-based Go relay panel

- The reusable idea is **reverse mode = restricted box dials out to the public box over a
  long-lived tcp/udp/ws/wss session**; the public panel never needs inbound reachability to
  the Iran box. Reimplement as an outbound agent, not an SSH listener on the Iran side.
- **ws/wss transports** are offered specifically because they survive CDN/HTTP-proxy
  environments and DPI better than raw tcp — worth copying for the dial-back agent.
- Once an overlay exists, direct SSH to a **stable virtual IP** replaces needing a public
  port. You can mimic this with your own agent assigning each Iran box a routable address on
  the panel side.
- Mesh relaying ("go through another connected node") is automatic in EasyTier; the SSH
  analog is **ProxyJump through an already-connected server**.
