# Tunnel Panel

**[راهنمای فارسی →](README-fa.md)**

A single-binary web panel + Telegram bot that runs on your **foreign (relay) server** and
links it to one or more **Iran servers**. You create a *tunnel* (a route: Iran server ⇄ a
foreign server, a set of ports), pick a **connection method**, and switch between methods at
any time. The panel writes the config and systemd units on **both** ends for you, forwards the
public ports from Iran to the foreign side, and can reach Iran even when its SSH is blocked.

## Highlights

- **9 connection methods**, switchable per tunnel with one click (see the table below).
- **Reaches Iran four ways, auto-selected:** a dial-back **agent** (Iran runs one command, no
  inbound SSH needed), **direct SSH**, **SSH through another server** (jump host), or an
  **SSH-over-proxy** (SOCKS5/HTTP). *Test paths* shows which ones work.
- **Route benchmark:** measures every method between two servers (latency, jitter, loss,
  throughput) and recommends the best, then applies it in one click.
- **Multi-node:** register several Iran and foreign servers; each tunnel picks its own pair.
- **Port forwarding** from Iran's public ports to the foreign side, with MSS clamping, in
  per-tunnel iptables chains that tear down cleanly.
- **Telegram bot** that does everything the panel does (start/stop/switch/status) over buttons;
  the method picker has an IPv4 / IPv6 switch, so each tunnel's method *and* family can be chosen.
- **Persistent & supervised:** every method is a `systemd` unit, so tunnels survive reboots.
- **SSH bridge:** expose an Iran server's SSH on a panel port so you can log in manually.
- **Traffic shaping:** optional per-tunnel CAKE/HTB/TBF/fq_codel qdisc + jitter + MSS clamp.
- **Country flags:** servers are geolocated by IP and shown with their flag.
- **Automatic failover:** a tunnel that stays down for 5 minutes is moved to a working method
  or the other address family (IPv4 ⇄ IPv6), verified by a real connection through the
  forwarded port to the foreign service; the original path is re-tested hourly (on a spare
  slot, without touching the live tunnel) and restored when it works. Per-tunnel switch.
- **Health & alerts:** live health on every card (red when down); Telegram 🔴/🟢/🔁 messages.
- **Diagnose / Trace / Speed test:** Diagnose checks every hop and names the problem (a server
  that drops ping is not reported as a dead tunnel when TCP gets through); Trace
  watches while you connect a client (e.g. Xray) and shows where the connection stops, with
  the service's own log lines; Speed test measures RTT and ↓/↑ throughput through the tunnel.
- **Live traffic** per tunnel and per server NIC; **benchmark history** of every route tested.
- **Reverse-tunnel preflight:** before starting a reverse method the panel checks that the
  foreign server can actually reach Iran's tunnel port and moves it to a port that gets
  through (443, 8443, 2053, …), or explains why the route needs an L3 method.
- **Install once:** binaries are uploaded only when their sha256 differs; "Install packages"
  pre-installs everything a server needs. IPv4/IPv6 addresses are read from the server.
- **arm64:** Golden-GRE's relay is built for arm64; Backhaul Premium's arm64 core is fetched from
  the vendor, or the amd64 core runs under box64/qemu-user (tcp/tcpmux/wssmux/anytls modes;
  ipx needs box64).

## Methods

| Method | Family | Encryption | Notes |
|---|---|---|---|
| **BackPack reverse** | v4/v6 | stealth (Noise) / TLS / token | 12 transports incl. `stealth`, `quic`, `wssmux` |
| **BackPack L3 (TUN)** | v4/v6 | Noise AEAD | Iran dials out — use when Iran has no open inbound port |
| **Backhaul reverse** | v4/v6 | token / wss | tcp, tcpmux, ws, wss, wsmux, wssmux, udp |
| **FRP reverse** | v4/v6 | token (+TLS) | tcp, websocket, quic, kcp |
| **Backhaul Premium** | v4 | AEAD (ipx) / TLS | `tun` + `ipx` raw carrier (icmp/ipip/udp/tcp/gre/bip), `anytls`. amd64, upload the core |
| **Golden-GRE** | v4 | optional XChaCha20 | GRE-in-FOU disguised as DNS or ICMP; several tunnels can share one server's port 53 |
| **Direct v6 (ip6gre)** | v6 | none | kernel only, lowest overhead; Carrier `udp` = GRE inside UDP where protocol 47 is filtered |
| **Plain GRE** | v4/v6 | none | kernel GRE / ip6gre |
| **IPsec (strongSwan)** | v6/v4 | AES-GCM | IKEv2, route-based XFRM interface |
| **Spoof-Tunnel** | v4 | none (spoofed) | stateless raw pipe via mutual source-IP spoofing; needs non-BCP38 providers; put an encrypted protocol inside |

## Install (on the foreign server, as root)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/aliasgari-ka/tunnel-panel/main/install.sh)
```

It installs dependencies, builds the binary (or uses a release), installs a `systemd` service,
and prints the URL. Open `http://<foreign-ip>:8088/` and create the admin account on first visit.

**Secure it with HTTPS.** `--ip-ssl` gets a real, warning-free Let's Encrypt cert for this
server's IP via sslip.io (no domain needed; ports 80+443 must be open). `--domain example.com`
does the same for your own domain. `--self-signed` serves HTTPS with a self-signed cert. Without
any flag the panel serves plain HTTP.

 Put it behind an HTTPS reverse proxy, or bind it to
localhost (`--addr 127.0.0.1:8088`) and reach it over an SSH tunnel. It stores server
credentials in `/etc/tunnel-panel/state.json` (mode 0600).

## Using it

1. **Settings** — enter this host's public IP and the agent dial-back address. Optionally add a
   Telegram bot token and your admin chat id.
2. **Servers** — add each Iran server (role *iran*) and any extra exit server (role *foreign*).
   Give SSH credentials, or use **Agent install** to run one command on Iran that dials back —
   no inbound SSH needed. **Test paths** shows every working route.
3. **Tunnels** — create a tunnel (Iran server + foreign server + family + ports), pick a method,
   tune it with ⚙, and **Start**. Change method later and **Switch**; the old one is torn down
   on both ends first. **Logs** streams the live apply output from both servers.
4. **Benchmark** — pick a server pair, run it, and apply the recommended method.

When Iran blocks inbound SSH entirely, use **Agent install** (the agent dials out), or **SSH
bridge** / **jump via another server** from the Servers page.

## How Iran is reached (fallback order)

```
agent (dial-back)  →  direct SSH  →  SSH via proxy  →  SSH through another server (jump)
```

The agent is a tiny second binary (`tp-agent`) the panel serves to the Iran box. It opens an
outbound TLS connection (the panel's key is pinned), and the panel runs operations over that
multiplexed link. Nothing listens for inbound connections on Iran.

## Build from source

```bash
bash build.sh amd64 arm64      # needs Go and gcc; writes dist/tunnel-panel-<arch>
```

`build.sh` compiles `tp-agent` (both arches) and the Golden-GRE relay
(`third_party/golden-gre`, Apache-2.0) and embeds them in the panel binary.

## Reset the admin password

On the foreign server, without touching your servers or tunnels:

```bash
tunnel-panel reset-password -user admin -password 'a-new-password'   # set a password
tunnel-panel reset-password                                          # or clear all accounts
systemctl restart tunnel-panel
```

## Notes & limitations

- The **Backhaul Premium** core is closed source and is **not** bundled or downloaded. Upload it
  once in *Settings → Helper binaries*; the panel stores it and pushes it to hosts itself. It is
  amd64 only, and the vendor's own installer (plain HTTP) is avoided.
- **Golden-GRE**'s relay is built for amd64 and arm64; **Premium**'s core is amd64 (arm64 via the
  vendor build or emulation, see above). Every other method is architecture-independent.
- **IPv6:** the panel never turns IPv6 forwarding on (the tunnels carry IPv4 inside). Earlier
  versions did, and with forwarding on Linux ignores router advertisements, so servers that learn
  their IPv6 default route from RA lost IPv6 after a while; every tunnel start now repairs that
  (`accept_ra=2` while forwarding is still on). Server addresses are validated and normalized, and
  kernel tunnels refuse to start with an IPv6 address the server doesn't have.
- **Golden-GRE (DNS)** relays receive on a per-tunnel port; an iptables TPROXY rule per peer hands
  each relay its peer's port-53 packets, so one server can run Golden tunnels to several servers.
  Two Golden tunnels between the *same* two servers need different "DNS port" options.
- The panel runs as root on the foreign server (it manages `ip`, `iptables`, `sysctl`, systemd)
  and uses root on the Iran side. A fresh random token/PSK is generated per tunnel — the public
  default secrets of the upstream tools are never used.
- Technique analyses live in `docs/` (frp, BackPack, Backhaul, Backhaul-Premium, Golden-GRE,
  Easy-Mesh, direct-v6, ipsec-v6).

## License

MIT for this project. `third_party/golden-gre` is Apache-2.0 (upstream LivingG0D/Golden-GRE).
