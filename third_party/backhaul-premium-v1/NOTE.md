# Backhaul Premium v1.0.2 (arm64)

The vendor's `backhaul_premium_linux_arm64.tar.gz` (built 2025-03-04), unchanged, with the
license it ships with (WTFPL, see LICENSE). It is the only arm64 build there is and it is
**v1.0.2**: old `[server]`/`[client]` config, transports tcp/tcpmux/ws/wss/wsmux/wssmux/udp,
no ipx/anytls. It does not interoperate with the v2 core (tested: the v2 server drops a v1
client's control channel), so the panel offers it as its own method,
"Backhaul Premium v1 (legacy)", used on both ends of a tunnel: natively on arm64, and under
qemu-aarch64 on amd64 hosts (the binary is static).

sha256 (binary inside): a23ccdc3cf1d605951be70bab95be4782b6125444389e5e37b8f3f7d5496027f
