#!/usr/bin/env bash
# Build the tunnel-panel binary with its embedded helpers.
# Produces dist/tunnel-panel-<arch> for the arch(es) you pass (default: host arch).
set -euo pipefail
cd "$(dirname "$0")"

ARCHES="${*:-$(go env GOARCH)}"
VERSION="${TP_VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)-$(date -u +%Y%m%d)}"
mkdir -p assets dist

echo "==> building tp-agent for amd64 and arm64"
for a in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -trimpath -ldflags "-s -w" -o "assets/tp-agent-$a" ./cmd/tp-agent
done

echo "==> compiling golden-gre-relay (amd64, arm64)"
if command -v gcc >/dev/null 2>&1; then
  gcc -O2 -w -pthread -static -o assets/golden-gre-relay-amd64 \
    third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c || \
  gcc -O2 -w -pthread -o assets/golden-gre-relay-amd64 \
    third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c
else
  echo "   gcc not found — the Golden-GRE method will be unavailable until you add assets/golden-gre-relay-amd64"
  : > assets/golden-gre-relay-amd64   # keep go:embed happy
fi

# arm64: cross-compile (apt install gcc-aarch64-linux-gnu), or natively on an arm64 host
CC_ARM=""
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then CC_ARM=aarch64-linux-gnu-gcc
elif [ "$(uname -m)" = aarch64 ] && command -v gcc >/dev/null 2>&1; then CC_ARM=gcc
elif command -v zig >/dev/null 2>&1; then CC_ARM="zig cc -target aarch64-linux-musl"; fi
if [ -n "$CC_ARM" ]; then
  echo "   arm64 compiler: $CC_ARM"
  $CC_ARM -O2 -w -pthread -static -o assets/golden-gre-relay-arm64 \
    third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c
  file assets/golden-gre-relay-arm64 2>/dev/null | grep -q aarch64 || { echo "arm64 relay build is not an aarch64 binary"; exit 1; }
else
  echo "   no arm64 C compiler — Golden-GRE will be unavailable on arm64 servers (apt install gcc-aarch64-linux-gnu)"
  : > assets/golden-gre-relay-arm64
fi

echo "==> unpacking Backhaul Premium v1.0.2 (arm64, the vendor's archive)"
tar -xzOf third_party/backhaul-premium-v1/backhaul_premium_linux_arm64.tar.gz backhaul_premium > assets/backhaul_premium_v1-arm64
echo "a23ccdc3cf1d605951be70bab95be4782b6125444389e5e37b8f3f7d5496027f  assets/backhaul_premium_v1-arm64" | sha256sum -c -

for arch in $ARCHES; do
  echo "==> building tunnel-panel for $arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "dist/tunnel-panel-$arch" .
done
echo "==> done:"
ls -la dist/
