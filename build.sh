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
elif [ "$(uname -m)" = aarch64 ] && command -v gcc >/dev/null 2>&1; then CC_ARM=gcc; fi
if [ -n "$CC_ARM" ]; then
  $CC_ARM -O2 -w -pthread -static -o assets/golden-gre-relay-arm64 \
    third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c
else
  echo "   no arm64 C compiler — Golden-GRE will be unavailable on arm64 servers (apt install gcc-aarch64-linux-gnu)"
  : > assets/golden-gre-relay-arm64
fi

for arch in $ARCHES; do
  echo "==> building tunnel-panel for $arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "dist/tunnel-panel-$arch" .
done
echo "==> done:"
ls -la dist/
