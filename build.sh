#!/usr/bin/env bash
# Build the tunnel-panel binary with its embedded helpers.
# Produces dist/tunnel-panel-<arch> for the arch(es) you pass (default: host arch).
set -euo pipefail
cd "$(dirname "$0")"

ARCHES="${*:-$(go env GOARCH)}"
mkdir -p assets dist

echo "==> building tp-agent for amd64 and arm64"
for a in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -trimpath -ldflags "-s -w" -o "assets/tp-agent-$a" ./cmd/tp-agent
done

echo "==> compiling golden-gre-relay (amd64)"
if command -v gcc >/dev/null 2>&1; then
  gcc -O2 -w -pthread -static -o assets/golden-gre-relay-amd64 \
    third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c || \
  gcc -O2 -w -pthread -o assets/golden-gre-relay-amd64 \
    third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c
else
  echo "   gcc not found — the Golden-GRE method will be unavailable until you add assets/golden-gre-relay-amd64"
  : > assets/golden-gre-relay-amd64   # keep go:embed happy
fi

for arch in $ARCHES; do
  echo "==> building tunnel-panel for $arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "dist/tunnel-panel-$arch" .
done
echo "==> done:"
ls -la dist/
