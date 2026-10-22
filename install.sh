#!/usr/bin/env bash
# Tunnel Panel installer — run as root on the FOREIGN (relay) server.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/aliasgari-ka/tunnel-panel/main/install.sh)
#   bash install.sh [--port 8088] [--agent-port 7020] [--ref main]
#
set -euo pipefail

REPO_SLUG="${TP_REPO:-aliasgari-ka/tunnel-panel}"
PORT=8088
AGENT_PORT=7020
REF=main
TLS=""
IPSSL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --agent-port) AGENT_PORT="$2"; shift 2;;
    --ref) REF="$2"; shift 2;;
    --domain) TLS="$2"; shift 2;;        # Let's Encrypt cert for this domain (needs 80+443)
    --ip-ssl) IPSSL=1; shift;;           # trusted cert for this server's IP via sslip.io
    --self-signed|--https) TLS="self"; shift;;
    --http) TLS=""; shift;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

# --ip-ssl: build a real Let's Encrypt cert for <ip-with-dashes>.sslip.io, which
# resolves to this server's public IPv4. No domain needed, no browser warning.
if [ "$IPSSL" = 1 ]; then
  PUBIP=$(curl -fsS4 --max-time 6 ifconfig.me 2>/dev/null || curl -fsS4 --max-time 6 api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
  case "$PUBIP" in
    *.*.*.*) TLS="$(echo "$PUBIP" | tr '.' '-').sslip.io";;
    *) echo "could not detect a public IPv4 for --ip-ssl"; exit 1;;
  esac
  echo "==> --ip-ssl: using domain $TLS (needs ports 80 and 443 open)"
fi
# With a real domain, the panel serves HTTPS on 443 (+80 for the ACME challenge).
if [ -n "$TLS" ] && [ "$TLS" != "self" ]; then PORT=443; fi

ARCH=amd64; case "$(uname -m)" in aarch64|arm64) ARCH=arm64;; x86_64) ARCH=amd64;; *) echo "unsupported arch $(uname -m)"; exit 1;; esac
DEST=/usr/local/bin/tunnel-panel
DATA=/etc/tunnel-panel
SRC=/opt/tunnel-panel-src
mkdir -p "$DATA"

have() { command -v "$1" >/dev/null 2>&1; }

# 1. runtime deps for the tunnel methods
if have apt-get; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  apt-get install -y -qq git curl iproute2 iptables ethtool openssl ca-certificates gcc >/dev/null 2>&1 || true
fi

# 2. get the binary: next to this script → GitHub release → build from source
SELF_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /tmp)"
GOV=1.24.7   # must satisfy go.mod (go 1.24)

fetch_release() {
  local base="https://github.com/$REPO_SLUG/releases/latest/download"
  local tmp; tmp=$(mktemp -d)
  echo "==> downloading prebuilt release ($ARCH)"
  curl -fsSL --retry 3 --max-time 300 -o "$tmp/tunnel-panel" "$base/tunnel-panel-$ARCH" || { rm -rf "$tmp"; return 1; }
  if curl -fsSL --retry 2 --max-time 30 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"; then
    want=$(awk -v f="tunnel-panel-$ARCH" '$2==f{print $1}' "$tmp/SHA256SUMS")
    got=$(sha256sum "$tmp/tunnel-panel" | awk '{print $1}')
    if [ -n "$want" ] && [ "$want" != "$got" ]; then echo "checksum mismatch — refusing"; rm -rf "$tmp"; return 1; fi
  fi
  install -m0755 "$tmp/tunnel-panel" "$DEST"
  rm -rf "$tmp"
}

go_ok() { have go && go version | grep -qE 'go1\.(2[4-9]|[3-9][0-9])'; }

install_go() {
  echo "==> installing Go $GOV"
  local f="go${GOV}.linux-${ARCH}.tar.gz"
  for m in https://go.dev/dl https://dl.google.com/go https://golang.google.cn/dl \
           https://mirrors.aliyun.com/golang https://mirrors.ustc.edu.cn/golang; do
    echo "   trying $m"
    if curl -fsSL --retry 2 --max-time 600 -o /tmp/go.tgz "$m/$f" && tar -tzf /tmp/go.tgz >/dev/null 2>&1; then
      rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
      export PATH=/usr/local/go/bin:$PATH
      return 0
    fi
  done
  echo "could not download Go from any mirror"; return 1
}

if [ -f "$SELF_DIR/dist/tunnel-panel-$ARCH" ]; then
  install -m0755 "$SELF_DIR/dist/tunnel-panel-$ARCH" "$DEST"
elif [ -f "$SELF_DIR/tunnel-panel-$ARCH" ]; then
  install -m0755 "$SELF_DIR/tunnel-panel-$ARCH" "$DEST"
elif [ "${TP_BUILD:-}" != 1 ] && fetch_release; then
  echo "   installed release binary"
else
  echo "==> building from source ($REPO_SLUG@$REF)"
  rm -rf "$SRC"
  git clone --depth 1 -b "$REF" "https://github.com/$REPO_SLUG" "$SRC"
  [ -x /usr/local/go/bin/go ] && export PATH=/usr/local/go/bin:$PATH
  go_ok || install_go
  # module downloads: fall back to public mirrors if proxy.golang.org is blocked
  export GOTOOLCHAIN=local
  export GOPROXY="${GOPROXY:-https://proxy.golang.org,https://goproxy.cn,https://goproxy.io,direct}"
  export GOSUMDB="${GOSUMDB:-sum.golang.org}"
  ( cd "$SRC" && bash build.sh "$ARCH" ) || { echo "build failed"; exit 1; }
  install -m0755 "$SRC/dist/tunnel-panel-$ARCH" "$DEST"
fi

cat >/etc/systemd/system/tunnel-panel.service <<UNIT
[Unit]
Description=Tunnel Panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$DEST --addr 0.0.0.0:$PORT --agent-addr 0.0.0.0:$AGENT_PORT --data $DATA --tls "$TLS"
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now tunnel-panel

IP=$(curl -fsS4 --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
SCHEME=http; OPENHOST="${IP}:${PORT}"
if [ "$TLS" = "self" ]; then SCHEME=https; fi
if [ -n "$TLS" ] && [ "$TLS" != "self" ]; then SCHEME=https; OPENHOST="$TLS"; fi
cat <<EOF

==============================================================
 Tunnel Panel is running.
   Open:        ${SCHEME}://${OPENHOST}/
   Agent port:  ${AGENT_PORT}  (Iran servers dial back to this)
   On first visit you create the admin account.
 Service:  systemctl status tunnel-panel
 Data:     ${DATA}
==============================================================
Tip: put it behind HTTPS, or bind to localhost and reach it over SSH.
EOF
