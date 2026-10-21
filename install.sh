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
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --agent-port) AGENT_PORT="$2"; shift 2;;
    --ref) REF="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

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

# 2. prefer a binary shipped next to this script (release tarball)
SELF_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /tmp)"
if [ -f "$SELF_DIR/dist/tunnel-panel-$ARCH" ]; then
  install -m0755 "$SELF_DIR/dist/tunnel-panel-$ARCH" "$DEST"
elif [ -f "$SELF_DIR/tunnel-panel-$ARCH" ]; then
  install -m0755 "$SELF_DIR/tunnel-panel-$ARCH" "$DEST"
else
  # 3. build from source
  echo "==> fetching source ($REPO_SLUG@$REF)"
  rm -rf "$SRC"
  git clone --depth 1 -b "$REF" "https://github.com/$REPO_SLUG" "$SRC"
  if ! have go; then
    echo "==> installing Go toolchain"
    GOV=1.23.6
    curl -fsSL "https://go.dev/dl/go${GOV}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
    export PATH=$PATH:/usr/local/go/bin
  fi
  ( cd "$SRC" && bash build.sh "$ARCH" )
  install -m0755 "$SRC/dist/tunnel-panel-$ARCH" "$DEST"
fi

cat >/etc/systemd/system/tunnel-panel.service <<UNIT
[Unit]
Description=Tunnel Panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$DEST --addr 0.0.0.0:$PORT --agent-addr 0.0.0.0:$AGENT_PORT --data $DATA
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now tunnel-panel

IP=$(curl -fsS4 --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
cat <<EOF

==============================================================
 Tunnel Panel is running.
   Open:        http://${IP}:${PORT}/
   Agent port:  ${AGENT_PORT}  (Iran servers dial back to this)
   On first visit you create the admin account.
 Service:  systemctl status tunnel-panel
 Data:     ${DATA}
==============================================================
Tip: put it behind HTTPS, or bind to localhost and reach it over SSH.
EOF
