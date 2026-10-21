#!/usr/bin/env bash
# Push this repo to your GitHub. Run it after creating an EMPTY repo on github.com
# (no README, no .gitignore, no license) named tunnel-panel.
#
#   bash push.sh                       # -> github.com/aliasgari-ka/tunnel-panel
#   bash push.sh <owner>/<repo>        # -> a different slug
set -euo pipefail
SLUG="${1:-aliasgari-ka/tunnel-panel}"
cd "$(dirname "$0")"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$SLUG.git"
git branch -M main
git push -u origin main
echo "Pushed to https://github.com/$SLUG"
echo "Install on a foreign server with:"
echo "  bash <(curl -fsSL https://raw.githubusercontent.com/$SLUG/main/install.sh)"
