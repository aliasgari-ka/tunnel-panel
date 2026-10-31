package main

// aptFix defines tp_apt_fix: before the panel installs a package, a half-finished upgrade
// or "Unmet dependencies" left on the server would fail every apt-get install (seen live on
// netherlands-iran: gcc-12-base upgraded, libgcc-s1/libstdc++6 not, so WireGuard couldn't
// be installed). It finishes pending configuration, and when apt is still broken repairs it
// with `apt-get -f install` — but only after a dry run shows the repair removes nothing; a
// repair that would remove packages is left to the owner, with their names. Existing config
// files are kept (confold). Returns 1 when apt stays broken; callers go on with `|| true`
// and their own install reports what failed.
const aptFix = `tp_apt_fix() {
  command -v apt-get >/dev/null 2>&1 || return 0
  export DEBIAN_FRONTEND=noninteractive
  apt-get check >/dev/null 2>&1 && return 0
  timeout 300 dpkg --force-confold --configure -a >/dev/null 2>&1 || true
  apt-get check >/dev/null 2>&1 && { echo "apt: finished an interrupted package configuration"; return 0; }
  local sim
  if ! sim=$(apt-get -s -f install 2>&1); then
    echo "apt is broken and can't be repaired automatically: $(echo "$sim" | grep -E '^E:' | head -2 | tr '\n' ' ')"
    return 1
  fi
  if echo "$sim" | grep -q '^Remv '; then
    echo "apt is broken; repairing it would remove: $(echo "$sim" | awk '/^Remv /{print $2}' | tr '\n' ' ')— not done automatically: run 'apt --fix-broken install' on the server"
    return 1
  fi
  echo "apt was broken (unmet dependencies); repairing it, nothing is removed: $(echo "$sim" | awk '/^Inst /{print $2}' | tr '\n' ' ')"
  if ! timeout 900 apt-get -f install -y -qq -o Dpkg::Options::=--force-confold >/tmp/tp-apt-fix.log 2>&1; then
    echo "apt repair failed: $(grep -E '^E:' /tmp/tp-apt-fix.log | head -2 | tr '\n' ' ')"
    return 1
  fi
  apt-get check >/dev/null 2>&1 && echo "apt: repaired"
}
`
