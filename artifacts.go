package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Artifact is a binary the foreign (panel) server fetches once and then uploads to a host.
// Iran servers frequently cannot reach GitHub, so nothing is downloaded on the Iran side.
type Artifact struct {
	Name  string // cache key, e.g. "backhaul-v0.7.2"
	Fetch string // bash run on the panel host with $ARCH and $OUT set; must write the binary to $OUT
	Asset string // alternatively: an embedded/uploaded helper "<name>-<arch>" (no fetch)
	Dest  string
	Mode  os.FileMode
}

var cacheDir = "/var/cache/tunnel-panel" // var: tests use a temp dir

var fetchMu sync.Mutex

// goArch maps `uname -m` output to release-asset arch names.
func goArch(uname string) string {
	switch strings.TrimSpace(uname) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv6l", "arm":
		return "arm"
	case "i386", "i686":
		return "386"
	}
	return "amd64"
}

func hostArch(ctx context.Context, h Host) (string, error) {
	out, err := h.Run(ctx, "uname -m", nil)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return goArch(lines[len(lines)-1]), nil
}

// ensureArtifact returns the bytes for an artifact built for arch, fetching into the cache if needed.
func ensureArtifact(ctx context.Context, j *Job, a Artifact, arch string) ([]byte, error) {
	if a.Asset != "" {
		return helperBytes(a.Asset, arch)
	}
	fetchMu.Lock()
	defer fetchMu.Unlock()
	out := filepath.Join(cacheDir, a.Name+"-"+arch)
	cached, cerr := os.ReadFile(out)
	fresh := true
	if st, err := os.Stat(out); err == nil && strings.Contains(a.Name, "latest") && time.Since(st.ModTime()) > 7*24*time.Hour {
		fresh = false // "latest" pins are re-resolved weekly so new upstream releases arrive
	}
	if cerr == nil && len(cached) > 0 && fresh {
		return cached, nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}
	j.log("[KH] fetching %s for %s", a.Name, arch)
	// set -e: a failed checksum or download must stop the script before anything is installed
	script := fmt.Sprintf("set -e\nARCH=%s\nOUT=%s\nTMP=$(mktemp -d)\ntrap 'rm -rf $TMP' EXIT\ncd $TMP\n%s\n", arch, shq(out+".part"), a.Fetch)
	if _, err := (LocalHost{}).Run(ctx, script, func(l string) { j.log("[KH] %s", l) }); err != nil {
		if len(cached) > 0 {
			j.log("[KH] refresh of %s failed, keeping the cached copy", a.Name)
			_ = os.Chtimes(out, time.Now(), time.Now())
			return cached, nil
		}
		return nil, fmt.Errorf("fetch %s: %w", a.Name, err)
	}
	if err := os.Rename(out+".part", out); err != nil {
		return nil, fmt.Errorf("fetch %s produced no file", a.Name)
	}
	return os.ReadFile(out)
}

// helperBytes loads a helper binary: an uploaded one in the data dir wins over the embedded one.
func helperBytes(name, arch string) ([]byte, error) {
	file := name + "-" + arch
	for _, get := range []func() ([]byte, error){
		func() ([]byte, error) { return os.ReadFile(filepath.Join(helpersDir(), file)) },
		func() ([]byte, error) { return assetBytes(file) },
	} {
		if b, err := get(); err == nil && len(b) > 0 {
			// a v1.x Premium core (old [server]/[client] format) can't run the v2 method
			if name == "backhaul_premium" && !bytes.Contains(b, []byte("anytls")) {
				return nil, fmt.Errorf("%s is a Backhaul Premium v1.x core (it can't talk to v2): use the \"Backhaul Premium v1 (legacy)\" method on both servers, or upload a v2 core", file)
			}
			return b, nil
		}
	}
	hint := ""
	if name == "backhaul_premium" {
		hint = fmt.Sprintf(" (the vendor's backhaul_premium_%s.tar.gz can be uploaded as is)", arch)
	}
	return nil, fmt.Errorf("helper %s is not available for %s — upload it as %s-%s under Settings → Helper binaries%s", name, arch, name, arch, hint)
}

var dataDir = "/etc/tunnel-panel"

func helpersDir() string { return filepath.Join(dataDir, "helpers") }

func ghURL(set Settings, url string) string { return set.GitHubProxy + url }

// ---- artifacts used by the methods ----

// backhaul v0.7.2 is a fixed release, so its archives are pinned: a download prefix
// (GitHubProxy) or a tampered mirror can't hand every server a different root binary
const (
	backhaulSHA256amd64 = "57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc"
	backhaulSHA256arm64 = "9a424c97ff16fc3f682e8314c418790d2b5bf3136e008edbb6cd402ea00999f6"
)

func artBackhaul(set Settings) Artifact {
	return Artifact{Name: "backhaul-v0.7.2", Dest: "/opt/backhaul/backhaul", Mode: 0o755, Fetch: fmt.Sprintf(`
curl -fL --retry 3 -o bh.tgz "%s"
case "$ARCH" in amd64) want=%s ;; arm64) want=%s ;; *) echo "no pinned checksum for $ARCH"; exit 1 ;; esac
echo "$want  bh.tgz" | sha256sum -c - || { echo "backhaul archive checksum mismatch — refusing to install it"; exit 1; }
tar -xzf bh.tgz backhaul
install -m0755 backhaul "$OUT"`, ghURL(set, "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_${ARCH}.tar.gz"), backhaulSHA256amd64, backhaulSHA256arm64)}
}

func artFRP(set Settings, bin string) Artifact {
	ver := set.FRPVersion
	return Artifact{Name: "frp-" + bin + "-" + orStr(ver, "latest"), Dest: "/opt/frp/" + bin, Mode: 0o755, Fetch: fmt.Sprintf(`
VER=%s
if [ -z "$VER" ]; then
  VER=$(curl -fsSLI -o /dev/null -w '%%{url_effective}' https://github.com/fatedier/frp/releases/latest | sed 's#.*/tag/v##')
fi
case "$VER" in ''|*[!0-9.]*) echo "cannot resolve the frp version (got '$VER'); set it in Settings"; exit 1 ;; esac
f="frp_${VER}_linux_${ARCH}.tar.gz"
curl -fL --retry 3 -o frp.tgz "%shttps://github.com/fatedier/frp/releases/download/v${VER}/$f"
# the release's own checksum list, straight from github.com (not through the download
# prefix, which could otherwise swap both files)
curl -fsSL --retry 3 -o sums "https://github.com/fatedier/frp/releases/download/v${VER}/frp_sha256_checksums.txt" || curl -fsSL --retry 3 -o sums "%shttps://github.com/fatedier/frp/releases/download/v${VER}/frp_sha256_checksums.txt"
grep " $f\$" sums | head -1 | sed "s# .*#  frp.tgz#" | sha256sum -c - || { echo "frp archive checksum mismatch — refusing to install it"; exit 1; }
tar -xzf frp.tgz --strip-components=1
install -m0755 %s "$OUT"`, shq(strings.TrimPrefix(ver, "v")), set.GitHubProxy, set.GitHubProxy, bin)}
}

func artBackpack(set Settings) Artifact {
	return Artifact{Name: "backpack-latest", Dest: "/usr/local/bin/backpack", Mode: 0o755, Fetch: fmt.Sprintf(`
base="%shttps://github.com/AminMGMT/BackPack/releases/latest/download"
curl -fL --retry 3 -o bp.tgz "$base/backpack_linux_${ARCH}.tar.gz"
curl -fL --retry 3 -o SHA256SUMS "$base/SHA256SUMS"
grep "backpack_linux_${ARCH}.tar.gz" SHA256SUMS | head -1 | sed 's# .*#  bp.tgz#' | sha256sum -c -
tar -xzf bp.tgz backpack
install -m0755 backpack "$OUT"`, set.GitHubProxy)}
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
