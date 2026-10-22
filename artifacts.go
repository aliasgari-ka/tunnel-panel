package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

const cacheDir = "/var/cache/tunnel-panel"

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
	if b, err := os.ReadFile(out); err == nil && len(b) > 0 {
		return b, nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}
	j.log("[KH] fetching %s for %s", a.Name, arch)
	script := fmt.Sprintf("ARCH=%s\nOUT=%s\nTMP=$(mktemp -d)\ntrap 'rm -rf $TMP' EXIT\ncd $TMP\n%s\n", arch, shq(out+".part"), a.Fetch)
	if _, err := (LocalHost{}).Run(ctx, script, func(l string) { j.log("[KH] %s", l) }); err != nil {
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
	if b, err := os.ReadFile(filepath.Join(helpersDir(), file)); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := assetBytes(file); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, fmt.Errorf("helper %s is not available for %s — upload it under Settings → Helper binaries", name, arch)
}

var dataDir = "/etc/tunnel-panel"

func helpersDir() string { return filepath.Join(dataDir, "helpers") }

func ghURL(set Settings, url string) string { return set.GitHubProxy + url }

// ---- artifacts used by the methods ----

func artBackhaul(set Settings) Artifact {
	return Artifact{Name: "backhaul-v0.7.2", Dest: "/opt/backhaul/backhaul", Mode: 0o755, Fetch: fmt.Sprintf(`
curl -fL --retry 3 -o bh.tgz "%s"
tar -xzf bh.tgz backhaul
install -m0755 backhaul "$OUT"`, ghURL(set, "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_${ARCH}.tar.gz"))}
}

func artFRP(set Settings, bin string) Artifact {
	ver := set.FRPVersion
	return Artifact{Name: "frp-" + bin + "-" + orStr(ver, "latest"), Dest: "/opt/frp/" + bin, Mode: 0o755, Fetch: fmt.Sprintf(`
VER=%q
if [ -z "$VER" ]; then
  VER=$(curl -fsSLI -o /dev/null -w '%%{url_effective}' https://github.com/fatedier/frp/releases/latest | sed 's#.*/tag/v##')
fi
[ -n "$VER" ] || { echo "cannot resolve latest frp version; set it in Settings"; exit 1; }
curl -fL --retry 3 -o frp.tgz "%shttps://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz"
tar -xzf frp.tgz --strip-components=1
install -m0755 %s "$OUT"`, ver, set.GitHubProxy, bin)}
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
