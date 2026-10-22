package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// probeArt is the tp-agent binary reused as the benchmark's path probe (see internal/probe).
// It lives apart from /usr/local/bin/tp-agent so a running agent is never overwritten.
var probeArt = Artifact{Name: "tp-probe", Asset: "tp-agent", Dest: "/usr/local/lib/tunnel-panel/tp-probe", Mode: 0o755}

// pushArtifacts uploads only the binaries whose sha256 on the host differs from the panel's
// copy, so switching methods doesn't resend megabytes that are already in place, while a
// newer binary on the panel (updated helper, new release) still replaces the old one.
func pushArtifacts(ctx context.Context, j *Job, label string, h Host, arts []Artifact) error {
	if len(arts) == 0 {
		return nil
	}
	arch, err := hostArch(ctx, h)
	if err != nil {
		return fmt.Errorf("detect arch: %w", err)
	}
	type item struct {
		art  Artifact
		data []byte
		sum  string
	}
	var items []item
	var check strings.Builder
	for _, art := range arts {
		data, err := ensureArtifact(ctx, j, art, arch)
		if err != nil && art.Asset != "" && vendorHelpers[art.Asset] != nil {
			// no copy on the panel: get the vendor's build for this arch automatically
			j.log("[%s] %s-%s is not on the panel yet — downloading the vendor's build", label, art.Asset, arch)
			if res, ferr := fetchVendorHelper(art.Asset + "-" + arch); ferr == nil {
				j.log("[%s] got %s-%s (%d KB, sha256 %s…, %s)", label, art.Asset, arch, res.Size/1024, res.SHA256[:12], res.Note)
				data, err = ensureArtifact(ctx, j, art, arch)
			} else {
				j.log("[%s] panel cannot reach the vendor (%v) — trying from the server itself", label, ferr)
				out, rerr := h.Run(ctx, vendorOnHostScript(art.Asset, arch, art.Dest), nil)
				if rerr == nil {
					j.log("[%s] %s", label, lastLine(out))
					continue // installed directly on the host
				}
				return fmt.Errorf("%v; the server's own download failed too: %s", err, lastLine(out))
			}
		}
		if err != nil {
			return err
		}
		s := sha256.Sum256(data)
		items = append(items, item{art, data, hex.EncodeToString(s[:])})
		fmt.Fprintf(&check, "sha256sum %s 2>/dev/null || true\n", shq(art.Dest))
	}
	out, _ := h.Run(ctx, check.String(), nil)
	have := map[string]string{} // dest -> sum on the host
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && len(f[0]) == 64 {
			have[f[1]] = f[0]
		}
	}
	for _, it := range items {
		if have[it.art.Dest] == it.sum {
			j.log("[%s] %s already installed (up to date)", label, it.art.Dest)
			continue
		}
		verb := "install"
		if have[it.art.Dest] != "" {
			verb = "update"
		}
		j.log("[%s] %s %s (%s, %d KB)", label, verb, it.art.Dest, arch, len(it.data)/1024)
		if err := h.WriteFile(it.art.Dest, it.data, it.art.Mode); err != nil {
			return err
		}
	}
	return nil
}

// withTail attaches the last lines of a failed command's output to its error, so the
// UI shows *why* a deploy failed instead of only "Process exited with status 1".
func withTail(err error, out string) error {
	if err == nil {
		return nil
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "-- ") || strings.HasPrefix(l, "unit tp-") {
			continue
		}
		// journalctl prefix: "Oct 22 10:00:00 host proc[123]: msg" -> "msg"
		if i := strings.Index(l, "]: "); i > 0 && i < 80 {
			l = l[i+3:]
		}
		keep = append(keep, l)
	}
	if len(keep) > 3 {
		keep = keep[len(keep)-3:]
	}
	if len(keep) == 0 {
		return err
	}
	return fmt.Errorf("%v — %s", err, strings.Join(keep, " | "))
}

// sideArtifacts lists every binary any method needs on one side (Iran or foreign),
// by building each method's plans for a throwaway tunnel.
func (a *App) sideArtifacts(iran bool) []Artifact {
	set := a.settings()
	ir := &Server{ID: "x", IPv4: "192.0.2.1", IPv6: "2001:db8::1"}
	kh := &Server{ID: "y", IPv4: "192.0.2.2", IPv6: "2001:db8::2"}
	seen := map[string]Artifact{probeArt.Dest: probeArt}
	for _, m := range methods {
		fam := m.Families[0]
		t := &Tunnel{ID: "prep", Family: fam, Ports: "443", Index: 250,
			Options: map[string]map[string]string{"spoof": {"spoof_ip": "192.0.2.9", "peer_spoof_ip": "192.0.2.10"}},
			Secrets: map[string]string{}}
		irP, khP, err := buildPlans(m, t, ir, kh, set)
		if err != nil {
			continue
		}
		p := khP
		if iran {
			p = irP
		}
		for _, art := range p.Artifacts {
			seen[art.Dest] = art
		}
	}
	var out []Artifact
	for _, art := range seen {
		out = append(out, art)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dest < out[j].Dest })
	return out
}

// prepScript installs the distro packages methods rely on, once, so a later method
// switch never waits on apt.
const prepScript = `pk=""
command -v swanctl >/dev/null 2>&1 || pk="$pk strongswan-swanctl charon-systemd libcharon-extra-plugins"
command -v ethtool >/dev/null 2>&1 || pk="$pk ethtool"
command -v iptables >/dev/null 2>&1 || pk="$pk iptables"
command -v openssl >/dev/null 2>&1 || pk="$pk openssl"
if [ -z "$pk" ]; then echo "packages: all present"; exit 0; fi
echo "installing:$pk"
if command -v apt-get >/dev/null 2>&1; then
  timeout 600 apt-get update -qq >/dev/null 2>&1 || true
  timeout 900 apt-get install -y -qq $pk >/dev/null 2>&1 || echo "WARNING: apt could not install some of:$pk"
elif command -v dnf >/dev/null 2>&1; then
  timeout 900 dnf install -y strongswan ethtool iptables openssl >/dev/null 2>&1 || echo "WARNING: dnf install failed"
fi
command -v swanctl >/dev/null 2>&1 && echo "strongSwan: ok" || echo "strongSwan: missing (IPsec will install it on first use)"
`

// Prepare pre-installs every method's binaries and packages on a server (srv == nil:
// this panel host), so switching methods later only writes configs and restarts a unit.
func (a *App) Prepare(srv *Server) (*Job, error) {
	key, name := "prep:local", "this panel host"
	if srv != nil {
		key, name = "prep:"+srv.ID, srv.Name
	}
	j, err := a.jobs.start(key, "prepare")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(30 * time.Minute)
		defer cancel()
		var h Host = LocalHost{}
		label, iran := "KH", false
		if srv != nil {
			hh, path, err := a.reach(ctx, srv, j)
			if err != nil {
				j.log("ERROR: cannot reach %s: %v", name, err)
				j.finish("error")
				return
			}
			j.log("%s reachable via %s", name, path)
			h, iran = hh, srv.Role != "foreign"
			if iran {
				label = "IR"
			}
		}
		j.log("preparing %s: binaries for every method + packages", name)
		failed := 0
		for _, art := range a.sideArtifacts(iran) {
			if err := pushArtifacts(ctx, j, label, h, []Artifact{art}); err != nil {
				failed++
				j.log("[%s] WARNING: %s: %v", label, art.Dest, err)
			}
		}
		out, _ := h.Run(ctx, prepScript, nil)
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if l != "" {
				j.log("[%s] %s", label, l)
			}
		}
		if srv != nil {
			_ = a.store.Update(func(st *State) error {
				if x := a.store.serverLocked(st, srv.ID); x != nil {
					x.Provisioned = time.Now().Unix()
				}
				return nil
			})
		}
		if failed > 0 {
			j.log("DONE — %s prepared, %d binaries unavailable (see warnings; those methods fetch on first use)", name, failed)
		} else {
			j.log("DONE — %s prepared; switching methods will no longer re-upload binaries", name)
		}
		j.finish("ok")
	}()
	return j, nil
}
