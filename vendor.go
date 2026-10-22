package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// vendorHelpers are closed helpers whose vendor publishes per-arch builds (we have no
// source to build them). The vendor serves them over plain HTTP — its own installer uses
// the same URLs, unchecked — so the panel fetches both mirrors and requires the copies
// to match, then checks the ELF architecture.
var vendorHelpers = map[string][]string{
	"backhaul_premium": {
		"http://script.backhaul.top:2095/backhaul_premium_%s.tar.gz",
		"http://79.175.167.114:2095/backhaul_premium_%s.tar.gz",
	},
}

type vendorResult struct {
	Source, SHA256, Note string
	Size                 int64
}

var vendorMu sync.Mutex

// fetchVendorHelper downloads "<base>-<arch>" from the vendor into the helpers dir.
func fetchVendorHelper(name string) (*vendorResult, error) {
	vendorMu.Lock()
	defer vendorMu.Unlock()
	i := strings.LastIndex(name, "-")
	if i < 0 {
		return nil, fmt.Errorf("bad helper name %q", name)
	}
	base, arch := name[:i], name[i+1:]
	urls := vendorHelpers[base]
	if urls == nil {
		return nil, fmt.Errorf("%s has no vendor download — upload it instead", base)
	}
	if err := os.MkdirAll(helpersDir(), 0o700); err != nil {
		return nil, err
	}
	cli := &http.Client{Timeout: 90 * time.Second}
	type got struct{ url, sum, path string }
	var ok []got
	var errs []string
	for k, u := range urls {
		u = fmt.Sprintf(u, arch)
		tmp := filepath.Join(helpersDir(), fmt.Sprintf("%s.fetch%d.part", name, k))
		err := func() error {
			resp, err := cli.Get(u)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(resp.Body, 200<<20))
			f.Close()
			if err != nil {
				return err
			}
			return normalizeHelper(tmp, name)
		}()
		if err != nil {
			os.Remove(tmp)
			errs = append(errs, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		b, _ := os.ReadFile(tmp)
		sum := sha256.Sum256(b)
		ok = append(ok, got{u, hex.EncodeToString(sum[:]), tmp})
	}
	defer func() {
		for _, g := range ok {
			os.Remove(g.path)
		}
	}()
	if len(ok) == 0 {
		return nil, fmt.Errorf("could not download %s from the vendor: %s", name, strings.Join(errs, "; "))
	}
	note := "only one vendor mirror answered, so the copy could not be cross-checked"
	if len(ok) > 1 {
		if ok[0].sum != ok[1].sum {
			return nil, fmt.Errorf("the two vendor mirrors served different files (%s vs %s) — refusing; upload a copy you trust", ok[0].sum[:12], ok[1].sum[:12])
		}
		note = "both vendor mirrors served the identical file"
	}
	dst := filepath.Join(helpersDir(), name)
	if err := os.Rename(ok[0].path, dst); err != nil {
		return nil, err
	}
	res := &vendorResult{Source: ok[0].url, SHA256: ok[0].sum, Note: note}
	if st, err := os.Stat(dst); err == nil {
		res.Size = st.Size()
	}
	return res, nil
}

// vendorOnHost downloads a vendor helper directly on the target host (for when the panel
// itself can't reach the vendor), checks its ELF machine and installs it at dest.
// Returns "" on success, else the reason.
func vendorOnHostScript(base, arch, dest string) string {
	urls := vendorHelpers[base]
	if urls == nil {
		return ""
	}
	mach := map[string]string{"amd64": "3e00", "arm64": "b700"}[arch]
	var us []string
	for _, u := range urls {
		us = append(us, shq(fmt.Sprintf(u, arch)))
	}
	return fmt.Sprintf(`D=%[1]s
m() { od -An -tx1 -j18 -N2 "$1" 2>/dev/null | tr -d ' \n'; }
if [ -x "$D" ] && [ "$(m "$D")" = %[2]s ]; then echo "already installed on this host"; exit 0; fi
T=$(mktemp -d); trap 'rm -rf $T' EXIT; cd $T
for u in %[3]s; do curl -fsSL --max-time 90 -o p.tgz "$u" && break; done
[ -s p.tgz ] || { echo "this host cannot reach the vendor either"; exit 1; }
tar -xzf p.tgz 2>/dev/null || { echo "vendor file is not a tar.gz"; exit 1; }
f=""; for x in $(find . -type f); do [ "$(m "$x")" = %[2]s ] && { f=$x; break; }; done
[ -n "$f" ] || { echo "no %[4]s binary inside the vendor archive"; exit 1; }
mkdir -p "$(dirname "$D")" && install -m0755 "$f" "$D" && echo "installed from the vendor on this host: $(sha256sum "$D" | cut -c1-16)…"
`, shq(dest), mach, strings.Join(us, " "), arch)
}
