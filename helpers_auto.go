package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Helpers the panel gets and keeps by itself (nothing is uploaded by hand any more):
//   - built-in ones (golden-gre-relay, the Premium v1 arm64 core) are embedded;
//   - Backhaul Premium v2 comes from the vendor at first need (both mirrors compared,
//     the ELF arch checked), and a v1.x core found in the v2 slot is replaced the same way;
//   - tpk-agent (TP Tunnel / TP Reverse) is a third-party closed binary that must not be in
//     this public repository: the copy on the panel host is kept (never deleted, carried in
//     backups) and, when missing, recovered from a server that already runs it.

// recoverableHelpers: helpers that can be copied back from a server that has them
// installed, with the paths the panel installs them at (emulated hosts keep the real
// binary at <dest>.amd64 behind a wrapper script).
var recoverableHelpers = map[string][]string{
	"tpk-agent-amd64": {tpkBin + ".amd64", tpkBin},
}

// knownHelperSums are builds we trust without a second opinion (sha256 of the binary).
// The hash only identifies the file; the binary itself never enters the repository.
var knownHelperSums = map[string][]string{
	"tpk-agent-amd64": {"f8418b4a2913076b5dc6f3d3c08f9dd8d2e1113ea6134434a063d07ce80aa5d5"}, // tp-agent 1.20.9
}

// helperRecover finds a missing recoverable helper on the servers (set by the App).
var helperRecover func(ctx context.Context, file string, logf func(string, ...any)) error

var helperAutoMu sync.Mutex

// helperLost: file -> why a recoverable helper couldn't be brought back (shown on its method)
var helperLost sync.Map

// ensureHelper is helperBytes, but a helper that is missing (or a v1.x core in the
// Premium v2 slot) is obtained automatically: from the vendor or from a server.
func ensureHelper(ctx context.Context, logf func(string, ...any), name, arch string) ([]byte, error) {
	b, err := helperBytes(name, arch)
	if err == nil {
		return b, nil
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	file := name + "-" + arch
	helperAutoMu.Lock()
	defer helperAutoMu.Unlock()
	if b, err2 := helperBytes(name, arch); err2 == nil {
		return b, nil // another job got it meanwhile
	}
	switch {
	// the vendor's arm64 build is v1.0.2, which can't talk to v2: arm64 hosts run the amd64 core
	case vendorHelpers[name] != nil && !(name == "backhaul_premium" && arch != "amd64"):
		logf("%s is not on the panel yet — downloading the vendor's build", file)
		res, ferr := fetchVendorHelper(file)
		if ferr != nil {
			return nil, fmt.Errorf("%s: the panel could not download it from the vendor: %v", file, ferr)
		}
		logf("got %s (%d KB, sha256 %s…, %s)", file, res.Size/1024, res.SHA256[:12], res.Note)
	case recoverableHelpers[file] != nil && helperRecover != nil:
		logf("%s is missing on the panel — copying it back from a server that has it", file)
		if rerr := helperRecover(ctx, file, logf); rerr != nil {
			helperLost.Store(file, fmt.Sprintf("The %s core is missing on the panel and %v; it is retried at every apply.", file, rerr))
			return nil, fmt.Errorf("%s is not on the panel and %v", file, rerr)
		}
		helperLost.Delete(file)
	default:
		return nil, err
	}
	return helperBytes(name, arch)
}

// ---- trusted checksums ----

func helperSumsPath() string { return filepath.Join(dataDir, "helper-sums.json") }

var helperSumsMu sync.Mutex

// trustedHelperSums: the pinned sums plus every sum the panel has itself held for file.
func trustedHelperSums(file string) map[string]bool {
	out := map[string]bool{}
	for _, s := range knownHelperSums[file] {
		out[s] = true
	}
	helperSumsMu.Lock()
	defer helperSumsMu.Unlock()
	var rec map[string][]string
	if b, err := os.ReadFile(helperSumsPath()); err == nil && json.Unmarshal(b, &rec) == nil {
		for _, s := range rec[file] {
			out[s] = true
		}
	}
	return out
}

// recordHelperSums notes the sha256 of every recoverable helper on the panel, so a later
// recovery can accept the same build (e.g. a newer one the admin put there) from one server.
func recordHelperSums() {
	helperSumsMu.Lock()
	defer helperSumsMu.Unlock()
	rec := map[string][]string{}
	if b, err := os.ReadFile(helperSumsPath()); err == nil {
		_ = json.Unmarshal(b, &rec)
	}
	changed := false
	for file := range recoverableHelpers {
		b, err := os.ReadFile(filepath.Join(helpersDir(), file))
		if err != nil || len(b) == 0 {
			continue
		}
		s := sha256.Sum256(b)
		sum := hex.EncodeToString(s[:])
		if !containsStr(rec[file], sum) {
			rec[file] = append(rec[file], sum)
			changed = true
		}
	}
	if changed {
		if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
			_ = os.WriteFile(helperSumsPath(), b, 0o600)
		}
	}
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// saveHelper writes a recovered/restored helper atomically after checking its ELF arch.
func saveHelper(file string, data []byte) error {
	if err := os.MkdirAll(helpersDir(), 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(helpersDir(), file+".recover.part")
	if err := os.WriteFile(tmp, data, 0o700); err != nil {
		return err
	}
	if err := normalizeHelper(tmp, file); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(helpersDir(), file)); err != nil {
		os.Remove(tmp)
		return err
	}
	recordHelperSums()
	return nil
}

// ---- recovery from the servers ----

// helperCandidate is a host that may have the helper installed.
type helperCandidate struct {
	label string
	host  func(ctx context.Context) (Host, error)
}

// recoverHelperFrom copies file back from the first candidate host whose copy is trusted:
// a pinned/recorded sha256, or the same build on two different servers.
func recoverHelperFrom(ctx context.Context, file string, cands []helperCandidate, logf func(string, ...any)) error {
	paths := recoverableHelpers[file]
	if paths == nil {
		return fmt.Errorf("%s can't be recovered from servers", file)
	}
	trusted := trustedHelperSums(file)
	seen := map[string]string{} // sha -> first host label
	tried := 0
	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		hctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		h, err := c.host(hctx)
		if err != nil {
			cancel()
			continue
		}
		tried++
		data, sum, err := readHelperFromHost(hctx, h, paths)
		cancel()
		if err != nil {
			continue
		}
		ok := trusted[sum]
		if !ok && seen[sum] != "" {
			ok = true // two servers hold the identical build
		}
		if !ok {
			if seen[sum] == "" {
				seen[sum] = c.label
			}
			logf("%s on %s is an unknown build (sha256 %s…) — looking for a second server with the same one", file, c.label, sum[:12])
			continue
		}
		if err := saveHelper(file, data); err != nil {
			logf("%s from %s rejected: %v", file, c.label, err)
			continue
		}
		logf("recovered %s from %s (%d KB, sha256 %s…)", file, c.label, len(data)/1024, sum[:12])
		return nil
	}
	if tried == 0 {
		return fmt.Errorf("no server that runs it could be reached")
	}
	return fmt.Errorf("no reachable server has a trusted copy")
}

// readHelperFromHost copies an amd64 ELF binary from the first existing path, in 2 MB
// base64 pieces (an agent frame and a log line both have size limits), and checks the
// result against the host's own sha256.
func readHelperFromHost(ctx context.Context, h Host, paths []string) ([]byte, string, error) {
	var q []string
	for _, p := range paths {
		q = append(q, shq(p))
	}
	out, err := h.Run(ctx, fmt.Sprintf(`for f in %s; do
  [ -f "$f" ] || continue
  [ "$(od -An -tx1 -j18 -N2 "$f" 2>/dev/null | tr -d ' \n')" = 3e00 ] || continue
  echo "HELPER $f $(stat -c %%s "$f") $(sha256sum "$f" | cut -d' ' -f1)"; exit 0
done; echo none`, strings.Join(q, " ")), nil)
	if err != nil {
		return nil, "", err
	}
	var path, sum string
	var size int
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 4 && f[0] == "HELPER" {
			path, sum = f[1], f[3]
			size, _ = strconv.Atoi(f[2])
		}
	}
	if path == "" || size <= 0 || size > 200<<20 || len(sum) != 64 {
		return nil, "", fmt.Errorf("not installed")
	}
	const piece = 2 << 20
	var buf bytes.Buffer
	for off := 0; off < size; off += piece {
		out, err := h.Run(ctx, fmt.Sprintf("dd if=%s bs=%d skip=%d count=1 2>/dev/null | base64", shq(path), piece, off/piece), nil)
		if err != nil {
			return nil, "", err
		}
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(out), ""))
		if err != nil {
			return nil, "", fmt.Errorf("bad copy: %v", err)
		}
		buf.Write(b)
	}
	s := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(s[:]); got != sum || buf.Len() != size {
		return nil, "", fmt.Errorf("copy doesn't match the server's checksum")
	}
	return buf.Bytes(), sum, nil
}

// recoverHelper is the App's helperRecover: servers of tunnels that use the helper come
// first (the panel host itself when it is their foreign end), then every other server.
func (a *App) recoverHelper(ctx context.Context, file string, logf func(string, ...any)) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	base := file[:strings.LastIndex(file, "-")]
	uses := map[string]bool{}
	for _, m := range methods {
		if m.Helper == base {
			uses[m.ID] = true
		}
	}
	rank := map[string]int{}
	var all []*Server
	panelEnd := false
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if uses[t.Active] || uses[t.Selected] {
				rank[t.ServerID] = 1
				if t.ForeignID == "" {
					panelEnd = true
				} else {
					rank[t.ForeignID] = 1
				}
			}
		}
		for _, s := range st.Servers {
			cp := *s
			all = append(all, &cp)
		}
	})
	sort.SliceStable(all, func(i, j int) bool { return rank[all[i].ID] > rank[all[j].ID] })
	var cands []helperCandidate
	if panelEnd {
		cands = append(cands, helperCandidate{"this panel host", func(context.Context) (Host, error) { return LocalHost{}, nil }})
	}
	for _, s := range all {
		s := s
		cands = append(cands, helperCandidate{s.Name, func(ctx context.Context) (Host, error) { return a.quickHost(ctx, s) }})
	}
	return recoverHelperFrom(ctx, file, cands, logf)
}

// keepHelpers records the helpers' checksums and brings a lost recoverable helper back
// while a tunnel still uses it, so the next apply doesn't have to.
func (a *App) keepHelpers() {
	time.Sleep(3 * time.Minute)
	for {
		recordHelperSums()
		for file := range recoverableHelpers {
			if st, err := os.Stat(filepath.Join(helpersDir(), file)); err == nil && st.Size() > 0 {
				continue
			}
			if !a.helperInUse(file) {
				continue
			}
			i := strings.LastIndex(file, "-")
			_, err := ensureHelper(context.Background(), func(f string, x ...any) { log.Printf("[helpers] "+f, x...) }, file[:i], file[i+1:])
			if err != nil {
				log.Printf("[helpers] %v", err)
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

func (a *App) helperInUse(file string) bool {
	base := file[:strings.LastIndex(file, "-")]
	in := false
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			for _, id := range []string{t.Active, t.Selected} {
				if m := methodByID[id]; m != nil && m.Helper == base {
					in = true
				}
			}
		}
	})
	return in
}

// ---- backups ----

// backupHelpers: the helpers that can't be downloaded again (tpk-agent), for the backup.
func backupHelpers() map[string][]byte {
	out := map[string][]byte{}
	for file := range recoverableHelpers {
		if b, err := os.ReadFile(filepath.Join(helpersDir(), file)); err == nil && len(b) > 0 {
			out[file] = b
		}
	}
	return out
}

// restoreHelpers writes a backup's helpers that the panel doesn't have. An existing file
// is never replaced; only known helper names are taken, and each must be a Linux binary
// for its arch (a restore is the admin's own file, like the SSH keys it carries).
func restoreHelpers(hs map[string][]byte) []string {
	var got []string
	for file, b := range hs {
		if recoverableHelpers[file] == nil || len(b) == 0 {
			continue
		}
		if st, err := os.Stat(filepath.Join(helpersDir(), file)); err == nil && st.Size() > 0 {
			continue
		}
		if saveHelper(file, b) == nil {
			got = append(got, file)
		}
	}
	sort.Strings(got)
	return got
}
