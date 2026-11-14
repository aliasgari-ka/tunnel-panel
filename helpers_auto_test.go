package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeELF is a minimal Linux ELF64 header for machine (0x3e amd64, 0xb7 arm64) plus body.
func fakeELF(machine uint16, body []byte) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(h[16:], 2)
	binary.LittleEndian.PutUint16(h[18:], machine)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64)
	return append(h, body...)
}

func helperTestDir(t *testing.T) {
	t.Helper()
	old := dataDir
	dataDir = t.TempDir()
	vendorMu.Lock()
	vendorDown = map[string]time.Time{}
	vendorMu.Unlock()
	helperLost.Range(func(k, _ any) bool { helperLost.Delete(k); return true })
	t.Cleanup(func() { dataDir = old })
}

// fileHost serves files from a map through the two commands readHelperFromHost runs.
type fileHost struct {
	files map[string][]byte
	runs  int
}

func (f *fileHost) Label() string                               { return "fake" }
func (f *fileHost) WriteFile(string, []byte, os.FileMode) error { return nil }

var ddRe = regexp.MustCompile(`^dd if='([^']+)' bs=(\d+) skip=(\d+) count=1`)

func (f *fileHost) Run(_ context.Context, script string, _ func(string)) (string, error) {
	f.runs++
	if m := ddRe.FindStringSubmatch(script); m != nil {
		b := f.files[m[1]]
		bs, _ := strconv.Atoi(m[2])
		skip, _ := strconv.Atoi(m[3])
		lo, hi := bs*skip, bs*(skip+1)
		if lo > len(b) {
			lo = len(b)
		}
		if hi > len(b) {
			hi = len(b)
		}
		enc := base64.StdEncoding.EncodeToString(b[lo:hi])
		var out strings.Builder
		for len(enc) > 76 { // like base64(1): wrapped lines
			out.WriteString(enc[:76] + "\n")
			enc = enc[76:]
		}
		out.WriteString(enc + "\n")
		return out.String(), nil
	}
	for _, p := range recoverableHelpers["tpk-agent-amd64"] {
		if b, ok := f.files[p]; ok && strings.Contains(script, shq(p)) {
			s := sha256.Sum256(b)
			return fmt.Sprintf("HELPER %s %d %s\n", p, len(b), hex.EncodeToString(s[:])), nil
		}
	}
	return "none\n", nil
}

func candidates(hs ...*fileHost) []helperCandidate {
	var out []helperCandidate
	for i, h := range hs {
		h := h
		out = append(out, helperCandidate{fmt.Sprintf("srv%d", i), func(context.Context) (Host, error) { return h, nil }})
	}
	return out
}

func pinTPK(t *testing.T, sum string) {
	old := knownHelperSums["tpk-agent-amd64"]
	knownHelperSums["tpk-agent-amd64"] = []string{sum}
	t.Cleanup(func() { knownHelperSums["tpk-agent-amd64"] = old })
}

// A lost tpk-agent comes back from a server that runs it (bigger than one 2 MB piece, at
// the emulated host's <dest>.amd64 path too), through ensureHelper as an apply calls it.
func TestHelperRecoveredFromServer(t *testing.T) {
	helperTestDir(t)
	bin := fakeELF(0x3e, bytes.Repeat([]byte("tp-agent 1.20.9 "), 300000)) // ~4.8 MB
	s := sha256.Sum256(bin)
	pinTPK(t, hex.EncodeToString(s[:]))
	empty := &fileHost{files: map[string][]byte{}}
	arm := &fileHost{files: map[string][]byte{tpkBin + ".amd64": bin, tpkBin: []byte("#!/bin/sh\nexec qemu\n")}}
	old := helperRecover
	helperRecover = func(ctx context.Context, file string, logf func(string, ...any)) error {
		return recoverHelperFrom(ctx, file, candidates(empty, arm), logf)
	}
	t.Cleanup(func() { helperRecover = old })

	got, err := ensureHelper(context.Background(), t.Logf, "tpk-agent", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bin) {
		t.Fatalf("recovered %d bytes, want %d identical", len(got), len(bin))
	}
	if b, _ := os.ReadFile(filepath.Join(helpersDir(), "tpk-agent-amd64")); !bytes.Equal(b, bin) {
		t.Fatal("not saved in the helpers dir")
	}
	// the arm64 slot isn't recovered (that host runs the amd64 build under emulation)
	if _, err := ensureHelper(context.Background(), t.Logf, "tpk-agent", "arm64"); err == nil {
		t.Fatal("tpk-agent-arm64 should not exist")
	}
}

// An existing helper is used as is: no server is asked, nothing is replaced.
func TestHelperExistingKept(t *testing.T) {
	helperTestDir(t)
	mine := fakeELF(0x3e, []byte("mine"))
	if err := os.MkdirAll(helpersDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(helpersDir(), "tpk-agent-amd64"), mine, 0o700)
	srv := &fileHost{files: map[string][]byte{tpkBin: fakeELF(0x3e, []byte("other"))}}
	old := helperRecover
	helperRecover = func(ctx context.Context, file string, logf func(string, ...any)) error {
		return recoverHelperFrom(ctx, file, candidates(srv), logf)
	}
	t.Cleanup(func() { helperRecover = old })
	got, err := ensureHelper(context.Background(), t.Logf, "tpk-agent", "amd64")
	if err != nil || !bytes.Equal(got, mine) || srv.runs != 0 {
		t.Fatalf("got %q, %v, %d runs; want the existing file untouched", got, err, srv.runs)
	}
	// a backup restore never replaces it either
	if r := restoreHelpers(map[string][]byte{"tpk-agent-amd64": fakeELF(0x3e, []byte("old"))}); len(r) != 0 {
		t.Fatalf("restore replaced the existing helper: %v", r)
	}
}

// An unknown build is taken only when two servers hold the identical file; a single
// unknown copy, or a non-amd64 file, is refused and the method gets its one-line note.
func TestHelperRecoverTrust(t *testing.T) {
	helperTestDir(t)
	pinTPK(t, strings.Repeat("0", 64))
	unknown := fakeELF(0x3e, []byte("unknown build"))
	one := &fileHost{files: map[string][]byte{tpkBin: unknown}}
	if err := recoverHelperFrom(context.Background(), "tpk-agent-amd64", candidates(one), t.Logf); err == nil {
		t.Fatal("a single unknown copy was accepted")
	}
	two := &fileHost{files: map[string][]byte{tpkBin: unknown}}
	if err := recoverHelperFrom(context.Background(), "tpk-agent-amd64", candidates(one, two), t.Logf); err != nil {
		t.Fatalf("two servers agree, still refused: %v", err)
	}
	// once held, the build's sum is recorded and trusted from one server
	if !trustedHelperSums("tpk-agent-amd64")[func() string { s := sha256.Sum256(unknown); return hex.EncodeToString(s[:]) }()] {
		t.Fatal("recovered build's sum not recorded")
	}

	helperTestDir(t)
	pinTPK(t, strings.Repeat("0", 64))
	old := helperRecover
	helperRecover = func(ctx context.Context, file string, logf func(string, ...any)) error {
		return recoverHelperFrom(ctx, file, candidates(&fileHost{files: map[string][]byte{}}), logf)
	}
	t.Cleanup(func() { helperRecover = old })
	if _, err := ensureHelper(context.Background(), t.Logf, "tpk-agent", "amd64"); err == nil {
		t.Fatal("expected an error with no server having it")
	}
	if v, ok := helperLost.Load("tpk-agent-amd64"); !ok || !strings.Contains(v.(string), "retried at every apply") {
		t.Fatalf("no note for the method: %v", v)
	}
}

func vendorTGZ(bin []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "backhaul_premium", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	tw.Write(bin)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func fakeVendor(t *testing.T, bin []byte) *int32 {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/backhaul_premium_amd64.tar.gz" {
			http.NotFound(w, r)
			return
		}
		w.Write(vendorTGZ(bin))
	}))
	t.Cleanup(srv.Close)
	old := vendorHelpers["backhaul_premium"]
	vendorHelpers["backhaul_premium"] = []string{srv.URL + "/backhaul_premium_%s.tar.gz", srv.URL + "/backhaul_premium_%s.tar.gz"}
	t.Cleanup(func() { vendorHelpers["backhaul_premium"] = old })
	pinVendor(t, bin)
	return &hits
}

// pinVendor adds bin's sha256 to the known amd64 builds for this test.
func pinVendor(t *testing.T, bin []byte) {
	sum := sha256.Sum256(bin)
	old := vendorSHA256["backhaul_premium"]["amd64"]
	vendorSHA256["backhaul_premium"]["amd64"] = append(append([]string{}, old...), hex.EncodeToString(sum[:]))
	t.Cleanup(func() { vendorSHA256["backhaul_premium"]["amd64"] = old })
}

// The vendor serves plain HTTP: a build whose sha256 is not pinned is refused, even when
// both mirrors serve the same file (someone on the path can swap both).
func TestVendorUnknownBuildRefused(t *testing.T) {
	helperTestDir(t)
	fakeVendor(t, fakeELF(0x3e, []byte("pinned")))
	evil := fakeELF(0x3e, []byte("swapped on the path"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(vendorTGZ(evil)) }))
	t.Cleanup(srv.Close)
	vendorHelpers["backhaul_premium"] = []string{srv.URL + "/a_%s.tgz", srv.URL + "/b_%s.tgz"}
	delete(vendorDown, "backhaul_premium-amd64")
	if _, err := fetchVendorHelper("backhaul_premium-amd64"); err == nil || !strings.Contains(err.Error(), "unknown build") {
		t.Fatalf("unpinned build accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(helpersDir(), "backhaul_premium-amd64")); err == nil {
		t.Fatalf("unpinned build was stored")
	}
	if sc := vendorOnHostScript("backhaul_premium", "amd64", "/opt/x"); !strings.Contains(sc, vendorSHA256["backhaul_premium"]["amd64"][0]) || !strings.Contains(sc, "unknown vendor build") {
		t.Fatalf("on-host script does not check the pinned sha256")
	}
}

// A missing Premium v2 core is downloaded from the vendor at first need and kept; an
// existing v2 core isn't downloaded again; a v1.x core in the v2 slot is replaced.
func TestHelperPremiumFromVendor(t *testing.T) {
	helperTestDir(t)
	v2 := fakeELF(0x3e, []byte("backhaul premium v2 anytls"))
	hits := fakeVendor(t, v2)
	got, err := ensureHelper(context.Background(), t.Logf, "backhaul_premium", "amd64")
	if err != nil || !bytes.Equal(got, v2) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	if *hits != 2 {
		t.Fatalf("%d vendor requests, want both mirrors once", *hits)
	}
	if _, err := ensureHelper(context.Background(), t.Logf, "backhaul_premium", "amd64"); err != nil || *hits != 2 {
		t.Fatalf("cached core fetched again (%d requests, %v)", *hits, err)
	}

	// outdated: a v1.x core sits in the v2 slot
	os.WriteFile(filepath.Join(helpersDir(), "backhaul_premium-amd64"), fakeELF(0x3e, []byte("premium v1.0.2")), 0o700)
	got, err = ensureHelper(context.Background(), t.Logf, "backhaul_premium", "amd64")
	if err != nil || !bytes.Equal(got, v2) {
		t.Fatalf("v1 core not replaced: %d bytes, %v", len(got), err)
	}

	// arm64 never takes the vendor's arm64 (v1) build: those hosts emulate the amd64 core
	before := *hits
	if _, err := ensureHelper(context.Background(), t.Logf, "backhaul_premium", "arm64"); err == nil || *hits != before {
		t.Fatalf("arm64 slot: err %v, %d new requests", err, *hits-before)
	}
}

// The backup that leaves the host carries tpk-agent; restoring it on a fresh panel puts it
// back, and the state part still loads as a plain State.
func TestHelperBackupRoundTrip(t *testing.T) {
	helperTestDir(t)
	bin := fakeELF(0x3e, []byte("tp core"))
	os.MkdirAll(helpersDir(), 0o700)
	os.WriteFile(filepath.Join(helpersDir(), "tpk-agent-amd64"), bin, 0o700)
	st := &State{Secret: "x"}
	data, err := json.Marshal(struct {
		*State
		HelperFiles map[string][]byte `json:"helperFiles,omitempty"`
	}{st, backupHelpers()})
	if err != nil {
		t.Fatal(err)
	}
	var back State
	if err := json.Unmarshal(data, &back); err != nil || back.Secret != "x" {
		t.Fatalf("state part: %v %q", err, back.Secret)
	}
	var extra struct {
		HelperFiles map[string][]byte `json:"helperFiles"`
	}
	json.Unmarshal(data, &extra)
	os.Remove(filepath.Join(helpersDir(), "tpk-agent-amd64"))
	if got := restoreHelpers(extra.HelperFiles); len(got) != 1 {
		t.Fatalf("restored %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(helpersDir(), "tpk-agent-amd64")); !bytes.Equal(b, bin) {
		t.Fatal("restored file differs")
	}
	// only known helper names, and only real binaries for their arch
	if got := restoreHelpers(map[string][]byte{"evil-amd64": bin, "tpk-agent-amd64": []byte("not elf")}); len(got) != 0 {
		t.Fatalf("restored %v", got)
	}
}
