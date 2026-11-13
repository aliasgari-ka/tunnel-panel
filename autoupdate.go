package main

// Automatic update: the panel looks at its GitHub release every few minutes and installs a
// newer build by itself, the way a careful manual deploy does it:
//
//   - only a build whose commit is ahead of the running one on GitHub (never a downgrade,
//     never a stale re-run of release.yml that overwrote "latest" with an older commit);
//   - the download's sha256 must match SHA256SUMS and its --version the release's VERSION;
//   - nothing is restarted while a job (apply, repair, benchmark, IG …) is running;
//   - the swap, the restart, the health check on the panel's own domain (with SNI — the
//     panel's TLS does not answer on 127.0.0.1) and the rollback run in a transient systemd
//     unit (apply.sh), outside the panel's own service, so a new build that does not come up
//     is put back without the panel's help.
//
// What follows an update is the existing "first start of a new version" path:
// repairAfterUpdate (tunnels, switchers, relays, one tunnel at a time; RepairAuto decides
// what may move users, and hand-set options are never touched) and whatever else hangs off
// the version change (IG Routing). This file adds no second re-apply.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	updRepo     = "aliasgari-ka/tunnel-panel"
	updAPI      = "https://api.github.com"
	updBin      = "/usr/local/bin/tunnel-panel" // var: tests point it elsewhere
	updEvery    = 5 * time.Minute
	updFirst    = 2 * time.Minute // after a start: the post-update repair goes first
	panelAddr   = ""              // --addr, for the health check
	updRunApply = runApplyUnit    // tests replace it
)

// AutoUpdate is what the panel knows about its updates (State.AutoUpdate).
type AutoUpdate struct {
	Off          bool   `json:"off,omitempty"` // the admin turned it off (default on)
	LastCheck    int64  `json:"lastCheck,omitempty"`
	Latest       string `json:"latest,omitempty"`     // the release's version ("" = not known)
	Note         string `json:"note,omitempty"`       // the last check's outcome in words
	CheckErr     bool   `json:"checkErr,omitempty"`   // the last check failed
	Installing   string `json:"installing,omitempty"` // version handed to apply.sh, until it reports
	InstallingAt int64  `json:"installingAt,omitempty"`
	// Last: the last install, as apply.sh reported it
	Last *UpdResult `json:"last,omitempty"`
	// Refused: versions that were rolled back or are not ahead of the running build — never tried again
	Refused map[string]string `json:"refused,omitempty"`
	// Told: the version the admin chat last heard about while auto-update was off
	Told string `json:"told,omitempty"`
}

// UpdResult is apply.sh's result file.
type UpdResult struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Result string `json:"result"` // ok | rolled_back | failed
	Note   string `json:"note,omitempty"`
	At     int64  `json:"at"`
}

type updRelease struct {
	Version string
	Bin     updAsset
	Sums    updAsset
}

type updAsset struct {
	Name string `json:"name"`
	URL  string `json:"url"` // API asset URL (fetched with Accept: application/octet-stream)
	Size int64  `json:"size"`
}

var updMu sync.Mutex // one check/install at a time
var updChecking atomic.Bool
var updReport atomic.Bool // this start follows an automatic install: Repair reports to the admin chat

func updDir() string { return filepath.Join(dataDir, "update") }

// autoUpdateLoop runs for the panel's lifetime.
func (a *App) autoUpdateLoop() {
	time.Sleep(updFirst)
	for {
		_, _ = a.autoUpdateCheck()
		time.Sleep(updEvery)
	}
}

func (a *App) updState() AutoUpdate {
	var u AutoUpdate
	a.store.View(func(st *State) {
		if st.AutoUpdate != nil {
			u = *st.AutoUpdate
		}
	})
	return u
}

func (a *App) updSet(fn func(u *AutoUpdate)) {
	_ = a.store.Update(func(st *State) error {
		if st.AutoUpdate == nil {
			st.AutoUpdate = &AutoUpdate{}
		}
		fn(st.AutoUpdate)
		return nil
	})
}

// updCollect reads the result apply.sh left behind (it runs while the panel restarts) and
// reports it once.
func (a *App) updCollect() {
	p := filepath.Join(updDir(), "result.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var r UpdResult
	if json.Unmarshal(b, &r) != nil || r.To == "" {
		_ = os.Remove(p)
		return
	}
	_ = os.Rename(p, p+".seen")
	a.updSet(func(u *AutoUpdate) {
		u.Last, u.Installing = &r, ""
		if r.Result != "ok" {
			u.refuse(r.To, r.Result+": "+r.Note)
		}
	})
	if r.Result == "ok" && r.To == version {
		updReport.Store(true)
	}
	a.push(updMessage(r, a.updAfterWords()))
}

// updAfterWords says what runs after a good update (the existing post-update path).
func (a *App) updAfterWords() string {
	var mode string
	running := 0
	a.store.View(func(st *State) {
		mode = st.RepairAuto
		for _, t := range st.Tunnels {
			if t.Active != "" {
				running++
			}
		}
	})
	switch {
	case running == 0:
		return "No tunnel is running, nothing to re-apply."
	case mode == repairAutoOff:
		return "Automatic Repair is off: open Tunnels → 🛠 Repair to re-apply."
	case mode == repairAutoAll:
		return fmt.Sprintf("In ~4 min Repair checks the %d running tunnel(s) one at a time and re-applies what changed (users may be moved); its report follows.", running)
	}
	return fmt.Sprintf("In ~4 min Repair checks the %d running tunnel(s) one at a time and fixes what cuts nobody by itself; what would move users waits for your OK. Its report follows.", running)
}

// refuse remembers a version that is never tried again (the last 20).
func (u *AutoUpdate) refuse(v, why string) {
	if u.Refused == nil {
		u.Refused = map[string]string{}
	}
	if len(u.Refused) >= 20 {
		u.Refused = map[string]string{}
	}
	u.Refused[v] = why
}

func updMessage(r UpdResult, after string) string {
	switch r.Result {
	case "ok":
		return fmt.Sprintf("⬆️ Panel updated by itself: %s → %s ✅\n%s", r.From, r.To, after)
	case "rolled_back":
		return fmt.Sprintf("⚠️ Panel update %s → %s rolled back: %s\nStill running %s; this version won't be tried again.", r.From, r.To, r.Note, r.From)
	}
	return fmt.Sprintf("❌ Panel update %s → %s failed: %s", r.From, r.To, r.Note)
}

// autoUpdateCheck looks at the release and installs it when it is newer and allowed.
func (a *App) autoUpdateCheck() (string, error) {
	if !updMu.TryLock() {
		return "a check is already running", nil
	}
	defer updMu.Unlock()
	updChecking.Store(true)
	defer updChecking.Store(false)
	a.updCollect() // apply.sh writes its result a minute after the restart
	note, err := a.updCheckOnce()
	a.updSet(func(u *AutoUpdate) {
		u.LastCheck, u.Note, u.CheckErr = time.Now().Unix(), note, err != nil
		if err != nil {
			u.Note = err.Error()
		}
	})
	return note, err
}

func (a *App) updCheckOnce() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	rel, err := updLatest(ctx)
	if err != nil {
		return "", err
	}
	a.updSet(func(u *AutoUpdate) { u.Latest = rel.Version })
	u := a.updState()
	if rel.Version == version {
		return "up to date", nil
	}
	if version == "dev" {
		return "a development build: not updated automatically", nil
	}
	if u.Installing == rel.Version {
		if time.Since(time.Unix(u.InstallingAt, 0)) < 15*time.Minute {
			return "installing " + rel.Version, nil
		}
		why := "the install started but never reported back"
		a.updSet(func(u *AutoUpdate) { u.Installing = ""; u.refuse(rel.Version, why) })
		a.push(fmt.Sprintf("⚠️ Panel update to %s: %s. Still running %s; look at journalctl -u 'tp-selfupdate-*' on the panel host.", rel.Version, why, version))
		return rel.Version + " not installed: " + why, nil
	}
	if why, ok := u.Refused[rel.Version]; ok {
		return rel.Version + " not installed: " + why, nil
	}
	// ahead of the running commit on GitHub? (a stale release run can put an older build on "latest")
	st, err := updCompare(ctx, updCommit(version), updCommit(rel.Version))
	if err != nil {
		return "", fmt.Errorf("compare %s with %s: %w", version, rel.Version, err)
	}
	switch st {
	case "ahead":
	case "identical":
		return "up to date (same commit)", nil
	default:
		why := fmt.Sprintf("its commit is %s of the running one — never a downgrade", st)
		a.updSet(func(u *AutoUpdate) { u.refuse(rel.Version, why) })
		a.push(fmt.Sprintf("⚠️ The release on GitHub (%s) is not newer than this panel (%s): %s. Not installed.", rel.Version, version, why))
		return rel.Version + " not installed: " + why, nil
	}
	if u.Off {
		if u.Told != rel.Version {
			a.updSet(func(u *AutoUpdate) { u.Told = rel.Version })
			a.push(fmt.Sprintf("⬆️ A new panel version is out: %s (running %s). Automatic update is off — turn it on in Settings, or update by hand.", rel.Version, version))
		}
		return rel.Version + " is out; automatic update is off", nil
	}
	if n := a.jobs.runningCount(); n > 0 {
		return fmt.Sprintf("%s is out — waiting: %d job(s) running (apply, repair, benchmark…); tried again in a few minutes", rel.Version, n), nil
	}
	newBin, err := updFetch(ctx, rel)
	if err != nil {
		return "", err
	}
	if n := a.jobs.runningCount(); n > 0 { // one started while downloading
		return fmt.Sprintf("%s downloaded — waiting: %d job(s) running", rel.Version, n), nil
	}
	a.updSet(func(u *AutoUpdate) { u.Installing, u.InstallingAt = rel.Version, time.Now().Unix() })
	if err := updRunApply(newBin, rel.Version); err != nil {
		a.updSet(func(u *AutoUpdate) { u.Installing = "" })
		return "", fmt.Errorf("start the install: %w", err)
	}
	return "installing " + rel.Version + " — the panel restarts", nil
}

// runningCount: jobs in progress, with or without a tunnel (IG and benchmark jobs have none).
func (js *Jobs) runningCount() int {
	js.mu.Lock()
	defer js.mu.Unlock()
	n := 0
	for _, j := range js.m {
		j.mu.Lock()
		if j.Status == "running" {
			n++
		}
		j.mu.Unlock()
	}
	return n
}

// updCommit: "9352e9f-20261113" → "9352e9f".
func updCommit(v string) string {
	c, _, _ := strings.Cut(v, "-")
	return c
}

var updHTTP = &http.Client{Timeout: 3 * time.Minute}

func updGet(ctx context.Context, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "tunnel-panel-update")
	resp, err := updHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

// updLatest reads the latest release: the binary for this arch, SHA256SUMS and VERSION.
func updLatest(ctx context.Context) (*updRelease, error) {
	resp, err := updGet(ctx, updAPI+"/repos/"+updRepo+"/releases/latest", "application/vnd.github+json")
	if err != nil {
		return nil, fmt.Errorf("GitHub release: %w", err)
	}
	defer resp.Body.Close()
	var rel struct {
		Assets []updAsset `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("GitHub release: %w", err)
	}
	out := &updRelease{}
	var ver updAsset
	for _, x := range rel.Assets {
		switch x.Name {
		case "tunnel-panel-" + runtime.GOARCH:
			out.Bin = x
		case "SHA256SUMS":
			out.Sums = x
		case "VERSION":
			ver = x
		}
	}
	if out.Bin.URL == "" || out.Sums.URL == "" {
		return nil, fmt.Errorf("the release has no tunnel-panel-%s or SHA256SUMS", runtime.GOARCH)
	}
	if ver.URL == "" {
		return nil, errors.New("the release has no VERSION file (built before automatic update)")
	}
	b, err := updAssetBytes(ctx, ver, 256)
	if err != nil {
		return nil, err
	}
	out.Version = strings.TrimSpace(string(b))
	if !validVersion(out.Version) {
		return nil, fmt.Errorf("the release's VERSION %q is not a version", out.Version)
	}
	return out, nil
}

// validVersion: "<commit>-<yyyymmdd>" as build.sh stamps it.
func validVersion(v string) bool {
	c, d, ok := strings.Cut(v, "-")
	if !ok || len(c) < 7 || len(c) > 40 || len(d) != 8 {
		return false
	}
	for _, r := range c {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	_, err := strconv.Atoi(d)
	return err == nil
}

func updAssetBytes(ctx context.Context, x updAsset, max int64) ([]byte, error) {
	resp, err := updGet(ctx, x.URL, "application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", x.Name, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", x.Name, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("download %s: larger than %d bytes", x.Name, max)
	}
	return b, nil
}

// updCompare asks GitHub how head relates to base: ahead | behind | diverged | identical.
func updCompare(ctx context.Context, base, head string) (string, error) {
	resp, err := updGet(ctx, fmt.Sprintf("%s/repos/%s/compare/%s...%s", updAPI, updRepo, base, head), "application/vnd.github+json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var c struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&c); err != nil {
		return "", err
	}
	if c.Status == "" {
		return "", errors.New("no status in GitHub's answer")
	}
	return c.Status, nil
}

// sumFor finds name's sha256 in a SHA256SUMS file.
func sumFor(sums, name string) string {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// updFetch downloads the binary into the update folder, checks its sha256 against SHA256SUMS
// and its --version against the release's VERSION, and returns its path.
func updFetch(ctx context.Context, rel *updRelease) (string, error) {
	sb, err := updAssetBytes(ctx, rel.Sums, 64<<10)
	if err != nil {
		return "", err
	}
	want := sumFor(string(sb), rel.Bin.Name)
	if want == "" {
		return "", fmt.Errorf("SHA256SUMS has no line for %s", rel.Bin.Name)
	}
	if err := os.MkdirAll(updDir(), 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(updDir(), "tunnel-panel.new")
	_ = os.Remove(dst)
	resp, err := updGet(ctx, rel.Bin.URL, "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("download %s: %w", rel.Bin.Name, err)
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 512<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("download %s: %w", rel.Bin.Name, err)
	}
	if err := updVerify(dst, n, hex.EncodeToString(h.Sum(nil)), want, rel.Version); err != nil {
		_ = os.Remove(dst)
		return "", err
	}
	return dst, nil
}

// updVerify: size, checksum and the binary's own --version.
func updVerify(path string, size int64, got, want, ver string) error {
	if size < 1<<20 {
		return fmt.Errorf("download is only %d bytes — not installed", size)
	}
	if got != want {
		return fmt.Errorf("sha256 of the download %s… is not the one in SHA256SUMS %s… — not installed", got[:12], want[:12])
	}
	v, err := updVersionOf(path)
	if err != nil {
		return fmt.Errorf("the new build does not run (--version: %v) — not installed", err)
	}
	if v != "tunnel-panel "+ver {
		return fmt.Errorf("the new build says %q, the release says %s — not installed", v, ver)
	}
	return nil
}

// updVersionOf runs a build's --version (a var: tests can't run a Linux binary).
var updVersionOf = func(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	return strings.TrimSpace(string(out)), err
}

// updHealthURL: what apply.sh asks to see the panel up — its own domain, resolved to this
// host (SNI), or plain http on the listen port without a domain.
func updHealthURL(tlsMode, addr string) (url, resolve string) {
	port := "443"
	if i := strings.LastIndex(addr, ":"); i >= 0 && addr[i+1:] != "" {
		port = addr[i+1:]
	}
	switch tlsMode {
	case "":
		return "http://127.0.0.1:" + port + "/", ""
	case "self":
		return "https://127.0.0.1:" + port + "/", ""
	}
	dom, _, _ := strings.Cut(tlsMode, ",")
	dom = strings.TrimSpace(dom)
	return "https://" + dom + ":" + port + "/", dom + ":" + port + ":127.0.0.1"
}

// runApplyUnit writes apply.sh and starts it as its own transient systemd unit: it outlives
// the panel's restart and rolls back without the panel.
func runApplyUnit(newBin, ver string) error {
	script := filepath.Join(updDir(), "apply.sh")
	if err := os.WriteFile(script, []byte(updApplySh), 0o700); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(updDir(), "result.json"))
	url, resolve := updHealthURL(panelTLS, panelAddr)
	unit := "tp-selfupdate-" + strconv.FormatInt(time.Now().Unix(), 10)
	cmd := exec.Command("systemd-run", "--unit="+unit, "--collect", "--quiet",
		"/bin/bash", script, updBin, newBin, version, ver, url, resolve, updDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// updApplySh: apply.sh BIN NEW FROM TO URL RESOLVE DIR. Backs BIN up, swaps NEW in with mv
// (never cp over a running binary), restarts, waits for the panel to answer on URL with the
// new version running and not restarting, else puts the backup back.
const updApplySh = `#!/bin/bash
set -u
BIN=$1 NEW=$2 FROM=$3 TO=$4 URL=$5 RESOLVE=$6 D=$7
SVC=${TP_SVC:-tunnel-panel} PROC=${TP_PROC:-/proc} NAP=${TP_NAP:-1}
PREV=$D/tunnel-panel.prev
log() { echo "apply: $*"; }
result() {
  local n=${2//\"/\'}
  printf '{"from":"%s","to":"%s","result":"%s","note":"%s","at":%s}\n' "$FROM" "$TO" "$1" "$n" "$(date +%s)" > "$D/result.json.tmp" && mv -f "$D/result.json.tmp" "$D/result.json"
  log "$1: $2"
}
ver() { timeout 20 "$1" --version 2>/dev/null | head -1; }
swap() { install -m0755 "$1" "$BIN.new" && mv -f "$BIN.new" "$BIN"; }
healthy() { # the service runs WANT, answers on URL, and does not restart for 20 s
  local want=$1 i code r0 r1 pid ok=0
  for i in $(seq 1 40); do
    sleep $((3*NAP))
    systemctl is-active -q "$SVC" || { ok=0; continue; }
    if [ -n "$RESOLVE" ]; then code=$(curl -sk -o /dev/null -m 8 -w '%{http_code}' --resolve "$RESOLVE" "$URL")
    else code=$(curl -sk -o /dev/null -m 8 -w '%{http_code}' "$URL"); fi
    case "$code" in 2??|3??|401) ok=$((ok+1)) ;; *) ok=0 ;; esac
    [ "$ok" -ge 2 ] && break
  done
  [ "$ok" -ge 2 ] || { echo "the panel did not answer on $URL (last HTTP ${code:-none})"; return 1; }
  r0=$(systemctl show -p NRestarts --value "$SVC"); sleep $((20*NAP)); r1=$(systemctl show -p NRestarts --value "$SVC")
  [ "$r0" = "$r1" ] && systemctl is-active -q "$SVC" || { echo "the panel restarts by itself (crash loop)"; return 1; }
  pid=$(systemctl show -p MainPID --value "$SVC")
  [ "$(ver "$PROC/$pid/exe")" = "tunnel-panel $want" ] || { echo "the running panel is not $want"; return 1; }
  return 0
}
[ "$(ver "$NEW")" = "tunnel-panel $TO" ] || { result failed "the new build does not say $TO"; exit 1; }
[ "$(ver "$BIN")" = "tunnel-panel $FROM" ] || { result failed "the installed build is not $FROM — someone changed it; not touched"; exit 1; }
install -m0755 "$BIN" "$PREV.tmp" && mv -f "$PREV.tmp" "$PREV" || { result failed "could not back up $BIN"; exit 1; }
[ "$(ver "$PREV")" = "tunnel-panel $FROM" ] || { result failed "the backup does not run"; exit 1; }
swap "$NEW" || { result failed "could not put the new build in place"; exit 1; }
log "installed $TO, restarting $SVC"
systemctl restart "$SVC"
if why=$(healthy "$TO"); then
  rm -f "$NEW"
  result ok "$TO runs and answers on $URL"
  exit 0
fi
log "unhealthy: $why — rolling back to $FROM"
swap "$PREV" && systemctl restart "$SVC"
if healthy "$FROM" >/dev/null; then result rolled_back "$why"
else result rolled_back "$why; and the old build $FROM did not come back cleanly either — look at the server"; fi
exit 1
`

// autoUpdateH: GET → the running version and what the automatic update last saw and did.
func (s *Server2) autoUpdateH(w http.ResponseWriter, r *http.Request) {
	u := s.app.updState()
	writeJSON(w, map[string]any{"current": version, "off": u.Off, "lastCheck": u.LastCheck, "latest": u.Latest,
		"note": u.Note, "checkErr": u.CheckErr, "installing": u.Installing, "last": u.Last,
		"checking": updChecking.Load(), "every": int(updEvery / time.Minute)})
}

// autoUpdateSetH: POST {Off} turns the automatic update off or on (on by default).
func (s *Server2) autoUpdateSetH(w http.ResponseWriter, r *http.Request) {
	var in struct{ Off bool }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	s.app.updSet(func(u *AutoUpdate) { u.Off = in.Off; u.Told = "" })
	s.autoUpdateH(w, r)
}

// autoUpdateCheckH: POST → check now (in the background; GET /api/autoupdate follows it).
func (s *Server2) autoUpdateCheckH(w http.ResponseWriter, r *http.Request) {
	go func() { _, _ = s.app.autoUpdateCheck() }()
	writeJSON(w, map[string]bool{"started": true})
}
