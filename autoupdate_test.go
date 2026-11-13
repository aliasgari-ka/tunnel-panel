package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUpdHelpers(t *testing.T) {
	if !validVersion("9352e9f-20261113") || validVersion("dev") || validVersion("zzzzzzz-20261113") || validVersion("9352e9f-2026") {
		t.Fatal("validVersion")
	}
	if updCommit("9352e9f-20261113") != "9352e9f" {
		t.Fatal("updCommit")
	}
	sums := "aa  other\n" + strings.Repeat("ab", 32) + "  tunnel-panel-amd64\n" + strings.Repeat("cd", 32) + " *VERSION\n"
	if sumFor(sums, "tunnel-panel-amd64") != strings.Repeat("ab", 32) || sumFor(sums, "VERSION") != strings.Repeat("cd", 32) || sumFor(sums, "x") != "" {
		t.Fatal("sumFor")
	}
	u, r := updHealthURL("tunnelpanel.unlimiteddev.co,152-53-86-103.sslip.io", "0.0.0.0:443")
	if u != "https://tunnelpanel.unlimiteddev.co:443/" || r != "tunnelpanel.unlimiteddev.co:443:127.0.0.1" {
		t.Fatal("health url (domain, SNI):", u, r)
	}
	if u, r := updHealthURL("", "0.0.0.0:8088"); u != "http://127.0.0.1:8088/" || r != "" {
		t.Fatal("health url (http):", u, r)
	}
}

// fakeGitHub serves releases/latest, its assets and compare like the GitHub API.
type fakeGitHub struct {
	mu      sync.Mutex
	ver     string
	bin     []byte
	sum     string // "" = the binary's real sha256
	compare string
	calls   []string
}

func (f *fakeGitHub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.URL.Path)
		base := "http://" + r.Host
		name := "tunnel-panel-" + runtime.GOARCH
		switch {
		case r.URL.Path == "/repos/"+updRepo+"/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{"assets": []map[string]any{
				{"name": name, "url": base + "/a/bin"}, {"name": "SHA256SUMS", "url": base + "/a/sums"}, {"name": "VERSION", "url": base + "/a/ver"}}})
		case r.URL.Path == "/a/ver":
			fmt.Fprintln(w, f.ver)
		case r.URL.Path == "/a/sums":
			s := f.sum
			if s == "" {
				h := sha256.Sum256(f.bin)
				s = hex.EncodeToString(h[:])
			}
			fmt.Fprintf(w, "%s  %s\n", s, name)
		case r.URL.Path == "/a/bin":
			if r.Header.Get("Accept") != "application/octet-stream" {
				t.Error("asset fetched without Accept: application/octet-stream")
			}
			_, _ = w.Write(f.bin)
		case strings.HasPrefix(r.URL.Path, "/repos/"+updRepo+"/compare/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"status": f.compare})
		default:
			http.NotFound(w, r)
		}
	})
}

func updTestApp(t *testing.T, gh *fakeGitHub) (*App, *[]string, *[]string) {
	t.Helper()
	dir := t.TempDir()
	st, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldData, oldAPI, oldVer, oldRun, oldVerOf := dataDir, updAPI, version, updRunApply, updVersionOf
	t.Cleanup(func() {
		dataDir, updAPI, version, updRunApply, updVersionOf = oldData, oldAPI, oldVer, oldRun, oldVerOf
	})
	srv := httptest.NewServer(gh.handler(t))
	t.Cleanup(srv.Close)
	dataDir, updAPI, version = dir, srv.URL, "1111111-20261113"
	var mu sync.Mutex
	var pushed, installs []string
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	a.notify = func(m string) { mu.Lock(); pushed = append(pushed, m); mu.Unlock() }
	updRunApply = func(bin, v string) error { installs = append(installs, v+" "+bin); return nil }
	updVersionOf = func(p string) (string, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return "tunnel-panel " + strings.TrimSpace(string(b[:strings.IndexByte(string(b), '\n')])), nil
	}
	return a, &pushed, &installs
}

func fakeBin(ver string) []byte { return append([]byte(ver+"\n"), make([]byte, 2<<20)...) }

func TestAutoUpdateInstallsNewer(t *testing.T) {
	gh := &fakeGitHub{ver: "2222222-20261114", bin: fakeBin("2222222-20261114"), compare: "ahead"}
	a, _, installs := updTestApp(t, gh)
	note, err := a.autoUpdateCheck()
	if err != nil || len(*installs) != 1 || !strings.HasPrefix((*installs)[0], "2222222-20261114 ") {
		t.Fatalf("note=%q err=%v installs=%v", note, err, *installs)
	}
	u := a.updState()
	if u.Installing != "2222222-20261114" || u.Latest != "2222222-20261114" || u.LastCheck == 0 {
		t.Fatalf("state %+v", u)
	}
	// while it installs, the next check doesn't start a second install
	if _, err := a.autoUpdateCheck(); err != nil || len(*installs) != 1 {
		t.Fatal("second install started", *installs)
	}
}

func TestAutoUpdateNeverDowngrades(t *testing.T) {
	for _, st := range []string{"behind", "diverged"} {
		gh := &fakeGitHub{ver: "0000000-20261101", bin: fakeBin("0000000-20261101"), compare: st}
		a, pushed, installs := updTestApp(t, gh)
		note, _ := a.autoUpdateCheck()
		if len(*installs) != 0 || !strings.Contains(note, "never a downgrade") {
			t.Fatalf("%s: note=%q installs=%v", st, note, *installs)
		}
		if _, ok := a.updState().Refused["0000000-20261101"]; !ok {
			t.Fatal("not remembered as refused")
		}
		_, _ = a.autoUpdateCheck() // no second message, no compare call again
		waitPushed(t, pushed, 1)
	}
}

func waitPushed(t *testing.T, pushed *[]string, n int) {
	t.Helper()
	for i := 0; i < 200; i++ { // push is async
		if len(*pushed) >= n {
			break
		}
		testSleep()
	}
	testSleep()
	if len(*pushed) != n {
		t.Fatalf("pushed %d messages, want %d: %q", len(*pushed), n, *pushed)
	}
}

func TestAutoUpdateChecksum(t *testing.T) {
	gh := &fakeGitHub{ver: "2222222-20261114", bin: fakeBin("2222222-20261114"), compare: "ahead", sum: strings.Repeat("0", 64)}
	a, _, installs := updTestApp(t, gh)
	if _, err := a.autoUpdateCheck(); err == nil || !strings.Contains(err.Error(), "sha256") || len(*installs) != 0 {
		t.Fatalf("err=%v installs=%v", err, *installs)
	}
	if _, err := os.Stat(filepath.Join(updDir(), "tunnel-panel.new")); err == nil {
		t.Fatal("a bad download was left behind")
	}
	// a binary that says another version than the release
	gh.sum, gh.bin = "", fakeBin("3333333-20261114")
	if _, err := a.autoUpdateCheck(); err == nil || !strings.Contains(err.Error(), "says") || len(*installs) != 0 {
		t.Fatalf("version mismatch: err=%v", err)
	}
	// an empty upload
	gh.bin = []byte("2222222-20261114\n")
	if _, err := a.autoUpdateCheck(); err == nil || !strings.Contains(err.Error(), "only") {
		t.Fatalf("tiny download: err=%v", err)
	}
}

func TestAutoUpdateWaitsForJobsAndOff(t *testing.T) {
	gh := &fakeGitHub{ver: "2222222-20261114", bin: fakeBin("2222222-20261114"), compare: "ahead"}
	a, pushed, installs := updTestApp(t, gh)
	j, _ := a.jobs.start("", "igproxy") // a job without a tunnel counts too
	note, _ := a.autoUpdateCheck()
	if len(*installs) != 0 || !strings.Contains(note, "waiting") {
		t.Fatalf("installed during a job: %q", note)
	}
	j.finish("ok")
	a.jobs.done(j)
	a.updSet(func(u *AutoUpdate) { u.Off = true })
	note, _ = a.autoUpdateCheck()
	_, _ = a.autoUpdateCheck()
	if len(*installs) != 0 || !strings.Contains(note, "off") {
		t.Fatalf("installed while off: %q", note)
	}
	waitPushed(t, pushed, 1) // told once
	a.updSet(func(u *AutoUpdate) { u.Off = false })
	if _, _ = a.autoUpdateCheck(); len(*installs) != 1 {
		t.Fatal("not installed once on again")
	}
}

func TestUpdCollectReportsOnce(t *testing.T) {
	gh := &fakeGitHub{}
	a, pushed, _ := updTestApp(t, gh)
	_ = os.MkdirAll(updDir(), 0o700)
	r := UpdResult{From: "1111111-20261113", To: "2222222-20261114", Result: "rolled_back", Note: "the panel did not answer", At: 1}
	b, _ := json.Marshal(r)
	_ = os.WriteFile(filepath.Join(updDir(), "result.json"), b, 0o600)
	a.updCollect()
	a.updCollect()
	waitPushed(t, pushed, 1)
	if !strings.Contains((*pushed)[0], "rolled back") || a.updState().Refused["2222222-20261114"] == "" {
		t.Fatalf("%q %+v", *pushed, a.updState())
	}
}

// apply.sh with stub systemctl/curl: a good build stays, a build that doesn't answer is
// rolled back (the backup goes back with mv, never cp over the running binary).
func TestApplyScript(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil || runtime.GOOS == "windows" {
		t.Skip("needs bash on Linux")
	}
	for _, tc := range []struct {
		name, newAnswers, want, installed string
	}{
		{"healthy", "200", "ok", "NEW"},
		{"unhealthy", "000", "rolled_back", "OLD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			stub := filepath.Join(d, "stub")
			_ = os.MkdirAll(stub, 0o755)
			bin, upd := filepath.Join(d, "tunnel-panel"), filepath.Join(d, "upd")
			_ = os.MkdirAll(upd, 0o700)
			mk := func(p, s string) { _ = os.WriteFile(p, []byte("#!/bin/bash\n"+s+"\n"), 0o755) }
			mk(bin, `echo "tunnel-panel 1111111-20261113"; # OLD`)
			mk(filepath.Join(upd, "tunnel-panel.new"), `echo "tunnel-panel 2222222-20261114"; # NEW`)
			// systemctl: active, no restarts, pid 1; curl: 200 for the new build, tc's answer otherwise
			mk(filepath.Join(stub, "systemctl"), `case "$1" in show) case "$3" in NRestarts) echo 0;; MainPID) echo 1;; esac;; esac; exit 0`)
			mk(filepath.Join(stub, "curl"), `if grep -q NEW "`+bin+`"; then echo -n `+tc.newAnswers+`; else echo -n 200; fi`)
			_ = os.MkdirAll(filepath.Join(d, "proc", "1"), 0o755)
			mk(filepath.Join(d, "proc", "1", "exe"), `exec "`+bin+`" "$@"`)
			script := filepath.Join(d, "apply.sh")
			_ = os.WriteFile(script, []byte(updApplySh), 0o700)
			cmd := exec.Command(bash, script, bin, filepath.Join(upd, "tunnel-panel.new"), "1111111-20261113", "2222222-20261114",
				"https://p.example:443/", "p.example:443:127.0.0.1", upd)
			cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"), "TP_PROC="+filepath.Join(d, "proc"), "TP_NAP=0")
			out, _ := cmd.CombinedOutput()
			b, err := os.ReadFile(filepath.Join(upd, "result.json"))
			if err != nil {
				t.Fatalf("no result: %v\n%s", err, out)
			}
			var r UpdResult
			if err := json.Unmarshal(b, &r); err != nil || r.Result != tc.want {
				t.Fatalf("result %s (%v)\n%s", b, err, out)
			}
			cur, _ := os.ReadFile(bin)
			if !strings.Contains(string(cur), tc.installed) {
				t.Fatalf("installed binary is not %s:\n%s\n%s", tc.installed, cur, out)
			}
			if prev, _ := os.ReadFile(filepath.Join(upd, "tunnel-panel.prev")); !strings.Contains(string(prev), "OLD") {
				t.Fatal("no backup of the old build")
			}
		})
	}
}

func testSleep() { time.Sleep(10 * time.Millisecond) }
