package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A user's benchmark runs only on its own pair: the guard also takes "iran"/"foreign", and
// with those the handler saw foreignId "" = the panel host.
func TestBenchStartOwnPairOnly(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s2", Name: "ali-iran", IPv4: "192.0.2.2", Role: "iran", Owner: "ali"},
			{ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
		}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"ali","password":"password1"}`)))
	var ali *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			ali = k
		}
	}
	for _, body := range []string{`{"iranId":"s2","foreign":"s3"}`, `{"iranId":"s2","foreignId":""}`, `{"iran":"s2","foreign":"s3"}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/bench/start", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(ali)
		s.guard("pair", s.benchStart)(w, r)
		if w.Code != 404 {
			t.Errorf("%s: %d %s, want 404 (no benchmark on the panel host)", body, w.Code, w.Body.String())
		}
	}
}

// The admin's IG backup folder is a name no account can take, a renamed account takes its
// backups along, and a new account of an old name does not get the old one's.
func TestIgBackupFolders(t *testing.T) {
	dataDir = t.TempDir()
	root := filepath.Join(dataDir, "igproxy-backup")
	_ = os.MkdirAll(filepath.Join(root, "_admin"), 0o700)
	_ = os.WriteFile(filepath.Join(root, "_admin", "a1-old.igpx"), []byte("x"), 0o600)
	if _, err := os.Stat(filepath.Join(igBackupDir(""), "a1-old.igpx")); err != nil {
		t.Fatalf("the old _admin folder was not taken over: %v", err)
	}
	for _, u := range []string{"_admin", "#admin", ".", "..", "...", "a|b", ""} {
		if validUsername(u) && igBackupDir(u) == igBackupDir("") {
			t.Errorf("account %q gets the admin's backup folder", u)
		}
		if u != "_admin" && validUsername(u) {
			t.Errorf("%q is accepted as a username", u)
		}
	}
	_ = os.MkdirAll(igBackupDir("ali"), 0o700)
	_ = os.WriteFile(filepath.Join(igBackupDir("ali"), "u1-x.igpx"), []byte("x"), 0o600)
	_ = os.MkdirAll(igBackupDir("ali2"), 0o700) // an older account's leftovers
	_ = os.WriteFile(filepath.Join(igBackupDir("ali2"), "u9-other.igpx"), []byte("x"), 0o600)
	igBackupMove("ali", "ali2")
	if got := igBackups([]string{"ali2"}); len(got) != 1 || got[0].File != "u1-x.igpx" {
		t.Fatalf("after the rename ali2 has %v, want only its own u1-x.igpx", got)
	}
	if got := igBackups([]string{"ali"}); len(got) != 0 {
		t.Fatalf("the old name still has backups: %v", got)
	}
	igBackupRetire("ali2")
	if got := igBackups([]string{"ali2"}); len(got) != 0 {
		t.Fatalf("a deleted account's backups stay under its name: %v", got)
	}
}

// A deleted account's cookie does not work for a new account of the same name.
func TestSessionNotRevivedByNewAccount(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	login := func(u string) *http.Cookie {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+u+`","password":"password1"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return k
			}
		}
		t.Fatalf("no session for %s", u)
		return nil
	}
	boss := login("boss")
	call := func(h http.HandlerFunc, body string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
		r.AddCookie(boss)
		h(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	who := func(c *http.Cookie) string {
		r := httptest.NewRequest("GET", "/x", nil)
		r.AddCookie(c)
		u, _ := s.who(r)
		return u
	}
	call(s.users, `{"Username":"bob","Password":"password1","Role":"user"}`)
	old := login("bob")
	call(s.userDelete, `{"Username":"bob"}`)
	call(s.users, `{"Username":"bob","Password":"password1","Role":"user"}`)
	if u := who(old); u != "" {
		t.Fatalf("the deleted account's cookie works for the new bob (user %q)", u)
	}
	if u := who(login("bob")); u != "bob" {
		t.Fatalf("the new bob's own cookie: user %q", u)
	}
}

// Parallel wrong sign-ins are counted before the password check: no more than 5 get one.
func TestLoginLimitParallel(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}}
		return nil
	})
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub()}, failures: map[string][]time.Time{}}
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"wrong-guess"}`)))
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[401] > 5 {
		t.Fatalf("%d passwords were checked in a burst (limit 5): %v", codes[401], codes)
	}
	// a right password after a wrong one still works, and does not use up the limit
	s2 := &Server2{app: s.app, failures: map[string][]time.Time{}}
	for i := 0; i < 8; i++ {
		w := httptest.NewRecorder()
		s2.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"boss","password":"password1"}`)))
		if w.Code != 200 {
			t.Fatalf("right password #%d: %d", i+1, w.Code)
		}
	}
}

// A backup with no accounts gets a setup code, so the first account can be made again.
func TestRestoreNoAccountsSetupCode(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	if _, err := a.restoreBackup([]byte(`{"secret":"x","servers":[{"id":"s1","name":"a"}]}`)); err != nil {
		t.Fatal(err)
	}
	code := ""
	st.View(func(s *State) { code = s.SetupCode })
	if code == "" {
		t.Fatal("restored without accounts and without a setup code: nobody can sign in")
	}
}

// A journal line later in the same second as the last one read is not lost.
func TestIgLogParseSameSecond(t *testing.T) {
	out := "1730800000.100000 h igproxy[1]: first\n1730800000.900000 h igproxy[1]: second\n1730800001.5 h igproxy[1]: third\n"
	ts, ms := igLogParse(out, 1730800000100000)
	if len(ms) != 2 || ms[0] != "second" || ms[1] != "third" || ts[1] != 1730800001500000 {
		t.Fatalf("got %v %v", ts, ms)
	}
}
