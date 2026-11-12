package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func hsRemoveFixture(t *testing.T) (*App, *Store) {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1", Role: "iran"},
			{ID: "kh1", Name: "uk", IPv4: "198.51.100.1", Role: "foreign"},
			{ID: "ir2", Name: "ali-ir", IPv4: "192.0.2.2", Role: "iran", Owner: "ali"},
			{ID: "kh2", Name: "ali-de", IPv4: "198.51.100.2", Role: "foreign", Owner: "ali"},
		}
		s.Tunnels = []*Tunnel{
			{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1,
				Active: "gre", Selected: "gre", HotStandby: true, Paths: []HSPath{
					{Method: "gre", Family: "v4", Index: 1},
					{Method: "bp_reverse", Family: "v4", Index: 2},
					{Method: "paqet", Family: "v4", Index: 3},
					{Method: "direct6", Family: "v6", Index: 4, Failed: "refused", FailedAt: time.Now().Unix()},
				}},
			{ID: "bbbbbbbbbbbb", Name: "one", ServerID: "ir2", ForeignID: "kh2", Family: "v4", Ports: "8443", Index: 5, Owner: "ali",
				Active: "gre", HotStandby: true, Paths: []HSPath{
					{Method: "gre", Family: "v4", Index: 5},
					{Method: "paqet", Family: "v4", Index: 6, Failed: "refused", FailedAt: time.Now().Unix()},
				}},
		}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon(), hsViews: map[string]*hsView{}}
	// the switcher has the users on BackPack reverse
	a.hsViews["aaaaaaaaaaaa"] = &hsView{Active: 1, Keys: []string{"gre|v4", "bp_reverse|v4", "paqet|v4"}, Paths: []string{"GRE (v4)", "BackPack reverse (v4)", "Paqet (v4)"}, OK: []bool{true, true, true}}
	return a, st
}

func hsWaitJob(t *testing.T, j *Job) {
	t.Helper()
	for end := time.Now().Add(2 * time.Minute); j.snapshot().Status == "running"; {
		if time.Now().After(end) {
			t.Fatal("job still running")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A path removed from the card goes on the tunnel's own list and stays out of everything
// automatic: the plan, Repair's diff and the hourly retry. The users' path and the last
// working one can't be removed; "put back" lets it in again.
func TestHSRemovePath(t *testing.T) {
	a, st := hsRemoveFixture(t)
	tun := st.Tunnel("aaaaaaaaaaaa")

	// the users' path: refused, nothing recorded
	if _, err := a.hsRemovePath(tun, "bp_reverse", "v4"); err == nil || !strings.Contains(err.Error(), "users are on") {
		t.Fatalf("removing the users' path: %v", err)
	}
	// a path that isn't on the tunnel
	if _, err := a.hsRemovePath(tun, "wg", "v4"); err == nil {
		t.Fatal("removed a path the tunnel doesn't have")
	}
	st.View(func(*State) {
		if len(tun.HSOff) != 0 {
			t.Fatalf("a refused removal was recorded: %v", tun.HSOff)
		}
	})

	// Paqet is idle: removed (the job can't reach the test servers, the choice stays anyway)
	j, err := a.hsRemovePath(tun, "paqet", "v4")
	if err != nil || j == nil || j.snapshot().Kind != "paths" {
		t.Fatalf("remove paqet: %v %v", j, err)
	}
	if _, err := a.hsRemovePath(tun, "gre", "v4"); err == nil {
		t.Fatal("a second removal ran while the first job holds the tunnel")
	}
	hsWaitJob(t, j)
	st.View(func(*State) {
		if !contains(tun.HSOff, "paqet|v4") {
			t.Fatalf("HSOff = %v, want paqet|v4", tun.HSOff)
		}
	})
	if !a.hsExcluded(tun, "paqet", "v4") || a.hsExcluded(tun, "paqet", "v6") || a.hsExcluded(tun, "gre", "v4") {
		t.Fatal("hsExcluded doesn't follow the tunnel's list (method and family)")
	}
	if a.hsCandidate(tun, methodByID["paqet"], "v4") {
		t.Fatal("a removed path is still a candidate for auto mode")
	}
	// Repair's diff takes it out and never adds it back
	drop, add := a.hsPathDiff(tun)
	for _, p := range add {
		if p.Method == "paqet" && p.Family == "v4" {
			t.Fatal("Repair would add the removed path back")
		}
	}
	gone := false
	for _, p := range drop {
		gone = gone || (p.Method == "paqet" && p.Family == "v4")
	}
	if !gone {
		t.Fatalf("Repair's diff keeps the removed path: drop %v", drop)
	}
	// a plan (Start / Re-apply) leaves it out
	for _, p := range a.hsPlan(tun, "gre", "v4") {
		if p.Method == "paqet" && p.Family == "v4" {
			t.Fatal("hsPlan put the removed path back")
		}
	}
	// the hourly retry of a failed path skips a removed one
	_ = st.Update(func(*State) error {
		tun.Paths = append(tun.Paths, HSPath{Method: "paqet", Family: "v4", Index: 9, Failed: "x", FailedAt: 1})
		return nil
	})
	for _, p := range a.hsRetryDue(tun, time.Now()) {
		if p.Method == "paqet" {
			t.Fatal("the retry would bring the removed path back")
		}
	}

	// put back: off the list, a candidate again (the tunnel is busy-free; its job fails on the test servers)
	j, err = a.hsRestorePath(tun, "paqet", "v4")
	if err != nil {
		t.Fatalf("put back: %v", err)
	}
	if j != nil {
		hsWaitJob(t, j)
	}
	if a.hsExcluded(tun, "paqet", "v4") || !a.hsCandidate(tun, methodByID["paqet"], "v4") {
		t.Fatal("put back didn't allow the path again")
	}
	if _, err := a.hsRestorePath(tun, "paqet", "v4"); err == nil {
		t.Fatal("put back of a path that isn't removed")
	}

	// a hand-picked Apply of a removed path wants it again
	_ = st.Update(func(*State) error { tun.HSOff = []string{"wg|v4"}; return nil })
	a.hsUnremove(tun, "wg", "v4")
	if a.hsExcluded(tun, "wg", "v4") {
		t.Fatal("hsUnremove left it on the list")
	}
}

// The last working path can't go; a failed path next to it can.
func TestHSRemoveLastWorking(t *testing.T) {
	a, st := hsRemoveFixture(t)
	one := st.Tunnel("bbbbbbbbbbbb")
	// the users' GRE is down, BackPack is the one path still answering
	_ = st.Update(func(*State) error {
		one.Paths = append(one.Paths, HSPath{Method: "bp_reverse", Family: "v4", Index: 7})
		return nil
	})
	a.hsViews["bbbbbbbbbbbb"] = &hsView{Active: 0, Keys: []string{"gre|v4", "bp_reverse|v4"}, OK: []bool{false, true}}
	if _, err := a.hsRemovePath(one, "bp_reverse", "v4"); err == nil || !strings.Contains(err.Error(), "last working path") {
		t.Fatalf("removing the last working path: %v", err)
	}
	j, err := a.hsRemovePath(one, "paqet", "v4")
	if err != nil {
		t.Fatalf("removing a failed path: %v", err)
	}
	hsWaitJob(t, j)
	st.View(func(*State) {
		if !contains(one.HSOff, "paqet|v4") {
			t.Fatalf("HSOff = %v", one.HSOff)
		}
	})
	// only one path deployed at all: the last working path
	_ = st.Update(func(*State) error {
		one.Paths = one.Paths[:1]
		return nil
	})
	a.hsViews["bbbbbbbbbbbb"] = &hsView{Active: -1, Keys: []string{"gre|v4"}, OK: []bool{true}}
	if _, err := a.hsRemovePath(one, "gre", "v4"); err == nil {
		t.Fatalf("removed the only deployed path")
	}
	// no switcher view yet: the tunnel's own path counts as the users'
	a.hsViews = map[string]*hsView{}
	_ = st.Update(func(*State) error {
		one.Paths = append(one.Paths, HSPath{Method: "bp_reverse", Family: "v4", Index: 7})
		return nil
	})
	if _, err := a.hsRemovePath(one, "gre", "v4"); err == nil || !strings.Contains(err.Error(), "users are on") {
		t.Fatalf("without a switcher view the tunnel's own path is the users': %v", err)
	}
}

// A user removes paths only on their own tunnels; the admin's tunnel answers "not found".
func TestHSRemovePermissions(t *testing.T) {
	a, _ := hsRemoveFixture(t)
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"ali","password":"password1"}`)))
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			c = k
		}
	}
	mux := a.routes()
	call := func(method, path, body string) (int, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(c)
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	for _, p := range []string{"/api/tunnels/hsremove", "/api/tunnels/hsrestore"} {
		if code, body := call("POST", p, `{"ID":"aaaaaaaaaaaa","Path":"paqet|v4"}`); code != 404 {
			t.Errorf("%s on the admin's tunnel: %d %s", p, code, body)
		}
		if code, _ := call("GET", p+"?id=bbbbbbbbbbbb", ""); code == 200 {
			t.Errorf("%s answered a GET", p)
		}
	}
	// their own tunnel: the rules apply (the last working path), not a permission error
	if code, body := call("POST", "/api/tunnels/hsremove", `{"ID":"bbbbbbbbbbbb","Path":"gre|v4"}`); code != 409 || !strings.Contains(body, "users are on") && !strings.Contains(body, "last working") {
		t.Errorf("own tunnel, users' path: %d %s", code, body)
	}
	if code, body := call("POST", "/api/tunnels/hsremove", `{"ID":"bbbbbbbbbbbb","Path":"nope|v4"}`); code != 400 {
		t.Errorf("bad path: %d %s", code, body)
	}
	st := a.store
	if code, body := call("POST", "/api/tunnels/hsremove", `{"ID":"bbbbbbbbbbbb","Path":"paqet|v4"}`); code != 200 || !strings.Contains(body, "job") {
		t.Errorf("own tunnel, failed path: %d %s", code, body)
	}
	for end := time.Now().Add(2 * time.Minute); a.jobs.running("bbbbbbbbbbbb") != "" && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	own := st.Tunnel("bbbbbbbbbbbb")
	st.View(func(*State) {
		if !contains(own.HSOff, "paqet|v4") {
			t.Error("the user's removal wasn't recorded")
		}
	})
}
