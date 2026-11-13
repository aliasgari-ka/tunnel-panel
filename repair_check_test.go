package main

// Repair's check and apply (repair.go) against a fake server: the check only reads, the apply
// does only what was chosen, an item that moves users waits for an explicit OK, and an account
// sees and repairs only its own tunnels.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// repairFake answers like a server where tp-brk.service failed and every tunnel's units lack
// the memory drop-in; it records what it was asked to run or write.
type repairFake struct {
	mu      sync.Mutex
	scripts []string
	writes  []string
}

var unitRe = regexp.MustCompile(`tp-[a-z0-9]+\.service`)

func (f *repairFake) Label() string { return "fake" }
func (f *repairFake) WriteFile(path string, _ []byte, _ os.FileMode) error {
	f.mu.Lock()
	f.writes = append(f.writes, path)
	f.mu.Unlock()
	return nil
}
func (f *repairFake) Run(_ context.Context, script string, _ func(string)) (string, error) {
	f.mu.Lock()
	f.scripts = append(f.scripts, script)
	f.mu.Unlock()
	switch {
	case strings.Contains(script, "MEMNEED"):
		return "MEMNEED " + strings.Join(unitRe.FindAllString(script, -1), " ") + "\n", nil
	case strings.Contains(script, "MEMTUNED"):
		u := unitRe.FindAllString(script, -1)
		return "MEMTUNED " + strings.Join(u[:1], " ") + "\nMEMRESTARTED\n", nil
	case strings.Contains(script, "is-active"):
		out := "active\n"
		if strings.Contains(script, "is-active tp-brk.service") {
			out = "failed\n"
		}
		if strings.Contains(script, "LINK") { // the Iran side's link check
			out += "LINK up\n"
		}
		return out, nil
	}
	return "", nil
}

func (f *repairFake) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scripts...)
}

func repairTestApp(t *testing.T) (*App, *repairFake) {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "192.0.2.1", Role: "iran"}, {ID: "kh", Name: "de", IPv4: "198.51.100.2", Role: "foreign"}}
		mk := func(id, owner string) *Tunnel {
			return &Tunnel{ID: id, Name: id, ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Active: "gre", Owner: owner,
				Options: map[string]map[string]string{}, Secrets: map[string]string{}}
		}
		s.Tunnels = []*Tunnel{mk("mem", ""), mk("brk", ""), mk("alis", "ali"), {ID: "off", Name: "off", ServerID: "ir", ForeignID: "kh"}}
		return nil
	})
	f := &repairFake{}
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon(), hostFor: func(*Server) Host { return f }}
	return a, f
}

func stateJSON(a *App) string {
	var b []byte
	a.store.View(func(st *State) { b, _ = json.Marshal(st) })
	return string(b)
}

func TestRepairCheckChangesNothing(t *testing.T) {
	a, f := repairTestApp(t)
	before := stateJSON(a)
	res := a.repairCheckAll(context.Background(), a.runningTunnels(nil))
	if got := stateJSON(a); got != before {
		t.Errorf("the check changed the state")
	}
	if len(f.writes) > 0 {
		t.Errorf("the check wrote files: %v", f.writes)
	}
	for _, s := range f.ran() {
		for _, bad := range []string{"systemctl restart", "mkdir", "daemon-reload", "> \"$f", "rm "} {
			if strings.Contains(s, bad) {
				t.Errorf("the check ran %q:\n%s", bad, s)
			}
		}
	}
	a.jobs.mu.Lock()
	n := len(a.jobs.m)
	a.jobs.mu.Unlock()
	if n != 0 {
		t.Errorf("the check started %d job(s)", n)
	}
	by := map[string]*RepairTunnel{}
	for _, r := range res {
		by[r.ID] = r
	}
	if len(res) != 3 || by["off"] != nil {
		t.Fatalf("running tunnels: got %d %v", len(res), by)
	}
	// impact flags
	if m := by["mem"]; m.State != "fix" || len(m.Items) != 1 || m.Items[0].Kind != rkMemory || m.Items[0].Impact != impNone || m.Items[0].Side != "both" {
		t.Errorf("mem: %+v", m)
	}
	if b := by["brk"]; b.State != "fix" || len(b.Items) != 1 || b.Items[0].Kind != rkReapply || b.Items[0].Impact != impUsers || b.Items[0].Side != "iran" ||
		!strings.Contains(b.Items[0].Text, "tp-brk.service failed") {
		t.Errorf("brk: %+v", b)
	}
}

func waitRepairJob(t *testing.T, j *Job) {
	t.Helper()
	for i := 0; j.snapshot().Status == "running"; i++ {
		if i > 300 {
			t.Fatal("job never ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRepairAppliesOnlyChosen(t *testing.T) {
	a, f := repairTestApp(t)
	// mem's memory fix chosen; brk's re-apply chosen but not confirmed; alis not chosen
	j, err := a.RepairPicked("test", "boss", map[string][]string{"mem": {rkMemory}, "brk": {rkReapply}}, false)
	if err != nil {
		t.Fatal(err)
	}
	waitRepairJob(t, j)
	var tuned []string
	for _, s := range f.ran() {
		if strings.Contains(s, "MEMTUNED") {
			tuned = append(tuned, unitRe.FindAllString(s, -1)...)
		}
	}
	if len(tuned) == 0 {
		t.Fatal("the chosen memory fix did not run")
	}
	for _, u := range tuned {
		if u != "tp-mem.service" {
			t.Errorf("memory fix ran on %s, which was not chosen", u)
		}
	}
	var last *RepairRun
	a.store.View(func(st *State) { last = st.LastRepair })
	if last == nil || len(last.Tunnels) != 2 {
		t.Fatalf("last run: %+v", last)
	}
	for _, x := range last.Tunnels {
		switch x.ID {
		case "mem":
			if x.Result != "fixed" {
				t.Errorf("mem: %s %s", x.Result, x.Done)
			}
		case "brk":
			if x.Result != "skipped" || !strings.Contains(x.Done, "needs your OK") {
				t.Errorf("brk without the OK: %s %s", x.Result, x.Done)
			}
		default:
			t.Errorf("%s was not chosen but is in the run", x.ID)
		}
	}
	if a.jobs.running("brk") != "" {
		t.Error("brk is being applied again without the OK")
	}
}

func TestRepairAutoSafe(t *testing.T) {
	for _, c := range []struct {
		mode, imp string
		ok        bool
	}{{"", impNone, true}, {"", impBlip, true}, {"", impUsers, false}, {"all", impUsers, true}} {
		if ok, _ := repairAutoAllows(c.mode, RepairItem{Impact: c.imp}); ok != c.ok {
			t.Errorf("mode %q impact %s: %v", c.mode, c.imp, ok)
		}
	}
	if ok, _ := repairPickAllows([]string{rkReapply}, true, RepairItem{Kind: rkReapply, Impact: impUsers}); !ok {
		t.Error("a confirmed re-apply was refused")
	}
	if ok, _ := repairPickAllows([]string{rkMemory}, true, RepairItem{Kind: rkSwitcher, Impact: impBlip}); ok {
		t.Error("an item that was not chosen ran")
	}
}

func TestRepairAccess(t *testing.T) {
	a, _ := repairTestApp(t)
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	login := func(u string) *http.Cookie {
		w := httptest.NewRecorder()
		s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"`+u+`","password":"password1"}`)))
		for _, k := range w.Result().Cookies() {
			if k.Name == "tp_session" {
				return k
			}
		}
		t.Fatal("no session for " + u)
		return nil
	}
	mux := a.routes()
	call := func(c *http.Cookie, path, body string) (int, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(c)
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	ali := login("ali")
	code, body := call(ali, "/api/repair/check", `{}`)
	if code != 200 || !strings.Contains(body, `"alis"`) || strings.Contains(body, `"mem"`) || strings.Contains(body, `"brk"`) {
		t.Errorf("ali's check: %d %s", code, body)
	}
	if code, body := call(ali, "/api/repair/check", `{"IDs":["mem"]}`); code != 404 {
		t.Errorf("ali checked the admin's tunnel: %d %s", code, body)
	}
	if code, body := call(ali, "/api/repair/apply", `{"Picks":{"mem":["memory"]}}`); code != 404 {
		t.Errorf("ali repaired the admin's tunnel: %d %s", code, body)
	}
	if code, _ := call(ali, "/api/repair/auto", `{"Mode":"all"}`); code != 403 {
		t.Errorf("ali set the automatic mode: %d", code)
	}
	boss := login("boss")
	if code, body := call(boss, "/api/repair/check", `{}`); code != 200 || !strings.Contains(body, `"alis"`) || !strings.Contains(body, `"mem"`) {
		t.Errorf("admin's check: %d %s", code, body)
	}
	if code, body := call(boss, "/api/repair/auto", `{"Mode":"off"}`); code != 200 {
		t.Errorf("admin set the automatic mode: %d %s", code, body)
	}
	// a run the admin started over both: ali sees only his tunnel in it
	run := &RepairRun{Job: "x", By: "boss", Tunnels: []*RepairTunnel{{ID: "mem", Name: "mem"}, {ID: "alis", Name: "alis", Owner: "ali"}}}
	if v := visibleRun(run, "ali", false); v == nil || len(v.Tunnels) != 1 || v.Tunnels[0].ID != "alis" || v.By != "" {
		t.Errorf("ali's view of the run: %+v", v)
	}
}
