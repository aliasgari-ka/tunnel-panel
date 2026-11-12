package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// optHost plays both servers and the switcher on the Iran one. Path keys "method|family" in
// keys; a path answers when ok(key, lastConfig) says so, where lastConfig is the last file
// written for that path's directory. pin presses move the users at once.
type optHost struct {
	mu     sync.Mutex
	keys   []string
	active int
	ok     func(key string, cfg string) bool
	cfg    map[int]string // path index -> last written content
	pins   []string
	tears  int
	deploy int
	t      *Tunnel
}

func (h *optHost) Label() string { return "opt" }
func (h *optHost) WriteFile(path string, b []byte, _ os.FileMode) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := 1; i < 250; i++ {
		if strings.Contains(path, fmt.Sprintf("/%sx%d/", h.t.ID, i)) {
			h.cfg[i] += string(b)
		}
	}
	return nil
}
func (h *optHost) Run(_ context.Context, s string, _ func(string)) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case strings.Contains(s, "echo TP-TEARDOWN-DONE"):
		h.tears++
		for i := range h.cfg {
			if strings.Contains(s, fmt.Sprintf("%sx%d", h.t.ID, i)) {
				h.cfg[i] = ""
			}
		}
		return "TP-TEARDOWN-DONE\n", nil
	case strings.Contains(s, "> pin"):
		f := strings.Fields(strings.SplitN(strings.SplitN(s, "then echo ", 2)[1], ">", 2)[0])
		var k int
		_, _ = fmt.Sscan(strings.Trim(f[0], "'"), &k)
		h.pins = append(h.pins, h.keys[k])
		h.active = k
		return "OK\n", nil
	case strings.Contains(s, `echo "K $(cat keys`):
		var b strings.Builder
		fmt.Fprintf(&b, "K %s\nA %d 1793215901\nM manual\n", strings.Join(h.keys, " "), h.active)
		for k, key := range h.keys {
			st := "down"
			idx := 0
			for _, p := range h.t.Paths {
				if p.Method+"|"+p.Family == key {
					idx = p.Index
				}
			}
			if h.ok(key, h.cfg[idx]) {
				st = "ok"
			}
			fmt.Fprintf(&b, "S %d %s 1793215000 40 0 90000\n", k, st)
		}
		b.WriteString("U active\n")
		return b.String(), nil
	case strings.Contains(s, "systemctl restart"):
		h.deploy++
		return "unit x: active\n", nil
	}
	return "", nil
}

func optSetup(t *testing.T, ok func(string, string) bool) (*App, *Tunnel, *optHost) {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir1", ForeignID: "kh1", Family: "v4", Ports: "443", Index: 1,
		Active: "gre", HotStandby: true, Options: map[string]map[string]string{"gre": {"mtu": "1436"}},
		Paths: []HSPath{
			{Method: "gre", Family: "v4", Index: 1},
			{Method: "wg", Family: "v4", Index: 2},
		}}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{
			{ID: "ir1", Name: "ir", IPv4: "192.0.2.1"},
			{ID: "kh1", Name: "uk", IPv4: "198.51.100.1", Role: "foreign"},
		}
		s.Tunnels = []*Tunnel{tn}
		return nil
	})
	h := &optHost{keys: []string{"gre|v4", "wg|v4"}, ok: ok, cfg: map[int]string{}, t: tn}
	a := &App{store: st, jobs: newJobs(), hsViews: map[string]*hsView{}, hostFor: func(*Server) Host { return h }}
	return a, tn, h
}

func optDone(t *testing.T, a *App, id string) *Job {
	t.Helper()
	j := a.jobs.get(id)
	for end := time.Now().Add(20 * time.Second); j.snapshot().Status == "running"; {
		if time.Now().After(end) {
			t.Fatalf("job still running: %v", j.snapshot().Lines)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return j.snapshot()
}

func init() {
	optPoll = 5 * time.Millisecond
	hsPinWait = 200 * time.Millisecond
}

// Saving a changed option starts a job at once that rebuilds only that method's path, with
// the users moved to another working path meanwhile and back afterwards.
func TestOptionsApplyAtOnce(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 2 * time.Second
	a, tn, h := optSetup(t, func(key, cfg string) bool { return true })
	res, code, err := a.SaveOptions(tn, "gre", map[string]string{"mtu": "1400"})
	if err != nil || code != 200 || res["job"] == "" {
		t.Fatalf("save: %v %d %v — want a job", res, code, err)
	}
	j := optDone(t, a, res["job"])
	log := strings.Join(j.Lines, "\n")
	if j.Status != "ok" || !strings.Contains(log, "DONE — GRE") && !strings.Contains(log, "runs with the new options") {
		t.Fatalf("status %s:\n%s", j.Status, log)
	}
	if got := tn.Options["gre"]["mtu"]; got != "1400" {
		t.Fatalf("stored mtu %q", got)
	}
	if !strings.Contains(h.cfg[1], "1400") {
		t.Fatalf("path 1 not rebuilt with mtu 1400: %q", h.cfg[1])
	}
	if h.cfg[2] != "" {
		t.Fatalf("the other path (wg) was touched: %q", h.cfg[2])
	}
	if len(h.pins) != 2 || h.pins[0] != "wg|v4" || h.pins[1] != "gre|v4" {
		t.Fatalf("users not moved off and back: pins %v\n%s", h.pins, log)
	}
	if tn.HSPin != "" {
		t.Fatalf("the users' choice changed: pin %q", tn.HSPin)
	}
}

// New options that make a working path fail: the previous ones are stored and deployed again.
func TestOptionsRollBack(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 300 * time.Millisecond
	a, tn, h := optSetup(t, func(key, cfg string) bool { return key != "gre|v4" || !strings.Contains(cfg, "1300") })
	res, _, err := a.SaveOptions(tn, "gre", map[string]string{"mtu": "1300"})
	if err != nil || res["job"] == "" {
		t.Fatalf("save: %v %v", res, err)
	}
	j := optDone(t, a, res["job"])
	log := strings.Join(j.Lines, "\n")
	if j.Status != "error" || !strings.Contains(log, "ROLLED BACK") {
		t.Fatalf("want a rollback, got %s:\n%s", j.Status, log)
	}
	if got := tn.Options["gre"]["mtu"]; got != "1436" {
		t.Fatalf("options not rolled back: mtu %q", got)
	}
	if strings.Contains(h.cfg[1], "1300") || !strings.Contains(h.cfg[1], "1436") {
		t.Fatalf("path not redeployed with the previous options: %q", h.cfg[1])
	}
	if n := len(h.pins); n == 0 || h.pins[n-1] != "gre|v4" {
		t.Fatalf("users not moved back: %v", h.pins)
	}
}

// A path that was already down before the change: the user's choice is kept.
func TestOptionsKeptWhenDownBefore(t *testing.T) {
	defer func(d time.Duration) { optWaitUp = d }(optWaitUp)
	optWaitUp = 200 * time.Millisecond
	a, tn, _ := optSetup(t, func(key, cfg string) bool { return key != "gre|v4" })
	res, _, _ := a.SaveOptions(tn, "gre", map[string]string{"mtu": "1300"})
	j := optDone(t, a, res["job"])
	if j.Status != "ok" || tn.Options["gre"]["mtu"] != "1300" || !strings.Contains(strings.Join(j.Lines, "\n"), "didn't before the change either") {
		t.Fatalf("%s mtu %s:\n%s", j.Status, tn.Options["gre"]["mtu"], strings.Join(j.Lines, "\n"))
	}
}

// A bad value is refused before anything is stored or started; the same values start nothing.
func TestOptionsRefused(t *testing.T) {
	a, tn, h := optSetup(t, func(string, string) bool { return true })
	if _, code, err := a.SaveOptions(tn, "gre", map[string]string{"mtu": "abc"}); err == nil || code != 400 {
		t.Fatalf("bad mtu accepted: %d %v", code, err)
	}
	if _, code, err := a.SaveOptions(tn, "gre", map[string]string{"nope": "1"}); err == nil || code != 400 {
		t.Fatalf("unknown option accepted: %d %v", code, err)
	}
	if tn.Options["gre"]["mtu"] != "1436" || h.deploy != 0 || a.jobs.running(tn.ID) != "" {
		t.Fatalf("a refused value changed something: %v deploys %d", tn.Options, h.deploy)
	}
	res, _, err := a.SaveOptions(tn, "gre", map[string]string{"mtu": ""}) // blank = the default 1436
	if err != nil || res["job"] != "" {
		t.Fatalf("unchanged options started a job: %v %v", res, err)
	}
	// a job already running: refused, nothing stored
	j, _ := a.jobs.start(tn.ID, "x")
	if _, code, _ := a.SaveOptions(tn, "gre", map[string]string{"mtu": "1400"}); code != 409 || tn.Options["gre"]["mtu"] != "" {
		t.Fatalf("saved during another job: %d %v", code, tn.Options["gre"])
	}
	a.jobs.done(j)
	// a stopped tunnel: stored, no job
	_ = a.store.Update(func(*State) error { tn.Active = ""; return nil })
	res, _, err = a.SaveOptions(tn, "gre", map[string]string{"mtu": "1400"})
	if err != nil || res["job"] != "" || tn.Options["gre"]["mtu"] != "1400" {
		t.Fatalf("stopped tunnel: %v %v %v", res, err, tn.Options["gre"])
	}
}

// The user's value wins over a carrier the benchmark put on the path (it kept the path on
// the benchmark's value, so the change never reached the server).
func TestOptionsPathOwnKeysYield(t *testing.T) {
	got := optPathOpts(map[string]string{"profile": "icmp", "port": "41000"}, []string{"profile"})
	if got["profile"] != "" || got["port"] != "41000" {
		t.Fatalf("got %v", got)
	}
	if c := optChanged(methodByID["premium"], map[string]string{"profile": "tcp"}, map[string]string{"profile": "udp", "mode": ""}); len(c) != 1 || c[0] != "profile" {
		t.Fatalf("changed %v", c)
	}
}

// Access: another account can't change a tunnel's options.
func TestOptionsAccess(t *testing.T) {
	a, tn, _ := optSetup(t, func(string, string) bool { return true })
	hash, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = a.store.Update(func(st *State) error {
		tn.Owner = "boss"
		st.Users = []User{{Username: "admin", Hash: string(hash)}, {Username: "ali", Hash: string(hash), Role: roleUser}, {Username: "boss", Hash: string(hash), Role: roleUser}}
		return nil
	})
	a.agents = newAgentHub()
	s := &Server2{app: a, failures: map[string][]time.Time{}}
	w := httptest.NewRecorder()
	s.login(w, httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"ali","password":"password1"}`)))
	var ck *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == "tp_session" {
			ck = k
		}
	}
	if ck == nil {
		t.Fatal("no session")
	}
	r := httptest.NewRequest("POST", "/api/tunnels/options", strings.NewReader(`{"ID":"aaaaaaaaaaaa","Method":"gre","Options":{"mtu":"1400"}}`))
	r.AddCookie(ck)
	w = httptest.NewRecorder()
	s.tunnelOptions(w, r)
	if w.Code == http.StatusOK || tn.Options["gre"]["mtu"] != "1436" {
		t.Fatalf("another account changed the options: %d %s", w.Code, w.Body.String())
	}
}
