package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func planHas(p BenchPlan, mid string) bool { return contains(p.Methods, mid) }

func planWhy(p BenchPlan, mid string) string {
	for _, l := range p.Left {
		if l.Method == mid {
			return l.Why
		}
	}
	return ""
}

// "Every method" measures every method of the family, also the ones left out on the route
// (seen live: 12 of 18 IPv4 methods were off on iran-107 → xe107-germany, and the dialog's
// "Every method" ran the same 6 as "The methods in use"); only a hard reason keeps one out.
func TestBenchPlanEveryMethod(t *testing.T) {
	st := &State{RouteSkip: map[string][]string{routeKey("ir", "kh"): {"gre|v4", "wg|v4", "frp|v4", "paqet|v6"}}}
	p := benchPlanLocked(st, "ir", "kh", "v4", true)
	var want []string
	for _, m := range methods {
		if supportsFamily(m, "v4") && m.ID != "spoof" {
			want = append(want, m.ID)
		}
	}
	if strings.Join(p.Methods, ",") != strings.Join(want, ",") {
		t.Fatalf("every method on v4 = %v, want %v", p.Methods, want)
	}
	for _, mid := range []string{"gre", "wg", "frp", "tpk", "bp_multi", "bp_pckfec", "espsk", "premium"} {
		if !planHas(p, mid) {
			t.Errorf("%s is not measured", mid)
		}
	}
	if strings.Join(p.Off, ",") == "" || !contains(p.Off, "gre") || !contains(p.Off, "wg") || !contains(p.Off, "frp") || contains(p.Off, "paqet") {
		t.Errorf("off = %v, want gre, wg, frp (paqet is off only on v6)", p.Off)
	}
	if w := planWhy(p, "spoof"); !strings.Contains(w, "UDP-only") {
		t.Errorf("spoof: why = %q", w)
	}
	if w := planWhy(p, "direct6"); w != "IPv6 only" {
		t.Errorf("direct6 on v4: why = %q", w)
	}
	if p.MaxMB != benchMaxMB || benchMaxMB > 6 {
		t.Errorf("maxMB = %d (cap %d)", p.MaxMB, benchMaxMB)
	}
	// each method is measured or left out with a reason, none twice
	seen := map[string]int{}
	for _, m := range p.Methods {
		seen[m]++
	}
	for _, l := range p.Left {
		seen[l.Method]++
		if l.Why == "" || l.Title == "" {
			t.Errorf("%s left out without a reason or title", l.Method)
		}
	}
	for _, m := range methods {
		if seen[m.ID] != 1 {
			t.Errorf("%s appears %d times", m.ID, seen[m.ID])
		}
	}

	// without all (the automatic weekly run, older clients) the route's choices hold
	q := benchPlanLocked(st, "ir", "kh", "v4", false)
	if planHas(q, "gre") || planWhy(q, "gre") != benchRouteOff || len(q.Off) != 0 {
		t.Errorf("without all: gre measured=%v why=%q off=%v", planHas(q, "gre"), planWhy(q, "gre"), q.Off)
	}
	if len(q.Methods) != len(p.Methods)-3 {
		t.Errorf("without all: %d methods, want %d", len(q.Methods), len(p.Methods)-3)
	}
	// another route's choices don't count
	if o := benchPlanLocked(st, "ir", "kh2", "v4", false); len(o.Methods) != len(p.Methods) {
		t.Errorf("another route: %d methods, want %d", len(o.Methods), len(p.Methods))
	}
	// v6: the IPv4-only methods are out with a reason
	v6 := benchPlanLocked(st, "ir", "kh", "v6", true)
	if planHas(v6, "golden") || planWhy(v6, "golden") != "IPv4 only" || !planHas(v6, "paqet") || !planHas(v6, "direct6") {
		t.Errorf("v6 plan: %v / left %v", v6.Methods, v6.Left)
	}
}

// A Golden-GRE a live tunnel runs on the route can't get a test copy beside it: left out,
// named, the other methods still measured.
func TestBenchPlanGoldenConflict(t *testing.T) {
	st := &State{Tunnels: []*Tunnel{{ID: "t1", Name: "live", ServerID: "ir", ForeignID: "kh", Family: "v4", Active: "golden",
		Options: map[string]map[string]string{"golden": {"facade": "dns"}}}}}
	if goldenConflict(st, &Tunnel{ID: "bench", ServerID: "ir", ForeignID: "kh", Family: "v4"}) == "" {
		t.Skip("Golden-GRE's default facade isn't dns here: no conflict to test")
	}
	p := benchPlanLocked(st, "ir", "kh", "v4", true)
	if planHas(p, "golden") || !strings.Contains(planWhy(p, "golden"), `"live"`) {
		t.Errorf("golden: measured=%v why=%q", planHas(p, "golden"), planWhy(p, "golden"))
	}
	if !planHas(p, "gre") {
		t.Error("gre left out too")
	}
	// another route: no conflict
	if q := benchPlanLocked(st, "ir", "kh2", "v4", true); !planHas(q, "golden") {
		t.Error("golden left out on another route")
	}
}

// A run that leaves a method out on the route keeps its earlier measured result (a run of
// every method on purpose said whether it works; the weekly automatic run must not wipe it).
func TestBenchEarlierKept(t *testing.T) {
	earlier := []BenchResult{{Method: "gre", OK: true, DownMbps: 50}, {Method: "wg", Skipped: true, Error: "excluded on this route"}}
	if r := benchEarlier(earlier, 100, "gre"); r == nil || !r.OK || r.At != 100 {
		t.Errorf("gre: %+v", r)
	}
	if r := benchEarlier(earlier, 100, "wg"); r != nil {
		t.Errorf("a skipped stub was carried: %+v", r)
	}
	if r := benchEarlier(earlier, 100, "frp"); r != nil {
		t.Errorf("frp: %+v", r)
	}
	if earlier[0].At != 0 {
		t.Error("benchEarlier changed the earlier results")
	}
}

// GET /api/bench/plan answers a reader (no POST), and only for the account's own pair.
func TestBenchPlanAPI(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	h, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	_ = st.Update(func(s *State) error {
		s.Users = []User{{Username: "boss", Hash: string(h)}, {Username: "ali", Hash: string(h), Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s1", Name: "boss-iran", IPv4: "192.0.2.1", Role: "iran"},
			{ID: "s4", Name: "boss-de", IPv4: "198.51.100.4", Role: "foreign"},
			{ID: "s2", Name: "ali-iran", IPv4: "192.0.2.2", Role: "iran", Owner: "ali"},
			{ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
		}
		s.RouteSkip = map[string][]string{routeKey("s2", "s3"): {"gre|v4"}}
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
	get := func(q string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/bench/plan?"+q, nil)
		r.AddCookie(ali)
		s.guard("pair", s.benchPlanAPI)(w, r)
		return w
	}
	if w := get("iran=s2&foreign=s3&family=v4"); w.Code != 200 || !strings.Contains(w.Body.String(), `"off":["gre"]`) || !strings.Contains(w.Body.String(), `"maxMB":6`) {
		t.Errorf("own pair: %d %s", w.Code, w.Body.String())
	}
	for _, q := range []string{"iran=s1&foreign=s4&family=v4", "iran=s2&foreign=&family=v4"} {
		if w := get(q); w.Code != 404 {
			t.Errorf("%s: %d, want 404", q, w.Code)
		}
	}
}
