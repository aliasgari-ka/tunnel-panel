package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A run of only some methods carries the others over from earlier runs. They keep when they
// were measured: without it an old result (even the ★ best) showed as measured by the newest
// run (seen in the live history: the same Paqet figures carried through four runs).
func TestBenchCarriedResultsKeepTheirTime(t *testing.T) {
	earlier := []BenchResult{
		{Method: "paqet", OK: true, DownMbps: 56, Mbps: 56, At: 1000}, // measured by an earlier run
		{Method: "gre", OK: true, DownMbps: 9},                        // saved before results had a time
		{Method: "wg", OK: true, DownMbps: 5, At: 1500},               // measured again now
	}
	out := withEarlier([]BenchResult{{Method: "wg", OK: true, DownMbps: 7, Mbps: 7, At: 3000}}, earlier, 2000)
	at := map[string]int64{}
	for _, r := range out {
		at[r.Method] = r.At
	}
	if at["wg"] != 3000 || at["paqet"] != 1000 || at["gre"] != 2000 {
		t.Fatalf("times: %v", at)
	}
	// ranking keeps the time with the result it belongs to
	rankBench(out)
	if out[0].Method != "paqet" || out[0].At != 1000 || !out[0].Recommended {
		t.Fatalf("ranked: %+v", out[0])
	}
}

// A benchmark that measured nothing writes no history: the page must still learn it failed
// (the old page went on showing the route's old results as the latest word).
func TestBenchFailureIsKeptUntilARunRecords(t *testing.T) {
	e := newHunt2Env(t, nil)
	if _, err := e.a.Bench(BenchRequest{IranID: "s2", ForeignID: "s3", Family: "v4", Methods: []string{"no-such-method"}}); err == nil {
		t.Fatal("no methods: no error")
	}
	fl := e.a.benchFailList()
	if len(fl) != 1 || fl[0].IranID != "s2" || fl[0].ForeignID != "s3" || fl[0].Family != "v4" || !strings.Contains(fl[0].Error, "no methods") || fl[0].At == 0 {
		t.Fatalf("fails: %+v", fl)
	}
	// the slot being busy is not a failure of the route
	j, _ := e.a.jobs.start("bench", "bench")
	if _, err := e.a.Bench(BenchRequest{IranID: "s1", ForeignID: "s3", Family: "v6"}); err == nil {
		t.Fatal("busy: no error")
	}
	e.a.jobs.done(j)
	if fl := e.a.benchFailList(); len(fl) != 1 {
		t.Fatalf("busy slot recorded as a failure: %+v", fl)
	}
	// a run that records results clears it
	e.a.recordBench(BenchRequest{IranID: "s2", ForeignID: "s3", Family: "v4"}, []BenchResult{{Method: "gre", OK: true}}, false)
	if fl := e.a.benchFailList(); len(fl) != 0 {
		t.Fatalf("still failed after a recorded run: %+v", fl)
	}
}

// /api/bench/status: the automatic benchmark's schedule per route in use, and failures —
// each only for whoever may see the route.
func TestBenchStatus(t *testing.T) {
	now := time.Now().Unix()
	e := newHunt2Env(t, func(s *State) {
		s.Settings.AutoBench = "6"
		s.Servers = append(s.Servers, &Server{ID: "s4", Name: "admin-de", IPv4: "198.51.100.4", Role: "foreign"})
		s.Tunnels = []*Tunnel{
			{ID: "t1", ServerID: "s2", ForeignID: "s3", Family: "v4", Active: "gre", Owner: "ali"},
			{ID: "t2", ServerID: "s1", ForeignID: "s4", Family: "v4", Active: "wg"},
		}
		s.BenchHistory = []BenchRecord{
			{IranID: "s2", ForeignID: "s3", Family: "v4", At: now - 3600, Full: true},
			{IranID: "s1", ForeignID: "s4", Family: "v4", At: now - 3600, Full: true},
		}
	})
	e.a.benchFailed(BenchRequest{IranID: "s1", ForeignID: "s4", Family: "v4", Auto: true}, "foreign server unreachable: x")
	type st struct {
		Hours  int          `json:"hours"`
		Routes []benchSched `json:"routes"`
		Fails  []BenchFail  `json:"fails"`
	}
	read := func(user string) st {
		w := e.call(e.cookie(user), e.s.benchStatus, "GET", "/api/bench/status", "")
		var v st
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || w.Code != 200 {
			t.Fatalf("%s: %d %s", user, w.Code, w.Body)
		}
		return v
	}
	b := read("boss")
	if b.Hours != 6 || len(b.Routes) != 2 || len(b.Fails) != 1 || !b.Fails[0].Auto {
		t.Fatalf("admin: %+v", b)
	}
	for _, r := range b.Routes {
		// the running methods are due 6 h after the last run (the full run only in 42 h)
		if r.NextFull || r.Next != now-3600+6*3600 || len(r.Running) != 1 {
			t.Errorf("schedule: %+v", r)
		}
	}
	a := read("ali")
	if len(a.Routes) != 1 || a.Routes[0].IranID != "s2" || len(a.Fails) != 0 {
		t.Fatalf("ali sees others' routes: %+v", a)
	}
	// off: no next time
	_ = e.st.Update(func(s *State) error { s.Settings.AutoBench = "0"; return nil })
	if b := read("boss"); b.Hours != 0 || b.Routes[0].Next != 0 {
		t.Fatalf("off: %+v", b)
	}
}

// The page's schedule editor sets only the interval, checked like the Settings page does,
// and only the admin may (the route guard).
func TestBenchAutoSet(t *testing.T) {
	e := newHunt2Env(t, func(s *State) { s.Settings.TelegramTok = "keep-me" })
	boss, ali := e.cookie("boss"), e.cookie("ali")
	if w := e.call(boss, e.s.guard("admin", e.s.benchAuto), "POST", "/api/bench/auto", `{"hours":" 12 "}`); w.Code != 200 {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}
	if s := e.a.settings(); s.AutoBench != "12" || s.TelegramTok != "keep-me" {
		t.Fatalf("settings: %q %q", s.AutoBench, s.TelegramTok)
	}
	for _, bad := range []string{`{"hours":"-1"}`, `{"hours":"721"}`, `{"hours":"abc"}`} {
		if w := e.call(boss, e.s.guard("admin", e.s.benchAuto), "POST", "/api/bench/auto", bad); w.Code != 400 {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	if w := e.call(ali, e.s.guard("admin", e.s.benchAuto), "POST", "/api/bench/auto", `{"hours":"0"}`); w.Code == 200 {
		t.Fatal("a user changed the automatic benchmark")
	}
	if e.a.settings().AutoBench != "12" {
		t.Fatal("changed by a refused call")
	}
}
