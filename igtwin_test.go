package main

import "testing"

// A machine that is on the page twice is driven by one entry only (the admin's): two entries with
// two memories moved NL's Google back and forth on 2026-11-17, a router restart each time.
func TestIgDriversOnePerMachine(t *testing.T) {
	srv := []*Server{
		{ID: "a", Name: "xe107", IPv4: "1.1.1.1", Igproxy: true},
		{ID: "b", Name: "nl", IPv4: "2.2.2.2", Owner: "arshad", Igproxy: true}, // listed before the admin's entry
		{ID: "c", Name: "هلند1", IPv4: "2.2.2.2", Igproxy: true},
		{ID: "d", Name: "usa-kharej", IPv4: "3.3.3.3", Igproxy: true},
		{ID: "e", Name: "usa", IPv4: "3.3.3.3", Owner: "arshad", Igproxy: true},
		{ID: "f", Name: "uk", IPv4: "4.4.4.4", Owner: "arshad", Igproxy: true},
		{ID: "g", Name: "iran", IPv4: "5.5.5.5"}, // not an IG Routing server
	}
	var ids string
	for _, x := range igDrivers(srv) {
		ids += x.ID
	}
	if ids != "acdf" {
		t.Fatalf("drivers %q, want acdf (order kept, the admin's entry for a shared machine)", ids)
	}
	tw := igTwinMap(srv)
	if len(tw) != 2 || tw["b"] != "c" || tw["e"] != "d" {
		t.Fatalf("twins %v", tw)
	}
}

func TestIgTwinCopyShowsTheDriversState(t *testing.T) {
	st := &State{
		Servers: []*Server{
			{ID: "b", IPv4: "2.2.2.2", Owner: "arshad", Igproxy: true},
			{ID: "c", IPv4: "2.2.2.2", Igproxy: true},
		},
		IgAuto: map[string]map[string]*IgAutoSvc{
			"b": {"GOOGLE": {Want: "warp6", Cur: "direct", Tries: 3}},
			"c": {"GOOGLE": {Want: "warp6"}},
		},
		WarpPool: map[string]*WarpPool{"c": {Need: 5, Have: 5, BadAt: map[string]int64{"x": 7}}},
	}
	if !igTwinCopy(st) {
		t.Fatal("nothing copied")
	}
	if g := st.IgAuto["b"]["GOOGLE"]; g.Cur != "" || g.Tries != 0 {
		t.Errorf("the twin keeps its own memory: %+v", g)
	}
	if p := st.WarpPool["b"]; p == nil || p.Need != 5 || p.BadAt["x"] != 7 {
		t.Errorf("pool not copied: %+v", p)
	}
	// copies, not shared pointers: the driver's later changes must not write through
	st.IgAuto["c"]["GOOGLE"].Tries = 9
	st.WarpPool["c"].BadAt["x"] = 8
	if st.IgAuto["b"]["GOOGLE"].Tries != 0 || st.WarpPool["b"].BadAt["x"] != 7 {
		t.Error("the twin shares the driver's records")
	}
	if igTwinCopy(st) != true {
		t.Error("a changed driver must be copied again")
	}
	if igTwinCopy(st) {
		t.Error("nothing changed: the store must not be written")
	}
}

// A pin set on the twin's card is the machine's pin: it lands on the driver's record, so the
// driver never moves what a person pinned.
func TestIgTwinPinLandsOnTheDriver(t *testing.T) {
	st0, err := LoadStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st0, jobs: newJobs(), agents: newAgentHub()}
	_ = a.store.Update(func(st *State) error {
		st.Servers = append(st.Servers,
			&Server{ID: "tw", IPv4: "2.2.2.2", Owner: "arshad", Igproxy: true},
			&Server{ID: "drv", IPv4: "2.2.2.2", Igproxy: true})
		return nil
	})
	a.igAutoPut("tw", "IG", func(s *IgAutoSvc) { s.Pin, s.Want = "proxy4", "proxy4" })
	a.wpPut("tw", func(p *WarpPool) { p.Off = true })
	a.store.View(func(st *State) {
		if d := st.IgAuto["drv"]["IG"]; d == nil || d.Pin != "proxy4" {
			t.Errorf("driver's record: %+v", d)
		}
		if w := st.IgAuto["tw"]["IG"]; w == nil || w.Pin != "proxy4" {
			t.Errorf("twin's copy: %+v", w)
		}
		if st.WarpPool["drv"] == nil || !st.WarpPool["drv"].Off || st.WarpPool["tw"] == nil || !st.WarpPool["tw"].Off {
			t.Errorf("pool switch: drv %+v tw %+v", st.WarpPool["drv"], st.WarpPool["tw"])
		}
	})
}
