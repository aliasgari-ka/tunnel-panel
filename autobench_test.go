package main

import (
	"strings"
	"testing"
	"time"
)

func TestAutoBenchDue(t *testing.T) {
	if autoBenchEvery(Settings{}) != 24*time.Hour || autoBenchEvery(Settings{AutoBench: "0"}) != 0 || autoBenchEvery(Settings{AutoBench: "6"}) != 6*time.Hour {
		t.Fatal("interval parsing")
	}
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	now := time.Now().Unix()
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", IPv4: "192.0.2.1", IPv6: "2001:db8::1"}, {ID: "k1", IPv4: "198.51.100.1", IPv6: "2001:db8::2", Role: "foreign"}, {ID: "k2", IPv4: "198.51.100.2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{
			{ID: "a", ServerID: "ir", ForeignID: "k1", Family: "v4", Active: "gre"},
			{ID: "b", ServerID: "ir", ForeignID: "k1", Family: "v6", Active: "gre"}, // same route: no duplicate
			{ID: "c", ServerID: "ir", ForeignID: "k2", Family: "v4", Active: "gre"},
			{ID: "d", ServerID: "ir", ForeignID: "k2", Family: "v4"}, // stopped
		}
		s.BenchHistory = []BenchRecord{
			{IranID: "ir", ForeignID: "k1", Family: "v4", At: now - 3600},    // fresh
			{IranID: "ir", ForeignID: "k2", Family: "v4", At: now - 13*3600}, // stale
		}
		return nil
	})
	a := &App{store: st}
	got := map[benchRoute]bool{}
	for _, r := range a.dueRoutes(12 * time.Hour) {
		got[r] = true
	}
	want := map[benchRoute]bool{{"ir", "k1", "v6"}: true, {"ir", "k2", "v4"}: true}
	if len(got) != len(want) {
		t.Fatalf("due: %v", got)
	}
	for r := range want {
		if !got[r] {
			t.Errorf("missing %v (got %v)", r, got)
		}
	}
}

// The benchmark measures only what runs: hot-standby paths that came up, a plain tunnel's method.
func TestRunningMethods(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", IPv4: "192.0.2.1"}}
		s.Tunnels = []*Tunnel{
			{ID: "a", ServerID: "ir", ForeignID: "k1", Family: "v4", Active: "gre"},
			{ID: "b", ServerID: "ir", ForeignID: "k1", Family: "v4", Active: "wg", Paths: []HSPath{
				{Method: "wg", Family: "v4"}, {Method: "espsk", Family: "v4"}, {Method: "ipsec", Family: "v4", Failed: "no"}, {Method: "gre", Family: "v6"}}},
			{ID: "c", ServerID: "ir", ForeignID: "k1", Family: "v4", Selected: "icmp"}, // stopped
			{ID: "d", ServerID: "ir", ForeignID: "k2", Family: "v4", Active: "icmp"},   // other route
		}
		return nil
	})
	a := &App{store: st}
	if got := strings.Join(a.runningMethods("ir", "k1", "v4"), ","); got != "gre,wg,espsk" {
		t.Errorf("v4: %s", got)
	}
	if got := strings.Join(a.runningMethods("ir", "k1", "v6"), ","); got != "gre" {
		t.Errorf("v6: %s", got)
	}
	// nothing runs over v6 on k2: nothing is built just to be measured
	if _, err := a.Bench(BenchRequest{IranID: "ir", ForeignID: "k2", Family: "v6", Running: true}); err == nil || !strings.Contains(err.Error(), "nothing to measure") {
		t.Errorf("want 'nothing to measure', got %v", err)
	}
}
