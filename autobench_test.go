package main

import (
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
