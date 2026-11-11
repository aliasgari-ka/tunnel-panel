package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestUsageDeltas: the first read only sets the baseline, increases add up in both the hour
// and the day, and a counter that went down (restarted) counts its whole new value.
func TestUsageDeltas(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, tehran)
	u.addLocked(now, "t", "x", 1000, 100)
	if len(u.Buckets) != 0 && u.Buckets[0].Tunnels["x"] != nil {
		t.Fatal("first read counted")
	}
	u.addLocked(now, "t", "x", 1500, 300)
	u.addLocked(now.Add(2*time.Hour), "t", "x", 200, 50) // restarted
	if got := *u.Buckets[0].Tunnels["x"]; got.Down != 500 || got.Up != 200 {
		t.Fatalf("hour got %+v, want 500/200", got)
	}
	if len(u.Days) != 1 {
		t.Fatalf("%d days", len(u.Days))
	}
	if got := *u.Days[0].Tunnels["x"]; got.Down != 700 || got.Up != 250 {
		t.Fatalf("day got %+v, want 700/250", got)
	}
	u.addLocked(now, "s", "", 10, 10)
	u.addLocked(now, "s", "", 30, 15)
	if got := *u.Days[0].Servers[""]; got.Down != 20 || got.Up != 5 {
		t.Fatalf("server got %+v", got)
	}
	// a new day starts at Tehran's midnight
	u.hourLocked(now.Add(14 * time.Hour))
	if u.dayLocked(time.Date(2026, 11, 1, 23, 59, 0, 0, tehran)) != u.Days[0] || u.dayLocked(time.Date(2026, 11, 2, 0, 1, 0, 0, tehran)) == u.Days[0] {
		t.Fatal("day buckets")
	}
	for i := 0; i < usageKeep+5; i++ {
		u.hourLocked(now.Add(time.Duration(i+20) * time.Hour))
	}
	if len(u.Buckets) != usageKeep {
		t.Fatalf("kept %d hours", len(u.Buckets))
	}
}

// TestUsageFoldHours: a log saved before daily buckets gets its hours folded into days.
func TestUsageFoldHours(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	u := &usageLog{Last: map[string]*usageLast{}}
	h := time.Date(2026, 11, 1, 1, 0, 0, 0, tehran)
	u.Buckets = []*usageBucket{
		{Hour: h.Unix(), Tunnels: map[string]*UsageBytes{"x": {Down: 5, Up: 1}}, Servers: map[string]*UsageBytes{}},
		{Hour: h.Add(time.Hour).Unix(), Tunnels: map[string]*UsageBytes{"x": {Down: 7, Up: 2}}, Servers: map[string]*UsageBytes{}},
	}
	u.saveLocked()
	got := loadUsage()
	if len(got.Days) != 1 || got.Days[0].Tunnels["x"].Down != 12 || got.Days[0].Tunnels["x"].Up != 3 {
		t.Fatalf("days %+v", got.Days)
	}
}

// TestUsagePaid: an Iran server with tunnels to two foreign servers pays each its own peer
// intake plus its users' upload; two tunnels on one pair split it by download; a bucket
// from before the peer counters splits the Iran card's intake (estimated).
func TestUsagePaid(t *testing.T) {
	pairs := map[string][2]string{"a": {"ir", "us"}, "b": {"ir", "fr"}, "c": {"ir", "fr"}}
	b := &usageBucket{
		Tunnels: map[string]*UsageBytes{"a": {Down: 1000, Up: 100}, "b": {Down: 300, Up: 10}, "c": {Down: 100, Up: 20}},
		Servers: map[string]*UsageBytes{"ir": {Down: 2000}},
		Peers:   map[string]*UsageBytes{"ir|us": {Down: 1100}, "ir|fr": {Down: 400}},
	}
	paid, est := usagePaid(b, pairs)
	if paid["a"] != 1200 || paid["b"] != 310 || paid["c"] != 120 || len(est) != 0 {
		t.Fatalf("paid %v est %v", paid, est)
	}
	b.Peers = nil
	paid, est = usagePaid(b, pairs)
	if !est["a"] || paid["a"]+paid["b"]+paid["c"] < 1990 || paid["a"] < paid["b"] {
		t.Fatalf("fallback paid %v est %v", paid, est)
	}
	// peer reads are kept per address and summed per pair
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, tehran)
	for _, ip := range []string{"1.1.1.1", "2a01::1"} {
		u.addLocked(now, "p", "ir|us|"+ip, 100, 10)
		u.addLocked(now, "p", "ir|us|"+ip, 150, 20)
	}
	if got := u.Buckets[0].Peers["ir|us"]; got == nil || got.Down != 100 || got.Up != 20 {
		t.Fatalf("peer bucket %+v", got)
	}
}

// TestPeerScript: one rule per foreign address, in the right iptables.
func TestPeerScript(t *testing.T) {
	s := peerScript(map[string]string{"1.2.3.4": "us", "2a01::1": "us"})
	for _, want := range []string{"tpp iptables 1.2.3.4", "tpp ip6tables 2a01::1", "tpp_chain iptables", "tpp_chain ip6tables"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if peerScript(nil) != "" {
		t.Fatal("empty")
	}
}

func TestUsageNicSetChange(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Now()
	u.addSrcLocked(now, "s", "ir", "nic eth0", 1000, 100)
	u.addSrcLocked(now, "s", "ir", "nic eth0", 1500, 200)
	u.addSrcLocked(now, "s", "ir", "nic eth0+eth1", 90000, 9000) // a second card: baseline only
	u.addSrcLocked(now, "s", "ir", "nic eth0+eth1", 90700, 9100)
	if x := u.Days[0].Servers["ir"]; x == nil || x.Down != 1200 || x.Up != 200 {
		t.Fatalf("got %+v, want 1200/200", x)
	}
}

func TestUsagePaidEst(t *testing.T) {
	pairs := map[string][2]string{"a": {"ir", "us"}, "b": {"ir2", "nl"}}
	measured := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Down: 1e9, Up: 1e8}},
		Servers: map[string]*UsageBytes{"ir": {Down: 2e9}},
		Peers:   map[string]*UsageBytes{"ir|us": {Down: 1.05e9}}}
	coef := usageCoef([]*usageBucket{measured}, pairs)
	if c := coef["a"]; c < 1.04 || c > 1.06 { // (0.1 + 1.05) / 1.1
		t.Fatalf("coef %v", c)
	}
	// an hour before the peer counters, on a server whose card carries 10x other traffic
	old := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Down: 2e9, Up: 2e8}, "b": {Down: 1e9}},
		Servers: map[string]*UsageBytes{"ir": {Down: 25e9}, "ir2": {Down: 3e9}}}
	paid, est := usagePaidEst(old, pairs, coef)
	if !est["a"] || paid["a"] < 2.29e9 || paid["a"] > 2.31e9 {
		t.Fatalf("a: %v %v, want ~2.3e9 estimated at its coefficient", paid["a"], est["a"])
	}
	if !est["b"] || paid["b"] != 3e9 { // no coefficient measured: the card's share, as before
		t.Fatalf("b: %v %v", paid["b"], est["b"])
	}
}

func TestUsageWatchCheck(t *testing.T) {
	pairs := map[string][2]string{"a": {"ir", "nl"}, "b": {"ir2", "us"}}
	names := map[string]string{"ir": "netherlands-iran", "a": "NL", "b": "US"}
	ok := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Down: 10e9, Up: 1e9}},
		Servers: map[string]*UsageBytes{"ir": {Down: 11.5e9}},
		Peers:   map[string]*UsageBytes{"ir|nl": {Down: 10.3e9}}}
	if is := usageWatchCheck(ok, pairs, names); len(is) != 0 {
		t.Fatalf("a normal hour: %+v", is)
	}
	double := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Down: 10e9, Up: 1e9}},
		Servers: map[string]*UsageBytes{"ir": {Down: 11.5e9}},
		Peers:   map[string]*UsageBytes{"ir|nl": {Down: 20.6e9}}}
	is := usageWatchCheck(double, pairs, names)
	if len(is) != 2 || is[0].key != "srv|ir" || is[1].key != "tun|a" {
		t.Fatalf("a doubled hour: %+v", is)
	}
	// no card data, or too little traffic: not judged
	small := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Down: 1e8}},
		Servers: map[string]*UsageBytes{}, Peers: map[string]*UsageBytes{"ir|nl": {Down: 9e8}}}
	if is := usageWatchCheck(small, pairs, names); len(is) != 0 {
		t.Fatalf("a quiet hour: %+v", is)
	}
}

func TestUsageRecordGap(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	now := time.Now()
	pairs := map[string]string{"tun": "ir|de"}
	round := func(td, pd uint64, pairOf map[string]string, withTun bool) {
		rs := []usageRead{{kind: "p", id: "ir|de|1.2.3.4", d: pd}}
		if withTun {
			rs = append(rs, usageRead{kind: "t", id: "tun", d: td})
		}
		u.recordLocked(now, rs, pairOf)
	}
	round(100, 1000, pairs, true)              // baselines
	round(200, 1110, pairs, true)              // +100 users, +110 from foreign
	round(0, 9000, map[string]string{}, false) // tunnel down / being applied: not read
	round(50, 20000, pairs, true)              // back, its counters restarted: rebase only
	round(150, 20105, pairs, true)             // +100 users, +105 from foreign
	got := u.Days[0].Peers["ir|de"]
	if got == nil || got.Down != 215 {
		t.Fatalf("from foreign %+v, want 215 (the outage not counted)", got)
	}
	if x := u.Days[0].Tunnels["tun"]; x.Down != 250 { // 100 + 50 after the restart + 100
		t.Fatalf("tunnel %+v", x)
	}
}

// A tunnel deleted before the log kept routes has bytes but no route: it was left at
// paid 0, so the page's total (sum of the rows) paid ×0.96 while every priced row was
// ×1.02. It now pays its users' bytes (×1, estimated), and the total is the sum of the rows.
func TestUsageTotalCountsUnroutedTunnels(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(x *State) error {
		x.Users = []User{{Username: "admin", Role: "admin"}}
		x.Tunnels = []*Tunnel{{ID: "live", ServerID: "ir", ForeignID: "de"}}
		return nil
	})
	now := time.Now()
	h := hourStart(now) - 3600
	u := &usageLog{Last: map[string]*usageLast{}, Known: map[string]*usageTun{}, Buckets: []*usageBucket{{
		Hour:    h,
		Tunnels: map[string]*UsageBytes{"live": {Down: 900e6, Up: 100e6}, "old": {Down: 450e6, Up: 50e6}},
		Servers: map[string]*UsageBytes{"ir": {Down: 1.2e9}},
		Peers:   map[string]*UsageBytes{"ir|de": {Down: 1e9}},
	}}, Days: []*usageBucket{{
		Hour:    dayStart(time.Unix(h, 0)),
		Tunnels: map[string]*UsageBytes{"live": {Down: 900e6, Up: 100e6}, "old": {Down: 450e6, Up: 50e6}},
		Servers: map[string]*UsageBytes{"ir": {Down: 1.2e9}},
		Peers:   map[string]*UsageBytes{"ir|de": {Down: 1e9}},
	}}}
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub(), usage: u}, failures: map[string][]time.Time{}}
	cw := httptest.NewRecorder()
	s.setCookie(cw, httptest.NewRequest("GET", "/", nil), "admin")
	for _, q := range []string{"days=1", "days=7", "days=7&hourly=1", fmt.Sprintf("from=%d&to=%d", h, now.Unix())} {
		req := httptest.NewRequest("GET", "/api/usage?"+q, nil)
		req.AddCookie(cw.Result().Cookies()[0])
		w := httptest.NewRecorder()
		s.usageGet(w, req)
		var m struct {
			Tunnels []*UsageSum `json:"tunnels"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		var used, paid, series uint64
		by := map[string]*UsageSum{}
		for _, x := range m.Tunnels {
			by[x.ID] = x
			used += x.Down + x.Up
			paid += x.Paid
			for _, st := range x.Series {
				series += st.Paid
			}
		}
		if by["old"] == nil || by["old"].Paid != 500e6 || !by["old"].Est {
			t.Fatalf("%s: the unrouted tunnel %+v, want paid 500 MB at ×1, estimated", q, by["old"])
		}
		if by["live"] == nil || by["live"].Paid != 1.1e9 {
			t.Fatalf("%s: live %+v, want 1.1 GB", q, by["live"])
		}
		if paid < used || series != paid {
			t.Fatalf("%s: total paid %d for %d used (series %d): the total fell below the rows", q, paid, used, series)
		}
	}
}
