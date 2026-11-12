package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// 2026-11-12: xe108's users went by another path from 11:00 Tehran and its route's
// foreign-server count fell to ~0.7 GB an hour while the tunnel moved 35-40 GB (the Iran
// card still took in 40 GB). Those hours were priced at ×0.1, so the Usage page's "you
// pay for" came out at ×0.99 of the traffic while every other tunnel was ×1.01-1.05.
func TestUsagePaidShortCountIsEstimated(t *testing.T) {
	pairs := map[string][2]string{"x": {"ir", "de"}}
	good := &usageBucket{Tunnels: map[string]*UsageBytes{"x": {Down: 33e9, Up: 4e9}},
		Servers: map[string]*UsageBytes{"ir": {Down: 40e9}},
		Peers:   map[string]*UsageBytes{"ir|de": {Down: 34.5e9}}} // ×1.04
	short := &usageBucket{Tunnels: map[string]*UsageBytes{"x": {Down: 35e9, Up: 4e9}},
		Servers: map[string]*UsageBytes{"ir": {Down: 41e9}},
		Peers:   map[string]*UsageBytes{"ir|de": {Down: 0.7e9}}}
	coef := usageCoef([]*usageBucket{good, short}, pairs)
	if c := coef["x"]; c < 1.03 || c > 1.05 {
		t.Fatalf("coef %v: the short hour must not pull the coefficient down", c)
	}
	paid, est := usagePaidEst(short, pairs, coef)
	if !est["x"] || paid["x"] < 39e9 {
		t.Fatalf("short hour paid %v est %v, want ≥ its 39 GB, estimated", paid["x"], est["x"])
	}
	// with no coefficient yet: the users' bytes, ×1
	paid, est = usagePaidEst(short, pairs, nil)
	if !est["x"] || paid["x"] != 39e9 {
		t.Fatalf("no coef: paid %v est %v", paid["x"], est["x"])
	}
	// a small hour stays as measured (its counts are rough); a normal hour stays measured
	small := &usageBucket{Tunnels: map[string]*UsageBytes{"x": {Down: 100e6, Up: 10e6}},
		Peers: map[string]*UsageBytes{"ir|de": {Down: 80e6}}}
	if paid, est := usagePaidEst(small, pairs, coef); est["x"] || paid["x"] != 90e6 {
		t.Fatalf("small hour paid %v est %v", paid["x"], est["x"])
	}
	if paid, est := usagePaidEst(good, pairs, coef); est["x"] || paid["x"] != 38.5e9 {
		t.Fatalf("good hour paid %v est %v", paid["x"], est["x"])
	}
	// the hourly watch still sees the broken count (it reads the raw price)
	if len(usageWatchCheck(short, pairs, map[string]string{})) == 0 {
		t.Fatal("the watch must still flag the ×0.1 hour")
	}
}

// The page's cards are the sum of the rows the API returns: whatever the range, the total
// paid is the sum of the tunnels' paid and of their steps, and with every tunnel measured
// at ×1 or more it is never below the traffic.
func TestUsageTotalsNeverBelowTraffic(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(x *State) error {
		x.Users = []User{{Username: "admin", Role: "admin"}}
		x.Tunnels = []*Tunnel{{ID: "a", ServerID: "ir", ForeignID: "de"}, {ID: "b", ServerID: "ir2", ForeignID: "nl"}}
		return nil
	})
	now := time.Now()
	u := &usageLog{Last: map[string]*usageLast{}, Known: map[string]*usageTun{}}
	day := map[string]*UsageBytes{}
	for i := 30; i >= 1; i-- {
		h := hourStart(now) - int64(i)*3600
		peerA := 34.5e9 // ×1.04
		if i <= 4 {
			peerA = 0.7e9 // its route's count missed the traffic
		}
		b := &usageBucket{Hour: h,
			Tunnels: map[string]*UsageBytes{"a": {Down: 33e9, Up: 4e9}, "b": {Down: 9e9, Up: 1e9}},
			Servers: map[string]*UsageBytes{"ir": {Down: 40e9}, "ir2": {Down: 11e9}},
			Peers:   map[string]*UsageBytes{"ir|de": {Down: uint64(peerA)}, "ir2|nl": {Down: 9.2e9}}}
		u.Buckets = append(u.Buckets, b)
		for id, x := range b.Tunnels {
			if day[id] == nil {
				day[id] = &UsageBytes{}
			}
			day[id].Down += x.Down
			day[id].Up += x.Up
		}
	}
	s := &Server2{app: &App{store: st, jobs: newJobs(), agents: newAgentHub(), usage: u}, failures: map[string][]time.Time{}}
	cw := httptest.NewRecorder()
	s.setCookie(cw, httptest.NewRequest("GET", "/", nil), "admin")
	hs := hourStart(now)
	for _, q := range []string{
		fmt.Sprintf("from=%d&to=%d", hs-24*3600, now.Unix()), // the page's "24 hours"
		fmt.Sprintf("from=%d&to=%d", hs-23*3600, now.Unix()),
		fmt.Sprintf("from=%d&to=%d", dayStart(now)-6*86400, now.Unix()),
		"days=1",
	} {
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
		for _, x := range m.Tunnels {
			used += x.Down + x.Up
			paid += x.Paid
			var sp uint64
			for _, st := range x.Series {
				sp += st.Paid
			}
			if sp != x.Paid {
				t.Fatalf("%s: %s steps %d != its paid %d", q, x.ID, sp, x.Paid)
			}
			series += sp
			if x.Down+x.Up > 0 && x.Paid < x.Down+x.Up {
				t.Fatalf("%s: %s paid %d for %d used (×%.2f)", q, x.ID, x.Paid, x.Down+x.Up, float64(x.Paid)/float64(x.Down+x.Up))
			}
		}
		if used == 0 || paid < used || series != paid {
			t.Fatalf("%s: total paid %d for %d used (×%.3f), steps %d", q, paid, used, float64(paid)/float64(used), series)
		}
	}
}
