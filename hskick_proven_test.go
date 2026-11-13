package main

import (
	"testing"
	"time"
)

// A path whose outage has a proven "restart fixes it" cause is restarted after
// hsKickProven, not hsKickAfter; a cause from an earlier outage, or one that doesn't
// suggest a restart, keeps the 30 minutes.
func TestHSKickProvenCause(t *testing.T) {
	tn := &Tunnel{ID: "x1", Name: "t", ServerID: "ir", ForeignID: "kh", Active: "gre", Family: "v4", HotStandby: true,
		Paths: []HSPath{{Method: "gre", Family: "v4", Index: 10}, {Method: "tpk", Family: "v4", Index: 12}}}
	a := hsTestApp(t, tn)
	now := time.Unix(1_800_000_000, 0)
	downAt := now.Unix() - 6*60
	v := &hsView{Active: 0, Keys: []string{"gre|v4", "tpk|v4"}, OK: []bool{true, false}, Changed: []int64{now.Unix() - 99999, downAt}}
	if got := a.hsKickDue(tn, v, now); len(got) != 0 {
		t.Fatalf("restarted after 6 min with no known cause: %v", got)
	}
	a.dc = dcState{cache: map[string]*DownCause{}, busy: map[string]bool{}, tried: map[string]time.Time{}}
	a.dc.cache["x1|tpk|v4"] = &DownCause{Key: "tpk|v4", DownAt: downAt, Code: "blocked", Restart: false}
	if got := a.hsKickDue(tn, v, now); len(got) != 0 {
		t.Fatalf("a route cause made the restart early: %v", got)
	}
	a.dc.cache["x1|tpk|v4"] = &DownCause{Key: "tpk|v4", DownAt: downAt - 3600, Code: "stuck", Restart: true}
	if got := a.hsKickDue(tn, v, now); len(got) != 0 {
		t.Fatalf("an earlier outage's cause made the restart early: %v", got)
	}
	a.dc.cache["x1|tpk|v4"] = &DownCause{Key: "tpk|v4", DownAt: downAt, Code: "stuck", Restart: true}
	if got := a.hsKickDue(tn, v, now); len(got) != 1 || got[0].Method != "tpk" {
		t.Fatalf("stuck core not restarted after 6 min: %v", got)
	}
	if got := a.hsKickDue(tn, v, now.Add(-2*time.Minute)); len(got) != 0 {
		t.Fatalf("restarted before %v: %v", hsKickProven, got)
	}
	// the users' path is still never restarted
	v.Active, v.OK = 1, []bool{true, false}
	if got := a.hsKickDue(tn, v, now); len(got) != 0 {
		t.Fatalf("the users' path was due: %v", got)
	}
}

