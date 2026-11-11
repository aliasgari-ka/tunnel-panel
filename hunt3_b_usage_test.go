package main

import (
	"encoding/json"
	"testing"
	"time"
)

// A deleted tunnel's usage is shown to the account it was of, by the name kept in the usage
// log (Known[id].Owner). A rename (password handler → renameOwnerLocked) moves the live
// servers/tunnels and the jobs to the new name, but not the usage log: the renamed account
// loses its deleted tunnels' history, and a new account created with the old name gets it
// (name, route and bytes) — the same name-reuse leak #116/#135 closed for IG backups and jobs.
func TestHunt3UsageHistoryFollowsOldName(t *testing.T) {
	e := newHunt2Env(t, nil)
	now := time.Now()
	e.a.usage = &usageLog{
		Last: map[string]*usageLast{},
		Buckets: []*usageBucket{{Hour: hourStart(now), Tunnels: map[string]*UsageBytes{"gone1": {Down: 5e9, Up: 1e9}},
			Servers: map[string]*UsageBytes{}}},
		Known: map[string]*usageTun{"gone1": {Pair: "s2|s3", Owner: "ali", Name: "ali-old-tunnel"}},
	}
	seen := func(who string) bool {
		w := e.call(e.cookie(who), e.s.usageGet, "GET", "/api/usage?days=1", "")
		var v struct{ Tunnels []struct{ ID string } }
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		for _, x := range v.Tunnels {
			if x.ID == "gone1" {
				return true
			}
		}
		return false
	}
	if !seen("ali") {
		t.Fatal("setup: ali doesn't see her own deleted tunnel's usage")
	}
	// ali renames herself to ali2
	if w := e.call(e.cookie("ali"), e.s.password, "POST", "/api/password", `{"Old":"password1","NewUser":"ali2"}`); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	// the admin makes a new, unrelated account called ali
	boss := e.cookie("boss")
	if w := e.call(boss, e.s.users, "POST", "/api/users", `{"Username":"ali","Password":"password1","Role":"user"}`); w.Code != 200 {
		t.Fatalf("new ali: %d %s", w.Code, w.Body)
	}
	if !seen("ali2") {
		t.Errorf("after the rename ali2 lost her deleted tunnel's usage history")
	}
	if seen("ali") {
		t.Errorf("the NEW account named ali sees the old ali's deleted tunnel (name, route, bytes)")
	}
}
