package main

import (
	"strings"
	"testing"
	"time"
)

func TestIgAgentOld(t *testing.T) {
	cur := "fc2fc762"
	yes := []map[string]string{
		{"state": "UPDATE", "sum": "d58ac30d"},
		{"state": "OK", "sum": "d58ac30d"},
		{"state": "IGFAIL", "sum": "d58ac30d"}, // an old agent hidden behind another state
		{"state": "OK", "sum": cur, "outdated": "1"},
	}
	no := []map[string]string{
		nil,
		{"state": "OK", "sum": cur},
		{"state": "OFFLINE"},
		{"state": "NOAGENT"},
		{"state": "PAUSED", "sum": "d58ac30d"},
		{"state": "DOWN", "sum": "d58ac30d"},
		{"state": "CHECKING", "sum": "d58ac30d"},
	}
	for _, i := range yes {
		if !igAgentOld(i, cur) {
			t.Errorf("should update: %v", i)
		}
	}
	for _, i := range no {
		if igAgentOld(i, cur) {
			t.Errorf("should not update: %v", i)
		}
	}
	if igAgentOld(map[string]string{"state": "UPDATE"}, "") {
		t.Error("no script on the panel host: nothing to update to")
	}
}

func TestIgAgentBackoff(t *testing.T) {
	want := map[int]time.Duration{1: 30 * time.Minute, 2: time.Hour, 3: 2 * time.Hour, 4: 4 * time.Hour, 5: 6 * time.Hour, 9: 6 * time.Hour}
	for n, d := range want {
		if got := igAgentBackoff(n); got != d {
			t.Errorf("tries %d: %v, want %v", n, got, d)
		}
	}
}

// xe108, 2026-11-16: the old v5 menu script replaced the agent. Such a server is told apart from
// one that never had the agent, is repaired by itself, and at any hour.
func TestIgAgentForeignScriptIsRepaired(t *testing.T) {
	text := igForeignMsg + " -> Install / update\n"
	inf := igParseInfo(3, text, "b5795541")
	if inf["state"] != "NOAGENT" || inf["foreign"] != "1" {
		t.Fatalf("a replaced agent: %v", inf)
	}
	if !igAgentOld(inf, "b5795541") {
		t.Error("a replaced agent must be installed again")
	}
	day := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if !igAgentNow(inf, day) {
		t.Error("a replaced agent is repaired at any hour")
	}
	never := igParseInfo(3, "igproxy is not installed here (missing, or the old v5) -> Install / update\n", "b5795541")
	if never["foreign"] != "" || igAgentOld(never, "b5795541") {
		t.Errorf("a server without the agent is left alone: %v", never)
	}
	if !strings.Contains(igScript([]string{"info"}, "", 30), igForeignMsg) {
		t.Error("the info script does not tell a replaced agent apart")
	}
}

// A new agent script is a few seconds without routing on every server: by itself it goes out
// only in the users' quiet hours.
func TestIgAgentRolloutWaitsForQuietHours(t *testing.T) {
	old := map[string]string{"state": "OK", "sum": "d58ac30d"}
	if igAgentNow(old, time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)) { // 15:30 Tehran
		t.Error("an ordinary update must not run by day")
	}
	if !igAgentNow(old, time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)) { // 04:30 Tehran
		t.Error("an ordinary update runs in the quiet hours")
	}
}
