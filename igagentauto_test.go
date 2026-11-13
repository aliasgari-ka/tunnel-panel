package main

import (
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
