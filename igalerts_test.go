package main

import (
	"strings"
	"testing"
	"time"
)

func TestIgAlertLines(t *testing.T) {
	st := &igAlertState{since: map[string]int64{}, sent: map[string]time.Time{}, pathBad: map[string]bool{}}
	now := time.Now()
	got := st.igAlertLines("s1", []string{
		"WARP 3 swapped live (no restart)",
		"guard: Google now on WARP 2 (DE) - live, no restart",
		"user path check failed: Gemini (Google does not answer (http 000)) -> repairing",
		"user path works again: Gemini",
		"user path check failed: Instagram -> repairing",
		"router DOWN -> everything DIRECT",
		"still broken -> restarting router",
		"test account not accepted by Instagram (login_required) - log in again (igpm -> server -> 6)",
	}, now)
	j := strings.Join(got, "\n")
	if len(got) != 2 || !strings.Contains(j, "router DOWN") || strings.Contains(j, "test account") || !strings.Contains(j, "Instagram broken") {
		t.Fatalf("first round:\n%s", j)
	}
	// the same again within the cooldowns: nothing; Instagram back: its recovery
	got = st.igAlertLines("s1", []string{"router DOWN -> everything DIRECT", "test account not accepted by Instagram (x)",
		"user path works again: Instagram"}, now.Add(10*time.Minute))
	if len(got) != 1 || !strings.Contains(got[0], "Instagram works again") {
		t.Fatalf("second round: %q", got)
	}
	// another server is not held back by the first one's cooldown
	if got = st.igAlertLines("s2", []string{"router DOWN -> everything DIRECT"}, now); len(got) != 1 {
		t.Fatalf("other server: %q", got)
	}
}
