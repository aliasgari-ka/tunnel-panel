package main

import (
	"strings"
	"testing"
	"time"
)

// Routine events skip Telegram unless "send every event" is on, but still reach the analysis.
func TestPushInfoQuiet(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	sent := make(chan string, 4)
	a := &App{store: st, jobs: newJobs()}
	a.notify = func(m string) { sent <- m }
	a.pushInfo("📊 routine one")
	select {
	case m := <-sent:
		t.Errorf("routine event sent by default: %s", m)
	case <-time.After(200 * time.Millisecond):
	}
	found := false
	aiAlerts.Lock()
	defer aiAlerts.Unlock()
	for _, x := range aiAlerts.l {
		found = found || strings.Contains(x.Msg, "routine one")
	}
	if !found {
		t.Errorf("routine event not kept for the analysis")
	}
	_ = st.Update(func(s *State) error { s.Settings.BotAll = "on"; return nil })
	a.pushInfo("📊 routine two")
	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Errorf("routine event not sent with botAll on")
	}
}
