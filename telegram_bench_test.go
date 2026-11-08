package main

import (
	"strings"
	"testing"
	"time"
)

// The bot's benchmark history shows Tehran time, like the rest of the bot.
func TestBotBenchHistoryTehranTime(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	at := time.Date(2026, 3, 1, 20, 0, 0, 0, time.UTC) // 23:30 in Tehran
	_ = st.Update(func(s *State) error {
		s.BenchHistory = []BenchRecord{{At: at.Unix(), IranID: "i", ForeignID: "k", IranName: "iran", ForeignName: "de", Family: "v4"}}
		return nil
	})
	oldLocal := time.Local
	time.Local = time.UTC // the panel host's own zone
	defer func() { time.Local = oldLocal }()
	b := newBot(&App{store: st}, "TOKEN", "42")
	if out := b.benchHistoryText(""); !strings.Contains(out, "Mar 1 23:30") {
		t.Errorf("not in Tehran time:\n%s", out)
	}
}
