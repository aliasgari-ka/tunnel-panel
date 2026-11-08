package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// What goes to Claude names the servers but carries no address, password, key or token.
func TestAISnapshotNoSecrets(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Settings.ClaudeKey = "sk-ant-secret"
		s.Settings.TelegramTok = "123:tgsecret"
		s.Servers = []*Server{
			{ID: "ir", Name: "iran1", Role: "iran", IPv4: "81.12.32.26", IPv6: "2a01:4f8:1:2::5", Password: "pw-secret", PrivateKey: "KEY-secret"},
			{ID: "fo", Name: "germany", Role: "foreign", IPv4: "159.195.1.2", AgentToken: "agent-secret"},
		}
		s.Tunnels = []*Tunnel{{ID: "t1", Name: "tun", ServerID: "ir", ForeignID: "fo", Family: "v4", Ports: "443", Index: 1, Active: "gre",
			Secrets:  map[string]string{"psk": "psk-secret"},
			Failover: &FailoverState{Method: "gre", Family: "v4", Reason: "no answer from 81.12.32.26"}}}
		s.Outages = []Outage{{ID: "o", Kind: "tunnel", Target: "t1", Name: "tun", Start: 1 << 40, Reason: "no answer from 81.12.32.26"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon(),
		healthCache: map[string]string{"t1": "license IP 81.12.32.26 does not match"}}
	a.traffic.res = map[string]*ServerRes{"fo": {Error: "unreachable: dial tcp 159.195.1.2:22: i/o timeout",
		IRQHint: "one core of 2a01::1 does the packet work"}}
	aiNoteAlert("🔴 down: 159.195.1.2 unreachable")
	b, _ := json.Marshal(a.aiSnapshot())
	out := string(b)
	for _, bad := range []string{"81.12.32.26", "2a01:4f8", "2a01::1", "159.195.1.2", "secret"} {
		if strings.Contains(out, bad) {
			t.Errorf("snapshot carries %q", bad)
		}
	}
	for _, want := range []string{"iran1", "germany", `"tun"`} {
		if !strings.Contains(out, want) {
			t.Errorf("snapshot lacks %s", want)
		}
	}
}

// Short IPv6 addresses go too; times stay.
func TestAIRedactIPv6Short(t *testing.T) {
	for in, want := range map[string]string{
		"from 2a01::1 down":           "from <ip> down",
		"fe80::1: timeout":            "<ip>: timeout",
		"[2a01:4f8::5]:443":           "[<ip>]:443",
		"at 15:04 and 12:30:00":       "at 15:04 and 12:30:00",
		"std::vector":                 "std::vector",
		"2a01:4f8:1:2::5 and 1.2.3.4": "<ip> and <ip>",
	} {
		if got := aiRedact(in); got != want {
			t.Errorf("aiRedact(%q) = %q, want %q", in, got, want)
		}
	}
}

// Outages come one line per tunnel; a flapping alert once, with how many times.
func TestAISummaries(t *testing.T) {
	now := int64(1_000_000)
	outs := aiOutages([]Outage{
		{Kind: "tunnel", Target: "t1", Name: "a", Start: now - 3600, End: now - 3000},
		{Kind: "tunnel", Target: "t1", Name: "a", Start: now - 600, End: 0},
		{Kind: "tunnel", Target: "t2", Name: "b", Start: now - 1_000_000, End: now - 999_000}, // too old
	}, now-7*86400, now)
	if len(outs) != 1 || outs[0].Count != 2 || outs[0].DownMin != 20 || outs[0].Longest != 10 || !outs[0].Ongoing {
		t.Errorf("outages: %+v", outs)
	}
	al := aiAlertSummary([]aiAlert{{now - 50, "path 1 down for 31s"}, {now - 40, "path 1 down for 45s"}, {now - 30, "other"}}, now-100)
	if len(al) != 2 || al[1]["times"] != 2 || al[0]["msg"] != "other" {
		t.Errorf("alerts: %+v", al)
	}
}

// The daily run's Telegram message: the summary, one line per finding, and a pointer to the actions.
func TestAIMessage(t *testing.T) {
	m := aiMessage(&AIReport{Summary: "ok", Findings: []AIFinding{{Severity: "high", Title: "t1 flaps"}}, Actions: []AIAction{{}}})
	for _, want := range []string{"ok", "🔴 t1 flaps", "1 suggested"} {
		if !strings.Contains(m, want) {
			t.Errorf("message lacks %q: %s", want, m)
		}
	}
	if m := aiMessage(&AIReport{Error: "no credit"}); !strings.Contains(m, "no credit") {
		t.Errorf("error not sent: %s", m)
	}
}
