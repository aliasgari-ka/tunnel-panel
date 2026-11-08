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
			Secrets: map[string]string{"psk": "psk-secret"}}}
		s.Outages = []Outage{{ID: "o", Kind: "tunnel", Target: "t1", Name: "tun", Start: 1 << 40, Reason: "no answer from 81.12.32.26"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon()}
	aiNoteAlert("🔴 down: 159.195.1.2 unreachable")
	b, _ := json.Marshal(a.aiSnapshot())
	out := string(b)
	for _, bad := range []string{"81.12.32.26", "2a01:4f8", "159.195.1.2", "secret"} {
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
