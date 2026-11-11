package main

import (
	"strings"
	"testing"
	"time"
)

// The web API redacts a job log for a user (jobView → logRedactor, TestHunt2JobLogRedacted):
// the SSH address/port of the admin's servers, jump hosts and their proxies. A user's own
// Telegram bot shows the same log raw: "📜 Last log" (lg:) on a tunnel of theirs that runs on
// the admin's server.
func TestHunt3UserBotLastLogNotRedacted(t *testing.T) {
	a, b, f := hunt2Bot(t, func(s *State) {
		s.Users = []User{{Username: "boss"}, {Username: "ali", Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s1", Name: "admin-iran", IPv4: "192.0.2.1", SSHHost: "203.0.113.9", SSHPort: 2222, Role: "iran"},
			{ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
			{ID: "s4", Name: "secret-jump", IPv4: "203.0.113.50", Proxy: "socks5://u:pw@203.0.113.60:1080"},
		}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "ali on admin", ServerID: "s1", ForeignID: "s3", Family: "v4", Ports: "443", Index: 9, Owner: "ali"}}
	})
	j, _ := a.jobs.start("aaaaaaaaaaaa", "apply")
	j.log("  direct SSH failed: dial tcp 203.0.113.9:2222: i/o timeout")
	j.log("  jump via secret-jump failed: jump host secret-jump unreachable: dial tcp 203.0.113.50:22: proxy socks5://u:pw@203.0.113.60:1080")
	j.finish("error")
	b.owner = "ali" // ali's own bot
	b.onCallback("42", 7, "cb", "lg:aaaaaaaaaaaa")
	got := strings.Join(f.texts(), "\n")
	if !strings.Contains(got, "last job") {
		t.Fatalf("no log sent:\n%s", got)
	}
	for _, leak := range []string{"203.0.113.9", "2222", "secret-jump", "203.0.113.50", "pw@"} {
		if strings.Contains(got, leak) {
			t.Errorf("ali's bot shows %q of the admin's servers:\n%s", leak, got)
		}
	}
}

// watchJob (every action from a user's bot: apply, stop, diagnose...) sends the ✓/✕/ERROR lines
// of the job raw too.
func TestHunt3UserBotWatchJobNotRedacted(t *testing.T) {
	a, b, f := hunt2Bot(t, func(s *State) {
		s.Users = []User{{Username: "boss"}, {Username: "ali", Role: roleUser}}
		s.Servers = []*Server{
			{ID: "s1", Name: "admin-iran", IPv4: "192.0.2.1", SSHHost: "203.0.113.9", SSHPort: 2222, Role: "iran"},
			{ID: "s3", Name: "ali-de", IPv4: "198.51.100.3", Role: "foreign", Owner: "ali"},
		}
		s.Tunnels = []*Tunnel{{ID: "aaaaaaaaaaaa", Name: "ali on admin", ServerID: "s1", ForeignID: "s3", Family: "v4", Ports: "443", Index: 9, Owner: "ali"}}
	})
	b.owner = "ali"
	j, _ := a.jobs.start("aaaaaaaaaaaa", "apply")
	j.log("ERROR: dial tcp 203.0.113.9:2222: i/o timeout")
	j.finish("error")
	b.watchJob("42", j, "Applying")
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(f.texts(), "\n"), "❌") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	got := strings.Join(f.texts(), "\n")
	if !strings.Contains(got, "❌") {
		t.Fatalf("no result:\n%s", got)
	}
	if strings.Contains(got, "203.0.113.9:2222") {
		t.Errorf("ali's bot shows the admin server's SSH address:\n%s", got)
	}
}
