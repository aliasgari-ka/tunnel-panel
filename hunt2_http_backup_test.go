package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkBackup runs the forms' checks and the panel's own invariants: a tampered backup put
// shell into the shaping script, the GitHub prefix or the FRP version, a path into an
// account name, and clashing tunnel numbers into the interfaces.
func TestHunt2BackupChecks(t *testing.T) {
	good := func() *State {
		return &State{
			Users:   []User{{Username: "boss"}, {Username: "ali", Role: roleUser}},
			Servers: []*Server{{ID: "ir", Role: "iran"}, {ID: "kh", Role: "foreign", Owner: "ali"}},
			Tunnels: []*Tunnel{
				{ID: "t1", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "gre", Selected: "gre",
					HotStandby: true, Paths: []HSPath{{Method: "gre", Family: "v4", Index: 1}, {Method: "direct6", Family: "v6", Index: 2}}},
				{ID: "t2", ServerID: "ir", Family: "v4", Ports: "8443", Index: 3, Owner: "ali"},
			},
		}
	}
	if err := checkBackup(good()); err != nil {
		t.Fatalf("a good backup: %v", err)
	}
	for name, bad := range map[string]func(*State){
		"github prefix":       func(s *State) { s.Settings.GitHubProxy = "https://x/$(id)" },
		"frp version":         func(s *State) { s.Settings.FRPVersion = "0.61.1;reboot" },
		"username":            func(s *State) { s.Users[1].Username = "../../etc" },
		"duplicate username":  func(s *State) { s.Users[1].Username = "boss" },
		"server owner":        func(s *State) { s.Servers[1].Owner = "../x" },
		"tunnel owner":        func(s *State) { s.Tunnels[1].Owner = ".." },
		"duplicate server":    func(s *State) { s.Servers[1].ID = "ir" },
		"duplicate tunnel id": func(s *State) { s.Tunnels[1].ID = "t1" },
		"duplicate index":     func(s *State) { s.Tunnels[1].Index = 1 },
		"path index clash":    func(s *State) { s.Tunnels[1].Index = 2 },
		"path index 250":      func(s *State) { s.Tunnels[0].Paths[1].Index = 250 },
		"two paths, one num":  func(s *State) { s.Tunnels[0].Paths[1].Index = 1 },
		"unknown active":      func(s *State) { s.Tunnels[0].Active = "x;reboot" },
		"unknown selected":    func(s *State) { s.Tunnels[1].Selected = "nope" },
		"unknown path method": func(s *State) { s.Tunnels[0].Paths[1].Method = "nope" },
		"unknown pin":         func(s *State) { s.Tunnels[0].HSPin = "nope|v4" },
		"failover method":     func(s *State) { s.Tunnels[0].Failover = &FailoverState{Method: "nope"} },
		"empty ports":         func(s *State) { s.Tunnels[1].Ports = "" },
	} {
		st := good()
		bad(st)
		if err := checkBackup(st); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the shaping layer is clamped like the form does (its interface goes into a script)
	st := good()
	st.Tunnels[0].Shape = Shape{Enabled: true, Qdisc: "cake; reboot", Iface: `eth0"; reboot; "`}
	if err := checkBackup(st); err != nil {
		t.Fatal(err)
	}
	if sh := st.Tunnels[0].Shape; sh.Iface != "" || sh.Qdisc != "cake" {
		t.Fatalf("shape not normalized: %+v", sh)
	}
}

// Every restore keeps its own copy of the state before it: two in one minute shared a name,
// and the second overwrote the first one's copy with the state the first had brought in.
func TestHunt2PreRestoreCopies(t *testing.T) {
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st, jobs: newJobs()}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "original", IPv4: "192.0.2.1"}}
		return nil
	})
	data, _ := a.backupJSON()
	for i := 0; i < 2; i++ {
		if _, err := a.restoreBackup(data); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := filepath.Glob(filepath.Join(a.backupDir(), "tunnel-panel-backup-*pre-restore*.json"))
	if len(ents) != 2 {
		t.Fatalf("pre-restore copies: %v", ents)
	}
	// a daily backup in the same second doesn't replace one either
	p1, err := a.saveLocalBackup()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := a.saveLocalBackup()
	if err != nil || p1 == p2 {
		t.Fatalf("second backup %q (%v) replaced %q", p2, err, p1)
	}
	if _, err := os.Stat(p1); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(p1), "tunnel-panel-backup-") {
		t.Fatal(p1)
	}
	_ = os.RemoveAll(a.backupDir())
}
