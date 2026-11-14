package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupRestore(t *testing.T) {
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st, jobs: newJobs()}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran-1", IPv4: "10.0.0.1", Password: "pw"}}
		s.Tunnels = []*Tunnel{{ID: "t1", Name: "one", ServerID: "ir", Ports: "443", Index: 1}}
		return nil
	})
	data, err := a.backupJSON()
	if err != nil || !strings.Contains(string(data), `"pw"`) {
		t.Fatalf("backup: %v %s", err, data)
	}
	_ = st.Update(func(s *State) error { s.Servers, s.Tunnels = nil, nil; return nil })
	if _, err := a.restoreBackup([]byte(`{"servers":[]}`)); err == nil {
		t.Error("restored a file that isn't a backup")
	}
	msg, err := a.restoreBackup(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(msg)
	if s := st.Server("ir"); s == nil || s.Password != "pw" {
		t.Error("server not restored")
	}
	// the state before the restore was kept, and survives a reload
	if ents, _ := filepath.Glob(filepath.Join(a.backupDir(), "*.json")); len(ents) != 1 {
		t.Errorf("pre-restore backup: %v", ents)
	}
	st2, _ := LoadStore(dataDir)
	if st2.Server("ir") == nil {
		t.Error("restore not saved to disk")
	}
	_ = os.RemoveAll(a.backupDir())
}

// A backup that leaves the host has no session key (it would let the holder sign any
// cookie), and a restore always makes a new key, from either kind of backup.
func TestBackupNoSessionSecret(t *testing.T) {
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st, jobs: newJobs()}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran-1", IPv4: "10.0.0.1", Password: "pw"}}
		return nil
	})
	var key string
	st.View(func(s *State) { key = s.Secret })
	out, err := a.backupFileJSON()
	if err != nil || strings.Contains(string(out), key) || !strings.Contains(string(out), backupNoSecret) {
		t.Fatalf("session key in the download/Telegram backup (%v)", err)
	}
	st.View(func(s *State) {
		if s.Secret != key {
			t.Fatalf("making a backup changed the live key")
		}
	})
	local, _ := a.backupJSON()
	for _, data := range [][]byte{out, local} {
		if _, err := a.restoreBackup(data); err != nil {
			t.Fatal(err)
		}
		st.View(func(s *State) {
			if s.Secret == key || s.Secret == backupNoSecret || len(s.Secret) != 64 {
				t.Fatalf("restore kept a known session key")
			}
			key = s.Secret
		})
	}
}
