package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// hsRepairFake is an Iran server whose hot-standby switcher answers as told: read fails the
// state read (a dropped SSH session), runs says the switcher unit runs, status is its status
// lines and active the users' path.
type hsRepairFake struct {
	read, runs bool
	status     string
	active     string
}

func (f *hsRepairFake) Label() string                               { return "fake" }
func (f *hsRepairFake) WriteFile(string, []byte, os.FileMode) error { return nil }
func (f *hsRepairFake) Run(_ context.Context, s string, _ func(string)) (string, error) {
	switch {
	case strings.Contains(s, `echo "K $(cat keys`):
		if !f.read {
			return "", errors.New("ssh: handshake failed: EOF")
		}
		return "K gre|v4 bp_reverse|v4 tpk|v4\nA " + f.active + "\nM auto\nC 1000\n" + f.status + "U active\n", nil
	case strings.Contains(s, "SWRUNS"):
		if f.runs {
			return "SWRUNS\n", nil
		}
		return "", nil
	case strings.Contains(s, "MEMNEED"):
		return "MEMNEED\n", nil
	}
	return "", nil
}

func hsRepairApp(t *testing.T, f Host) *App {
	t.Helper()
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "192.0.2.1", Role: "iran"}, {ID: "kh", Name: "us", IPv4: "198.51.100.2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "usa", Name: "usa", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Active: "gre", HotStandby: true, HSAuto: true,
			HSPin: "bp_reverse|v4", Options: map[string]map[string]string{}, Secrets: map[string]string{},
			Paths: []HSPath{{Method: "gre", Family: "v4", Index: 4}, {Method: "bp_reverse", Family: "v4", Index: 20}, {Method: "tpk", Family: "v4", Index: 46}}}}
		// every other method left out on this tunnel: the route plans just these three paths
		for _, m := range methods {
			if m.ID != "gre" && m.ID != "bp_reverse" && m.ID != "tpk" {
				s.Tunnels[0].HSOff = append(s.Tunnels[0].HSOff, m.ID+"|v4", m.ID+"|v6")
			}
		}
		return nil
	})
	return &App{store: st, jobs: newJobs(), agents: newAgentHub(), traffic: newTrafficMon(), hostFor: func(*Server) Host { return f }}
}

func hsRepairCheck(t *testing.T, f *hsRepairFake) *RepairTunnel {
	t.Helper()
	a := hsRepairApp(t, f)
	// the route's choices match the running paths: only the switcher's state is looked at
	if drop, put := a.hsPathDiff(a.store.Tunnel("usa")); len(drop)+len(put) > 0 {
		t.Skipf("the test route plans other paths here (%d to drop, %d to add)", len(drop), len(put))
	}
	res := a.repairCheckAll(context.Background(), a.runningTunnels(nil))
	if len(res) != 1 {
		t.Fatalf("got %d tunnels", len(res))
	}
	return res[0]
}

func hasReapply(rt *RepairTunnel) bool {
	for _, it := range rt.Items {
		if it.Kind == rkReapply {
			return true
		}
	}
	return false
}

// 2026-11-14, تانل آمریکا: the repair after an update rebuilt a working hot-standby tunnel and
// cut its users ~20 s. A state read that fails while the switcher runs is no reason for that.
func TestRepairNoRebuildWhenStateUnreadable(t *testing.T) {
	rt := hsRepairCheck(t, &hsRepairFake{read: false, runs: true})
	if hasReapply(rt) || !strings.Contains(rt.Note, "could not be read") {
		t.Fatalf("want no rebuild and a note: %+v", rt)
	}
	// a switcher that doesn't run is still rebuilt
	rt = hsRepairCheck(t, &hsRepairFake{read: false, runs: false})
	if !hasReapply(rt) {
		t.Fatalf("a switcher that isn't running must be rebuilt: %+v", rt)
	}
}

// The users' path is down and other paths answer: the switcher moves them itself.
func TestRepairNoRebuildWhenOthersAnswer(t *testing.T) {
	rt := hsRepairCheck(t, &hsRepairFake{read: true, active: "0 1000", status: "S 0 down 900 - - -\nS 1 ok 900 170 0 -\nS 2 ok 900 175 0 -\n"})
	if hasReapply(rt) || !strings.Contains(rt.Note, "moves them") {
		t.Fatalf("want no rebuild: %+v", rt)
	}
	// every path down: rebuilt
	rt = hsRepairCheck(t, &hsRepairFake{read: true, active: "0 1000", status: "S 0 down 900 - - -\nS 1 down 900 - - -\nS 2 down 900 - - -\n"})
	if !hasReapply(rt) {
		t.Fatalf("every path down must be rebuilt: %+v", rt)
	}
}
