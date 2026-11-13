package main

import (
	"context"
	"testing"
	"time"
)

func TestBetterPathWanted(t *testing.T) {
	for path, want := range map[string]bool{
		"direct SSH":           false,
		"SSH via proxy":        false,
		"agent":                false,
		"direct SSH over IPv6": true,
		"jump via xe108 iran":  true,
	} {
		if got := betterPathWanted(path); got != want {
			t.Errorf("betterPathWanted(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestBetterPathDueOncePerInterval(t *testing.T) {
	now := time.Now()
	id := "due-" + now.String()
	if !betterPathDue(id, now) {
		t.Fatal("first try not due")
	}
	if betterPathDue(id, now.Add(betterPathEvery/2)) {
		t.Fatal("due again before the interval")
	}
	if !betterPathDue(id, now.Add(betterPathEvery+time.Second)) {
		t.Fatal("not due after the interval")
	}
}

// A server the panel reached through a jump host (its direct SSH failed for a while) goes
// back to direct SSH once that works: the jump connection used to stay in use for as long
// as it answered keepalives (usa-kharej, 2026-11-13: "traffic: EOF").
func TestBackToDirectFromJump(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	viaPort, _ := countingSSHD(t)
	tgtPort, _ := countingSSHD(t)
	via := &Server{ID: "bvia", Name: "via", IPv4: "127.0.0.1", SSHPort: viaPort, Password: "x", Prepared: true}
	tgt := &Server{ID: "btgt", Name: "tgt", IPv4: "127.0.0.1", SSHPort: tgtPort, Password: "x", Prepared: true}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{via, tgt}; return nil })
	a := &App{store: st, jobs: newJobs()}
	ctx := context.Background()
	t.Cleanup(func() { dropHost(tgt.ID); dropHost(via.ID) })

	// the state after a lock-out: only the jump connection is cached
	jump := newSSHHost(st, tgt, a.jumpDial(ctx, via))
	if _, err := jump.client(); err != nil {
		t.Fatalf("jump connect: %v", err)
	}
	jumpKey, directKey := tgt.ID+"|jump via via", tgt.ID+"|direct SSH"
	reachCache.Lock()
	reachCache.m[jumpKey] = jump
	reachCache.Unlock()

	h, path, err := a.sshReach(ctx, tgt, func(string, ...any) {})
	if err != nil || h != Host(jump) || path != "jump via via" {
		t.Fatalf("first reach: %v %q %v (want the cached jump right away)", h, path, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		reachCache.Lock()
		_, d := reachCache.m[directKey]
		_, j := reachCache.m[jumpKey]
		reachCache.Unlock()
		if d && !j {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not back on direct SSH: direct cached %v, jump cached %v", d, j)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, path, err = a.sshReach(ctx, tgt, func(string, ...any) {}); err != nil || path != "direct SSH" {
		t.Fatalf("second reach: %q %v, want direct SSH", path, err)
	}
	if tgt.LastPath != "direct SSH" {
		t.Errorf("LastPath = %q, want direct SSH", tgt.LastPath)
	}
	// a fallback whose better path still fails stays in use, and no second try runs at once
	if betterPathDue(tgt.ID, time.Now()) {
		t.Error("a second try was due right after the first")
	}
}
