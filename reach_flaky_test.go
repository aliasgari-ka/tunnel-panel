package main

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// A direct address that accepts the connection and then says nothing must not use up the
// caller's whole deadline: the next path (the same server over IPv6) still gets its turn.
// ir-xe101-100, 2026-11-20: its IPv4 flapped, health checks spent their 40 s on it and the
// tunnels were reported "Iran server unreachable" while the server answered over IPv6.
func TestReachSilentDirectLeavesTimeForNextPath(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	port, _ := countingSSHD(t) // the "IPv6" address: 127.0.0.1
	hole, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("no second loopback address here: %v", err)
	}
	t.Cleanup(func() { hole.Close() })
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() }) // accepted, never answered
		}
	}()
	srv := &Server{ID: "silent4", Name: "silent4", IPv4: "127.0.0.2", IPv6: "127.0.0.1", SSHPort: port, Password: "x", Prepared: true}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{srv}; return nil })
	a := &App{store: st, jobs: newJobs()}
	t.Cleanup(func() { dropHost(srv.ID) })

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	start := time.Now()
	_, path, err := a.sshReach(ctx, srv, func(string, ...any) {})
	if err != nil || path != "direct SSH over IPv6" {
		t.Fatalf("reach = %q, %v after %s; want direct SSH over IPv6", path, err, time.Since(start).Round(time.Millisecond))
	}
}

// A cached connection that no longer answers is dropped, not dialled anew inside the lookup
// (that dial ignored the caller's deadline).
func TestReachDeadCachedIsNotRedialledInPlace(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	port, _ := countingSSHD(t)
	srv := &Server{ID: "deadc", Name: "deadc", IPv4: "127.0.0.1", SSHPort: port, Password: "x", Prepared: true}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{srv}; return nil })
	a := &App{store: st, jobs: newJobs()}
	t.Cleanup(func() { dropHost(srv.ID) })

	var dials atomic.Int32
	dead := newSSHHost(st, srv, func(addr string) (net.Conn, error) { dials.Add(1); return directDial(addr) })
	key := srv.ID + "|direct SSH"
	reachCache.Lock()
	reachCache.m[key] = dead // never connected: answers nothing
	reachCache.Unlock()

	h, path, err := a.sshReach(context.Background(), srv, func(string, ...any) {})
	if err != nil || path != "direct SSH" {
		t.Fatalf("reach = %q, %v", path, err)
	}
	if h == Host(dead) || dials.Load() != 0 {
		t.Fatalf("the dead cached connection was dialled again in place (%d dials)", dials.Load())
	}
}

func TestDialShare(t *testing.T) {
	now := time.Now()
	// no deadline (a job): the path may take as long as it needs
	if _, cancel, share := dialShare(context.Background(), 3, now); share != 0 {
		t.Errorf("no deadline: share %s, want 0", share)
	} else {
		cancel()
	}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(40*time.Second))
	defer cancel()
	// the last path: all that is left
	if _, c, share := dialShare(ctx, 0, now); share != 0 {
		t.Errorf("last path: share %s, want 0", share)
	} else {
		c()
	}
	dctx, c, share := dialShare(ctx, 2, now)
	defer c()
	if share != 20*time.Second {
		t.Errorf("share = %s, want 20s", share)
	}
	if dl, _ := dctx.Deadline(); dl.Sub(now) != 20*time.Second {
		t.Errorf("deadline in %s, want 20s", dl.Sub(now))
	}
}

// Going back to a better path that does not last is tried later and later, and from the
// start again once a return lasted.
func TestBetterPathBackoff(t *testing.T) {
	now := time.Now()
	id := "flap-" + now.String()
	if !betterPathDue(id, now) {
		t.Fatal("first try not due")
	}
	// went back, and on the fallback again a minute later: 2 → 4 min
	betterPathBack(id, now)
	now = now.Add(time.Minute)
	if betterPathDue(id, now.Add(betterPathEvery)) {
		t.Fatal("due after 2 min although the last return did not last")
	}
	if !betterPathDue(id, now.Add(2*betterPathEvery)) {
		t.Fatal("not due after 4 min")
	}
	// it keeps failing to last: never beyond betterPathMax
	for i := 0; i < 10; i++ {
		now = now.Add(time.Hour)
		betterPathBack(id, now)
		if !betterPathDue(id, now.Add(time.Minute)) {
			t.Fatalf("round %d: not due an hour after the last try", i)
		}
	}
	betterPath.Lock()
	w := betterPath.wait[id]
	betterPath.Unlock()
	if w != betterPathMax {
		t.Fatalf("wait = %s, want %s", w, betterPathMax)
	}
	// a return that lasted: back to the short interval
	now = now.Add(time.Hour)
	betterPathBack(id, now)
	now = now.Add(betterPathHeld + time.Minute)
	if !betterPathDue(id, now) {
		t.Fatal("not due after a return that lasted")
	}
	if betterPathDue(id, now.Add(betterPathEvery/2)) || !betterPathDue(id, now.Add(betterPathEvery+time.Second)) {
		t.Fatal("interval not back to betterPathEvery")
	}
}
