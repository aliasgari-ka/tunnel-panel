package main

import (
	"testing"
	"time"
)

// An open bridge follows the bind asked last: a public one asked again as localhost-only
// is closed and opened anew on 127.0.0.1, and the old one's Close leaves the new one alone.
func TestBridgeBindFollowsRequest(t *testing.T) {
	a := &App{}
	srv := &Server{ID: "bridge-test"}
	pub, err := a.OpenBridge(srv, true, time.Minute)
	if err != nil {
		t.Skip("cannot listen on 0.0.0.0:", err)
	}
	if pub.Bind != "0.0.0.0" {
		t.Fatalf("bind %s", pub.Bind)
	}
	loc, err := a.OpenBridge(srv, false, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer loc.Close()
	if loc == pub || loc.Bind != "127.0.0.1" {
		t.Fatalf("localhost asked, got bind %s (same bridge: %v)", loc.Bind, loc == pub)
	}
	if again, _ := a.OpenBridge(srv, false, time.Minute); again != loc {
		t.Error("the same bind should refresh the open bridge")
	}
	pub.Close() // the old reaper's late Close
	bridges.mu.Lock()
	cur := bridges.m[srv.ID]
	bridges.mu.Unlock()
	if cur != loc {
		t.Error("closing the replaced bridge dropped the new one")
	}
}
