package main

import (
	"strings"
	"testing"
	"time"
)

func TestGemSignedIn(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	later := float64(now.Add(time.Hour).Unix())
	// what the profile kept after Google's 2026-11-10 sign-out: no session cookie
	out := []gemCookie{{Name: "__Host-GAPS", Domain: "accounts.google.com", Expires: later},
		{Name: "OSID", Domain: "gemini.google.com", Expires: later}, {Name: "SID", Domain: ".google.de", Expires: later}}
	if gemSignedIn(out, now) {
		t.Fatal("signed in without a .google.com session cookie")
	}
	if gemSignedIn(append(out, gemCookie{Name: "SID", Domain: ".google.com", Expires: float64(now.Add(-time.Hour).Unix())}), now) {
		t.Fatal("an expired SID counts")
	}
	if !gemSignedIn(append(out, gemCookie{Name: "__Secure-1PSID", Domain: ".google.com", Expires: later}), now) {
		t.Fatal("a live __Secure-1PSID does not count")
	}
	if !gemSignedIn([]gemCookie{{Name: "SID", Domain: "google.com", Session: true, Expires: -1}}, now) {
		t.Fatal("a session SID does not count")
	}
}

// One message when it goes, a reminder a day, one when it is back; browser errors say nothing.
func TestGemAcctNote(t *testing.T) {
	g := &gemAcctT{}
	t0 := time.Unix(2_000_000_000, 0)
	if m := g.note("in", nil, t0); m != "" {
		t.Fatalf("first in: %q", m)
	}
	if m := g.note("out", nil, t0.Add(time.Minute)); !strings.Contains(m, "signed out") || !strings.Contains(m, gemHome) {
		t.Fatalf("going out: %q", m)
	}
	if m := g.note("out", nil, t0.Add(time.Hour)); m != "" {
		t.Fatalf("repeated within a day: %q", m)
	}
	if m := g.note("", errTest, t0.Add(2*time.Hour)); m != "" || g.State != "out" {
		t.Fatalf("browser error: %q state %q", m, g.State)
	}
	if m := g.note("out", nil, t0.Add(25*time.Hour)); m == "" {
		t.Fatal("no daily reminder")
	}
	if m := g.note("in", nil, t0.Add(26*time.Hour)); !strings.Contains(m, "signed in again") {
		t.Fatalf("back in: %q", m)
	}
	if s := g.snapshot(); s["state"] != "in" || s["exit"] != gemHome {
		t.Fatalf("snapshot %v", s)
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

var errTest = testErr("no browser")

// The account is never taken to another exit, not even by hand.
func TestGemSignedNeverAway(t *testing.T) {
	_, _, err := gemProbeAs(t.Context(), "socks5://192.0.2.1:12371", true)
	if err == nil || err.Error() != gemNoAway {
		t.Fatalf("signed probe away from home: %v", err)
	}
}
