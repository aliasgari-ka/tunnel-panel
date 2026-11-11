package main

// Is the Google test account still signed in? Read from the test browser's own cookie jar over
// DevTools (Storage.getCookies): no page is opened and nothing goes to Google, so asking costs
// the account nothing. Google's session cookies (SID / __Secure-1PSID on .google.com) are what
// it clears when it ends a session; the profile keeps everything else (that is how the 2026-11-10
// sign-out looked). The admin gets one message when it goes, a reminder a day while it stays
// signed out, and one when it is back; the IG Routing page shows it on the test browser button.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// gemCookie is the part of a CDP cookie read here (never its value).
type gemCookie struct {
	Name    string  `json:"name"`
	Domain  string  `json:"domain"`
	Expires float64 `json:"expires"` // unix seconds; -1 = a session cookie
	Session bool    `json:"session"`
}

// gemSessionCookies are the ones Google drops when it signs the account out.
var gemSessionCookies = map[string]bool{"SID": true, "__Secure-1PSID": true, "__Secure-3PSID": true}

// gemSignedIn: a Google session cookie for .google.com that has not expired.
func gemSignedIn(cs []gemCookie, now time.Time) bool {
	for _, c := range cs {
		d := strings.TrimPrefix(c.Domain, ".")
		if d != "google.com" || !gemSessionCookies[c.Name] {
			continue
		}
		if c.Session || c.Expires <= 0 || int64(c.Expires) > now.Unix() {
			return true
		}
	}
	return false
}

// gemAcctRead asks the test browser: "in" | "out".
func gemAcctRead(ctx context.Context) (string, error) {
	w, err := cdpDial(ctx, gemCDPAddr)
	if err != nil {
		return "", fmt.Errorf("Google test browser: %w", err)
	}
	defer w.Close()
	var r struct {
		Cookies []gemCookie `json:"cookies"`
	}
	if err := w.call(ctx, "", "Storage.getCookies", nil, &r); err != nil {
		return "", err
	}
	if gemSignedIn(r.Cookies, time.Now()) {
		return "in", nil
	}
	return "out", nil
}

// gemAcctT is the last answer: State "in" | "out" | "" (not known: the browser did not answer).
type gemAcctT struct {
	mu      sync.Mutex
	State   string    `json:"state"`
	Since   time.Time `json:"since"`   // when State became what it is
	Checked time.Time `json:"checked"` // last answer from the browser
	Err     string    `json:"err,omitempty"`
	told    time.Time // last message about a signed-out account
}

var gemAcct = &gemAcctT{}

// note records one reading and says what to tell the admin ("" = nothing).
func (g *gemAcctT) note(state string, err error, now time.Time) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.Err = err.Error()
		return "" // the browser's own outages are told by gb-tunnel / the tunnel alerts
	}
	g.Err, g.Checked = "", now
	prev := g.State
	if state != prev {
		g.State, g.Since = state, now
	}
	switch {
	case state == "out" && (prev != "out" || now.Sub(g.told) >= 24*time.Hour):
		g.told = now
		return "🔑 The Google test account is signed out of the test browser (Google ended its session). The signed-in Gemini check is blind until you log in again: IG Routing → 🔑 Google test browser. It goes out through " + gemHome + " (the panel host's own IP)."
	case state == "in" && prev == "out":
		g.told = time.Time{}
		return "🔑 The Google test account is signed in again."
	}
	return ""
}

func (g *gemAcctT) snapshot() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]any{"state": g.State, "since": g.Since, "checked": g.Checked, "err": g.Err, "exit": gemHome}
}

const gemAcctTick = 10 * time.Minute

func (a *App) gemAcctLoop() {
	time.Sleep(90 * time.Second)
	for ; ; time.Sleep(gemAcctTick) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		st, err := gemAcctRead(ctx)
		cancel()
		if msg := gemAcct.note(st, err, time.Now()); msg != "" {
			a.push(msg)
		}
	}
}

// GET /api/igproxy/gaccount: the test account's state for the page (admin only).
// It reads the browser afresh when the last answer is older than a minute (local, costs Google
// nothing), so the page shows a new sign-in at once.
func (s *Server2) gemAcctGet(w http.ResponseWriter, r *http.Request) {
	gemAcct.mu.Lock()
	old := time.Since(gemAcct.Checked) > time.Minute
	gemAcct.mu.Unlock()
	if old {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		st, err := gemAcctRead(ctx)
		cancel()
		if msg := gemAcct.note(st, err, time.Now()); msg != "" {
			s.app.push(msg)
		}
	}
	writeJSON(w, gemAcct.snapshot())
}
