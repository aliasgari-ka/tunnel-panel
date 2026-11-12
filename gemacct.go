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

// gemAcctRead asks the test browser: "in" | "out", and how many Google cookies it holds at all
// (none = the profile itself was emptied, not just the session ended).
func gemAcctRead(ctx context.Context) (string, int, error) {
	w, err := cdpDial(ctx, gemCDPAddr)
	if err != nil {
		return "", 0, fmt.Errorf("Google test browser: %w", err)
	}
	defer w.Close()
	var r struct {
		Cookies []gemCookie `json:"cookies"`
	}
	if err := w.call(ctx, "", "Storage.getCookies", nil, &r); err != nil {
		return "", 0, err
	}
	n := 0
	for _, c := range r.Cookies {
		if d := strings.TrimPrefix(c.Domain, "."); d == "google.com" || strings.HasSuffix(d, ".google.com") {
			n++
		}
	}
	if gemSignedIn(r.Cookies, time.Now()) {
		return "in", n, nil
	}
	return "out", n, nil
}

// gemAcctCause: the likeliest reason the account is signed out, from what the panel saw.
// risk = gemHomeRecent (users' Google on the account's IP); ncookies = Google cookies left;
// dom = Google's country for the home exit now ("" = not known).
func gemAcctCause(risk string, ncookies int, dom string) string {
	var why []string
	if risk != "" {
		why = append(why, risk)
	}
	if ncookies == 0 {
		why = append(why, "the browser profile was emptied (no Google cookies at all): the profile was wiped or recreated")
	}
	if dom != "" && !gemDomIs(dom, "de") {
		why = append(why, "Google places the account's exit "+gemHomeHost()+" in ."+dom+" now (it was .de)")
	}
	if len(why) == 0 {
		return "Google ended the session itself (its session cookies were cleared, the rest of the profile is intact); no route change, profile wipe or exit move was seen"
	}
	return strings.Join(why, "; ")
}

// gemAcctT is the last answer: State "in" | "out" | "" (not known: the browser did not answer).
type gemAcctT struct {
	mu      sync.Mutex
	State   string    `json:"state"`
	Since   time.Time `json:"since"`   // when State became what it is
	Checked time.Time `json:"checked"` // last answer from the browser
	Err     string    `json:"err,omitempty"`
	Cause   string    `json:"cause,omitempty"` // why it is signed out (set when it went)
	told    time.Time // last message about a signed-out account
}

var gemAcct = &gemAcctT{}

// wentOut: would this reading be the moment the account is found signed out?
func (g *gemAcctT) wentOut(state string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return state == "out" && g.State != "out"
}

// note records one reading and says what to tell the admin ("" = nothing). cause is used when
// the account has just gone out.
func (g *gemAcctT) note(state, cause string, err error, now time.Time) string {
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
		g.Cause = ""
		if state == "out" {
			g.Cause = cause
		}
	}
	switch {
	case state == "out" && (prev != "out" || now.Sub(g.told) >= 24*time.Hour):
		g.told = now
		why := ""
		if g.Cause != "" {
			why = "\nWhy: " + g.Cause + "."
		}
		return "🔑 The Google test account is signed out of the test browser." + why + "\nThe signed-in Gemini check is blind until you log in again: IG Routing → 🔑 Google test account. It goes out through " + gemHome + " (the panel host's own IP, Germany)."
	case state == "in" && prev == "out":
		g.told = time.Time{}
		return "🔑 The Google test account is signed in again."
	}
	return ""
}

func (g *gemAcctT) snapshot() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]any{"state": g.State, "since": g.Since, "checked": g.Checked, "err": g.Err, "exit": gemHome, "cause": g.Cause}
}

const gemAcctTick = 10 * time.Minute

func (a *App) gemAcctLoop() {
	time.Sleep(90 * time.Second)
	for ; ; time.Sleep(gemAcctTick) {
		// first the guard: users' Google must not share the account's IP
		gctx, gcancel := context.WithTimeout(context.Background(), 4*time.Minute)
		if msg := a.gemHomeGuard(gctx); msg != "" {
			a.push(msg)
		}
		gcancel()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		st, n, err := gemAcctRead(ctx)
		cancel()
		if msg := gemAcct.note(st, a.gemAcctWhy(st, n, err), err, time.Now()); msg != "" {
			a.push(msg)
		}
	}
}

// gemAcctWhy works the cause out only when the account has just gone out (one keyless page
// fetch through the home exit, no account in it).
func (a *App) gemAcctWhy(st string, n int, err error) string {
	if err != nil || !gemAcct.wentOut(st) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return gemAcctCause(gemHomeRecent(time.Now()), n, gemDom(ctx, gemHome))
}

// GET /api/igproxy/gaccount: the test account's state for the page (admin only).
// It reads the browser afresh when the last answer is older than a minute (local, costs Google
// nothing), so the page shows a new sign-in at once.
func (s *Server2) gemAcctGet(w http.ResponseWriter, r *http.Request) {
	// ?fresh=1 (the sign-in window polls it): read again after 3 s instead of a minute
	age := time.Minute
	if r.URL.Query().Get("fresh") == "1" {
		age = 3 * time.Second
	}
	gemAcct.mu.Lock()
	old := time.Since(gemAcct.Checked) > age
	gemAcct.mu.Unlock()
	if old {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		st, n, err := gemAcctRead(ctx)
		cancel()
		if msg := gemAcct.note(st, s.app.gemAcctWhy(st, n, err), err, time.Now()); msg != "" {
			s.app.push(msg)
		}
	}
	writeJSON(w, gemAcct.snapshot())
}
