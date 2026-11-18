package main

// The Google test account's session needs a Google page now and then.
//
// Chrome refreshes Google's short-lived session cookies (__Secure-1PSIDTS, SIDCC) only while a
// Google page asks for them. The test browser starts on about:blank and the panel's own checks no
// longer open the account's Gemini (they are keyless), so after the browser restart of
// 2026-11-14 17:23 UTC nothing of the account's touched Google for four days: the session
// cookies stayed (SID until 12-19), the refreshed ones ran out at 17:20, and Google then asked
// for the password again (a tab on accounts.google.com/v3/signin/challenge/pwd, 2026-11-17/18).
// The panel kept saying "signed in": it looked at SID only.
//
// So the panel keeps one Google page of the account open in the test browser (its own context,
// in the background, myaccount.google.com: it opens whatever Gemini makes of the exit) and
// reloads it every gemKeepEvery. A page of the account that sits on Google's sign-in or
// password step means Google wants the password: the account reads "out" (gemacct.go) and the
// admin is told, instead of "signed in".

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	gemKeepURL   = "https://myaccount.google.com/"
	gemKeepEvery = time.Hour
	gemKeepMax   = 2 // keep pages the panel opens at most (a person may close or reuse them)
)

var gemKeepMem = struct {
	sync.Mutex
	reloaded time.Time
}{}

// gemPage1 is one page target of the browser.
type gemPage1 struct {
	ID  string `json:"targetId"`
	Typ string `json:"type"`
	URL string `json:"url"`
	Ctx string `json:"browserContextId"`
}

// gemReauthURL: Google's sign-in or password step (the account must sign in again there).
func gemReauthURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Host, "accounts.google.com") {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasPrefix(p, "/v3/signin/") || strings.HasPrefix(p, "/signin/") ||
		p == "/servicelogin" || strings.HasPrefix(p, "/v2/signin")
}

// gemKeepPage: a page that keeps the session warm (a Google page of the account that is not a
// sign-in step).
func gemKeepPage(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, "myaccount.google.com")
}

// gemAccountPages: the account's own pages (its default context: no throw-away probe context).
func gemAccountPages(ctx context.Context, w *cdpConn) ([]gemPage1, error) {
	var bcs struct {
		IDs []string `json:"browserContextIds"`
	}
	if err := w.call(ctx, "", "Target.getBrowserContexts", nil, &bcs); err != nil {
		return nil, err
	}
	other := map[string]bool{}
	for _, id := range bcs.IDs {
		other[id] = true
	}
	var ts struct {
		Infos []gemPage1 `json:"targetInfos"`
	}
	if err := w.call(ctx, "", "Target.getTargets", nil, &ts); err != nil {
		return nil, err
	}
	var out []gemPage1
	for _, t := range ts.Infos {
		if t.Typ != "page" || other[t.Ctx] {
			continue
		}
		if _, probe := gemProbeCtxs.Load(t.Ctx); probe {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// gemKeepPlan: what to do with the account's pages: open a keep page, reload one (its id), and
// whether a page shows Google's sign-in step.
func gemKeepPlan(pages []gemPage1, lastReload, now time.Time) (open bool, reload string, reauth bool) {
	keep := 0
	for _, p := range pages {
		if gemReauthURL(p.URL) {
			reauth = true
		}
		if gemKeepPage(p.URL) {
			keep++
			if reload == "" {
				reload = p.ID
			}
		}
	}
	if keep == 0 {
		return !reauth, "", reauth // no new page over a sign-in step a person may be typing in
	}
	if now.Sub(lastReload) < gemKeepEvery {
		reload = ""
	}
	return false, reload, reauth
}

// gemKeep opens or reloads the keep page; true = a page of the account is on Google's sign-in step.
func gemKeep(ctx context.Context) (bool, error) {
	w, err := cdpDial(ctx, gemCDPAddr)
	if err != nil {
		return false, err
	}
	defer w.Close()
	pages, err := gemAccountPages(ctx, w)
	if err != nil {
		return false, err
	}
	gemKeepMem.Lock()
	last := gemKeepMem.reloaded
	gemKeepMem.Unlock()
	now := time.Now()
	open, reload, reauth := gemKeepPlan(pages, last, now)
	switch {
	case open:
		n := 0
		for _, p := range pages {
			if gemKeepPage(p.URL) {
				n++
			}
		}
		if n < gemKeepMax {
			err = w.call(ctx, "", "Target.createTarget", map[string]any{"url": gemKeepURL, "background": true}, nil)
		}
	case reload != "":
		var at struct {
			Session string `json:"sessionId"`
		}
		if err = w.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": reload, "flatten": true}, &at); err == nil {
			err = w.call(ctx, at.Session, "Page.reload", map[string]any{}, nil)
			_ = w.call(ctx, "", "Target.detachFromTarget", map[string]any{"sessionId": at.Session}, nil)
		}
	}
	if (open || reload != "") && err == nil {
		gemKeepMem.Lock()
		gemKeepMem.reloaded = now
		gemKeepMem.Unlock()
	}
	return reauth, err
}
