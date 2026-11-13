package main

// Which answer from Google ended the test account's session, and when.
//
// A standing DevTools connection to the test browser sees every response its pages get
// (Network.responseReceivedExtraInfo carries the raw Set-Cookie lines). When one of them deletes
// a Google session cookie (SID / __Secure-1PSID / __Secure-3PSID: an Expires in the past or
// Max-Age 0), the URL (no query), the HTTP status and the time are kept. Only cookie names are
// read, never a value. The sign-out alert then says exactly what happened: Google refusing the
// tab's routine session refresh (RotateCookies = Google revoked the session on its side), a
// sign-out page opened in the browser, or no page at all (Chrome's own account check, outside
// the pages, or the cookies went another way).
//
// Throw-away contexts of the account-less exit checks (gemProbe) are left out: they never hold
// the account.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gemCut is one answer that deleted the account's session cookies.
type gemCut struct {
	At     time.Time `json:"at"`
	URL    string    `json:"url"` // scheme://host/path, no query
	Status int       `json:"status"`
	Names  []string  `json:"names"`
}

var gemWatch = struct {
	sync.Mutex
	last gemCut
	up   time.Time // since when the watcher is connected (zero = not connected)
	seen int       // answers read since it connected (shows it works)
	tabs int       // pages and workers it listens to
}{}

// gemProbeCtxs: browser contexts of the account-less probes (not the account's).
var gemProbeCtxs sync.Map

// gemCookieCut: does this Set-Cookie line delete a Google session cookie? (its name if so)
func gemCookieCut(line string, now time.Time) (string, bool) {
	parts := strings.Split(line, ";")
	name, val, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if !ok || !gemSessionCookies[strings.TrimSpace(name)] {
		return "", false
	}
	name = strings.TrimSpace(name)
	cut := strings.TrimSpace(val) == "" || strings.EqualFold(strings.TrimSpace(val), "EXPIRED")
	for _, a := range parts[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(a), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "max-age":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n <= 0 {
				cut = true
			}
		case "expires":
			v = strings.TrimSpace(v)
			for _, f := range []string{http.TimeFormat, time.RFC1123, "Mon, 02-Jan-2006 15:04:05 MST", "Monday, 02-Jan-06 15:04:05 MST"} {
				if t, err := time.Parse(f, v); err == nil {
					if t.Before(now) {
						cut = true
					}
					break
				}
			}
		}
	}
	return name, cut
}

// gemCutsIn: the session cookies one response's headers delete.
func gemCutsIn(headers map[string]any, now time.Time) []string {
	var names []string
	for k, v := range headers {
		if !strings.EqualFold(k, "set-cookie") {
			continue
		}
		s, _ := v.(string)
		for _, l := range strings.Split(s, "\n") {
			if n, ok := gemCookieCut(l, now); ok {
				names = append(names, n)
			}
		}
	}
	return names
}

// gemBareURL: scheme://host/path (a query can hold tokens).
func gemBareURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return clipTo(s, 60)
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func gemWatchLoop() {
	time.Sleep(45 * time.Second)
	for {
		gemWatchOnce(gemCDPAddr)
		gemWatch.Lock()
		gemWatch.up = time.Time{}
		gemWatch.Unlock()
		time.Sleep(30 * time.Second)
	}
}

// gemWatchOnce holds one connection until it breaks.
func gemWatchOnce(addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	w, err := cdpDial(ctx, addr)
	cancel()
	if err != nil {
		return
	}
	defer w.Close()
	send := func(session, method string, params any) error {
		w.id++
		m := map[string]any{"id": w.id, "method": method, "params": params}
		if session != "" {
			m["sessionId"] = session
		}
		b, _ := json.Marshal(m)
		_ = w.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return w.writeFrame(1, b)
	}
	attach := map[string]any{"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true}
	if send("", "Target.setAutoAttach", attach) != nil {
		return
	}
	gemWatch.Lock()
	gemWatch.up, gemWatch.seen, gemWatch.tabs = time.Now(), 0, 0
	gemWatch.Unlock()
	urls := map[string]string{} // session/requestId -> url
	probe := map[string]bool{}  // sessions in a probe's context
	for {
		// an idle browser sends nothing: a quiet line is asked a question, a dead one breaks
		_ = w.c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		raw, err := w.readMsg()
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				if send("", "Target.getTargets", map[string]any{}) != nil {
					return
				}
				_ = w.c.SetReadDeadline(time.Now().Add(30 * time.Second))
				if _, err := w.readMsg(); err != nil {
					return
				}
				continue
			}
			return
		}
		var ev struct {
			Method  string          `json:"method"`
			Session string          `json:"sessionId"`
			Params  json.RawMessage `json:"params"`
		}
		if json.Unmarshal(raw, &ev) != nil || ev.Method == "" {
			continue
		}
		switch ev.Method {
		case "Target.attachedToTarget":
			var p struct {
				Session string `json:"sessionId"`
				Info    struct {
					Type string `json:"type"`
					Ctx  string `json:"browserContextId"`
				} `json:"targetInfo"`
			}
			if json.Unmarshal(ev.Params, &p) != nil {
				continue
			}
			if _, ok := gemProbeCtxs.Load(p.Info.Ctx); ok {
				probe[p.Session] = true
			}
			switch p.Info.Type {
			case "page", "iframe", "service_worker", "worker", "shared_worker":
				gemWatch.Lock()
				gemWatch.tabs++
				gemWatch.Unlock()
				_ = send(p.Session, "Network.enable", map[string]any{})
				_ = send(p.Session, "Target.setAutoAttach", attach) // out-of-process frames, workers
			}
		case "Target.detachedFromTarget":
			var p struct {
				Session string `json:"sessionId"`
			}
			_ = json.Unmarshal(ev.Params, &p)
			delete(probe, p.Session)
			gemWatch.Lock()
			if gemWatch.tabs > 0 {
				gemWatch.tabs--
			}
			gemWatch.Unlock()
		case "Network.requestWillBeSent":
			var p struct {
				ID  string `json:"requestId"`
				Req struct {
					URL string `json:"url"`
				} `json:"request"`
			}
			if json.Unmarshal(ev.Params, &p) == nil && !probe[ev.Session] {
				if len(urls) > 5000 {
					urls = map[string]string{}
				}
				urls[ev.Session+"/"+p.ID] = p.Req.URL
			}
		case "Network.responseReceivedExtraInfo":
			if probe[ev.Session] {
				continue
			}
			var p struct {
				ID      string         `json:"requestId"`
				Status  int            `json:"statusCode"`
				Headers map[string]any `json:"headers"`
			}
			if json.Unmarshal(ev.Params, &p) != nil {
				continue
			}
			now := time.Now()
			gemWatch.Lock()
			gemWatch.seen++
			gemWatch.Unlock()
			if names := gemCutsIn(p.Headers, now); len(names) > 0 {
				u := urls[ev.Session+"/"+p.ID]
				if u == "" {
					u = "(a request the watcher did not see start)"
				} else {
					u = gemBareURL(u)
				}
				gemWatch.Lock()
				gemWatch.last = gemCut{At: now, URL: u, Status: p.Status, Names: names}
				gemWatch.Unlock()
			}
		}
	}
}

// gemCutSince: the last cut at or after t (ok=false: none), and whether the watcher was
// connected all along since t (so "none" means no page was told to drop them).
func gemCutSince(t time.Time) (gemCut, bool, bool) {
	gemWatch.Lock()
	defer gemWatch.Unlock()
	watched := !gemWatch.up.IsZero() && !gemWatch.up.After(t)
	if gemWatch.last.At.IsZero() || gemWatch.last.At.Before(t) {
		return gemCut{}, false, watched
	}
	return gemWatch.last, true, watched
}

// gemCutWhy: the cause in words, from the cut a page saw ("" = nothing to say).
func gemCutWhy(c gemCut, ok, watched bool) string {
	if !ok {
		if watched {
			return "no page of the test browser was told to drop the session (the watcher saw every answer): Chrome's own account check outside the pages did, or the browser lost the cookies"
		}
		return ""
	}
	at := c.At.UTC().Format("01-02 15:04:05") + " UTC"
	low := strings.ToLower(c.URL)
	switch {
	case strings.Contains(low, "logout") || strings.Contains(low, "signout"):
		return "a sign-out page was opened in the test browser (" + c.URL + ", " + at + "): someone signed the account out by hand"
	case strings.Contains(low, "rotatecookies"):
		return "Google refused the Gemini tab's routine session refresh (" + c.URL + " → HTTP " + strconv.Itoa(c.Status) + ", " + at + ") and deleted " + strings.Join(c.Names, ", ") + ": Google revoked the session on its side"
	}
	return "Google deleted " + strings.Join(c.Names, ", ") + " in its answer to " + c.URL + " (HTTP " + strconv.Itoa(c.Status) + ", " + at + ")"
}

// gemWatchState for the page: connected since, answers seen, the last cut.
func gemWatchState() map[string]any {
	gemWatch.Lock()
	defer gemWatch.Unlock()
	m := map[string]any{"up": gemWatch.up, "seen": gemWatch.seen, "tabs": gemWatch.tabs}
	if !gemWatch.last.At.IsZero() {
		m["lastCut"] = gemWatch.last
	}
	return m
}
