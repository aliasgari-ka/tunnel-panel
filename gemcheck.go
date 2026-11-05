package main

// The signed-in Gemini check. Google can refuse Gemini to a signed-in account ("not supported
// in your country") on an exit that every keyless check passes; only a signed-in browser sees
// it. The Google test browser (gbrowser.go) holds the test account; its DevTools port reaches
// the panel host over the same SSH tunnel (gemCDPAddr). For a server, the page is opened in a
// fresh browser context whose proxy is that server's "users' route" relay (the agent's socks
// port RELAY_BASE-1, open to our servers only): Google sees exactly the exit the users get.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	gemCDPAddr   = "127.0.0.1:9277"
	gemRelayPort = 12370 // the agent's relay that follows the users' routes (RELAY_BASE-1)
	gemURL       = "https://gemini.google.com/app"
)

// gemPage is what the page showed.
type gemPage struct {
	URL    string `json:"u"`
	Title  string `json:"ti"`
	Input  bool   `json:"inp"`
	SignIn bool   `json:"signin"`
	Text   string `json:"t"`
}

const gemPageJS = `(() => { const t = (document.body && document.body.innerText) || '';
 return JSON.stringify({u: location.href, ti: document.title,
  inp: !!document.querySelector('rich-textarea, div.ql-editor[contenteditable="true"]'),
  signin: !!document.querySelector('a[href*="ServiceLogin"], a[href*="/signin"]'),
  t: t.slice(0, 1500)}); })()`

// Gemini's own words for an account it will not serve.
var gemRefusals = []string{"not supported in your country", "isn't currently supported", "isn't available in your country",
	"not available in your country", "not available in your region", "isn't available for your account"}

// gemVerdict: ok | refused | signedout | captcha | "" (not decided yet).
func gemVerdict(p gemPage) string {
	low := strings.ToLower(p.Text)
	for _, r := range gemRefusals {
		if strings.Contains(low, r) {
			return "refused"
		}
	}
	switch {
	case strings.Contains(p.Text, "That’s an error") || strings.Contains(p.Text, "That's an error"):
		return "refused" // "403. That’s an error. Your client does not have permission…"
	case strings.Contains(p.URL, "google.com/sorry") || strings.Contains(low, "unusual traffic"):
		return "captcha"
	case strings.HasPrefix(p.URL, "https://accounts.google.com/"):
		return "signedout"
	case p.Input && !p.SignIn:
		return "ok"
	case p.SignIn && strings.HasPrefix(p.URL, "https://gemini.google.com/"):
		return "signedout"
	}
	return ""
}

type cdpCookie struct {
	Name         string  `json:"name"`
	Value        string  `json:"value"`
	Domain       string  `json:"domain"`
	Path         string  `json:"path"`
	Expires      float64 `json:"expires"`
	HTTPOnly     bool    `json:"httpOnly"`
	Secure       bool    `json:"secure"`
	Session      bool    `json:"session"`
	SameSite     string  `json:"sameSite,omitempty"`
	Priority     string  `json:"priority,omitempty"`
	SourceScheme string  `json:"sourceScheme,omitempty"`
	SourcePort   int     `json:"sourcePort,omitempty"`
	PartitionKey any     `json:"partitionKey,omitempty"`
}

func gemGoogleCookie(c cdpCookie) bool {
	d := strings.TrimPrefix(c.Domain, ".")
	return c.PartitionKey == nil && (d == "google.com" || strings.HasSuffix(d, ".google.com"))
}

// cookieParams turns read cookies into what Storage.setCookies takes.
func cookieParams(cs []cdpCookie, keep func(cdpCookie) bool) []map[string]any {
	var out []map[string]any
	for _, c := range cs {
		if !keep(c) {
			continue
		}
		p := map[string]any{"name": c.Name, "value": c.Value, "domain": c.Domain, "path": c.Path,
			"secure": c.Secure, "httpOnly": c.HTTPOnly}
		if !c.Session && c.Expires > 0 {
			p["expires"] = c.Expires
		}
		for k, v := range map[string]string{"sameSite": c.SameSite, "priority": c.Priority, "sourceScheme": c.SourceScheme} {
			if v != "" {
				p[k] = v
			}
		}
		if c.SourcePort > 0 {
			p["sourcePort"] = c.SourcePort
		}
		out = append(out, p)
	}
	return out
}

// gemProbe opens Gemini signed in, through proxy ("socks5://ip:port"; "" = the browser's own
// exit) and returns the verdict and what the page showed.
func gemProbe(ctx context.Context, proxy string) (string, gemPage, error) {
	var page gemPage
	w, err := cdpDial(ctx, gemCDPAddr)
	if err != nil {
		return "", page, fmt.Errorf("Google test browser: %w", err)
	}
	defer w.Close()
	bctx := ""
	if proxy != "" {
		var r struct {
			ID string `json:"browserContextId"`
		}
		if err := w.call(ctx, "", "Target.createBrowserContext", map[string]any{"proxyServer": proxy, "disposeOnDetach": true}, &r); err != nil {
			return "", page, err
		}
		bctx = r.ID
		defer func() {
			// Google rotates the session cookies now and then: the new ones go back to the main
			// profile, or it would carry outdated ones (and be signed out).
			c2, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var got struct {
				Cookies []cdpCookie `json:"cookies"`
			}
			if w.call(c2, "", "Storage.getCookies", map[string]any{"browserContextId": bctx}, &got) == nil {
				if ps := cookieParams(got.Cookies, func(c cdpCookie) bool {
					return gemGoogleCookie(c) && (strings.Contains(c.Name, "PSIDTS") || strings.Contains(c.Name, "SIDCC"))
				}); len(ps) > 0 {
					_ = w.call(c2, "", "Storage.setCookies", map[string]any{"cookies": ps}, nil)
				}
			}
			_ = w.call(c2, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bctx}, nil)
		}()
		var main struct {
			Cookies []cdpCookie `json:"cookies"`
		}
		if err := w.call(ctx, "", "Storage.getCookies", nil, &main); err != nil {
			return "", page, err
		}
		ps := cookieParams(main.Cookies, gemGoogleCookie)
		if len(ps) == 0 {
			return "signedout", page, nil
		}
		if err := w.call(ctx, "", "Storage.setCookies", map[string]any{"cookies": ps, "browserContextId": bctx}, nil); err != nil {
			return "", page, err
		}
	}
	tp := map[string]any{"url": "about:blank", "background": true}
	if bctx != "" {
		tp["browserContextId"] = bctx
	}
	var t struct {
		ID string `json:"targetId"`
	}
	if err := w.call(ctx, "", "Target.createTarget", tp, &t); err != nil {
		return "", page, err
	}
	defer func() {
		c2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.call(c2, "", "Target.closeTarget", map[string]any{"targetId": t.ID}, nil)
	}()
	var at struct {
		Session string `json:"sessionId"`
	}
	if err := w.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": t.ID, "flatten": true}, &at); err != nil {
		return "", page, err
	}
	var nav struct {
		Err string `json:"errorText"`
	}
	if err := w.call(ctx, at.Session, "Page.navigate", map[string]any{"url": gemURL}, &nav); err != nil {
		return "", page, err
	}
	if nav.Err != "" {
		return "noanswer", page, fmt.Errorf("the page did not open: %s", nav.Err)
	}
	// the app draws itself for a few seconds; a refusal can show after the input box
	var ok time.Time
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return "", page, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		var ev struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		if err := w.call(ctx, at.Session, "Runtime.evaluate", map[string]any{"expression": gemPageJS, "returnByValue": true}, &ev); err != nil {
			continue
		}
		if json.Unmarshal([]byte(ev.Result.Value), &page) != nil {
			continue
		}
		switch v := gemVerdict(page); v {
		case "ok":
			if ok.IsZero() {
				ok = time.Now()
			} else if time.Since(ok) >= 6*time.Second {
				return v, page, nil
			}
		case "":
		default:
			return v, page, nil
		}
	}
	if !ok.IsZero() {
		return "ok", page, nil
	}
	return "noanswer", page, nil
}

// gemini-check [socks5://ip:port]: one probe from the command line (prints what the page showed).
func gemCheckCmd(args []string) {
	proxy := ""
	if len(args) > 0 {
		proxy = args[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	v, p, err := gemProbe(ctx, proxy)
	b, _ := json.MarshalIndent(p, "", " ")
	fmt.Printf("verdict=%s err=%v\n%s\n", v, err, b)
	if v != "ok" {
		os.Exit(1)
	}
}

// gemWhy is the short reason a page gives: the error line, or where Google places the exit.
func gemWhy(p gemPage) string {
	ls := strings.Split(p.Text, "\n")
	for i, l := range ls {
		if strings.Contains(l, "From your IP address") && i > 0 {
			return strings.TrimSpace(ls[i-1])
		}
	}
	low := strings.ToLower(p.Text)
	for _, r := range gemRefusals {
		if strings.Contains(low, r) {
			return r
		}
	}
	for _, l := range ls {
		if l = strings.TrimSpace(l); l != "" {
			return clipTo(l, 80)
		}
	}
	return ""
}

// ---- the loop: one server per round, each about every gemServerEvery; Google sees one
// signed-in page now and then, the way a person opens it (no prompts, never a captcha solved:
// a captcha only makes that exit wait longer).

const (
	gemTick        = 20 * time.Minute
	gemServerEvery = 6 * time.Hour
	gemRecheck     = 10 * time.Minute // a refusal is looked at once more before it counts
)

type gemSrvState struct {
	last    time.Time
	next    time.Time
	verdict string // the last counted one
	pending bool   // refused once, a second look is due
	why     string
	moved   time.Time // the last time its Google was moved (at most once per gemServerEvery)
}

func (a *App) gemLoop() {
	st := map[string]*gemSrvState{}
	var signedOutSent time.Time
	time.Sleep(3 * time.Minute)
	relays := map[string]string{} // server id -> the allow-list it last took
	for ; ; time.Sleep(gemTick) {
		var list []*Server
		a.store.View(func(s *State) {
			for _, x := range s.Servers {
				if x.Igproxy && x.IPv4 != "" {
					list = append(list, x)
				}
			}
		})
		a.gemRelaySync(list, relays)
		// the one most overdue: a pending second look first, then the longest unchecked
		now := time.Now()
		var pick *Server
		for _, s := range list {
			g := st[s.ID]
			if g == nil {
				g = &gemSrvState{}
				st[s.ID] = g
			}
			if now.Before(g.next) {
				continue
			}
			if pick == nil || g.pending && !st[pick.ID].pending || g.pending == st[pick.ID].pending && g.last.Before(st[pick.ID].last) {
				pick = s
			}
		}
		if pick == nil {
			continue
		}
		g := st[pick.ID]
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		v, page, err := gemProbe(ctx, fmt.Sprintf("socks5://%s:%d", pick.IPv4, gemRelayPort))
		if v == "signedout" { // the account itself, or only this exit? the browser's own exit tells
			if ov, _, oerr := gemProbe(ctx, ""); oerr == nil && ov == "signedout" {
				cancel()
				if time.Since(signedOutSent) > 24*time.Hour {
					signedOutSent = time.Now()
					a.push("🔑 Gemini test account (Google test browser) is signed out — log in again: IG Routing → 🔑 Google test browser. The signed-in Gemini checks wait until then.")
				}
				continue
			}
		}
		cancel()
		g.last = time.Now()
		g.next = g.last.Add(gemServerEvery)
		if err != nil && v == "" {
			log.Printf("gemini check %s: %v", pick.Name, err)
			continue // the browser or the tunnel to it; not this server's fault
		}
		why := gemWhy(page)
		switch v {
		case "ok":
			g.pending = false
			if g.verdict != "" && g.verdict != "ok" && g.verdict != "noanswer" {
				a.push(fmt.Sprintf("✅ Gemini (signed in) works again on %s (%s)", igLabel(pick), why))
			}
			g.verdict, g.why = v, why
			// one Google country for every server: users move between servers, and an account that
			// hops countries looks suspicious to Google
			inf := a.igInfo(context.Background(), pick)
			if d := inf["gdom"]; pick.Owner == "" && d != "" && d != "-" && d != gemWantDom && time.Since(g.moved) > gemServerEvery {
				g.moved = time.Now()
				a.push(fmt.Sprintf("🌍 Google places the users of %s in .%s (not .%s)\n→ %s", igLabel(pick), d, gemWantDom, a.gemFix(pick, inf)))
			}
		case "refused", "signedout":
			if !g.pending && g.verdict != v {
				g.pending, g.next = true, g.last.Add(gemRecheck)
				continue
			}
			g.pending = false
			if g.verdict != v {
				inf := a.igInfo(context.Background(), pick)
				msg := fmt.Sprintf("🔴 Gemini (signed in) refused on %s: %s\nGoogle route there: %s", igLabel(pick), why, igProxyName(inf, inf["google"], a.igServerByIP))
				if pick.Owner == "" {
					g.moved = time.Now()
					msg += "\n→ " + a.gemFix(pick, inf)
				}
				a.push(msg)
			}
			g.verdict, g.why = v, why
		case "captcha":
			g.next = g.last.Add(3 * gemServerEvery)
			if g.verdict != v {
				a.push(fmt.Sprintf("🟠 Google shows a captcha to the Gemini test account on %s — that exit is checked less often now", igLabel(pick)))
			}
			g.verdict = v
		default: // noanswer: the relay is not there (older agent) or the page hung; checked again next time
			log.Printf("gemini check %s: no answer (%v) %s", pick.Name, err, clipTo(page.Text, 100))
		}
	}
}

