package main

// The Gemini check in a real browser. Google can refuse Gemini to a signed-in account ("not
// supported in your country") on an exit that every keyless HTTP check passes. The Google test
// browser (gbrowser.go) is used for it; its DevTools port reaches the panel host over the same
// SSH tunnel (gemCDPAddr).
//
// An exit is checked WITHOUT the test account: in a throw-away browser context (no cookies)
// whose proxy is that server's relay. The signed-out Gemini app tells the two apart as well: on
// an exit Google serves it prints where it places the IP ("London, UK / From your IP address"),
// on one it refuses to accounts that line never comes (compared with the signed-in answer on 7
// exits, 2026-11-10: the same every time). The account itself never leaves its home exit
// (gemHome): seen from another IP and country at every check, Google signed it out again and
// again. Only `gemini-check --signed` still takes the account to an exit, for a check by hand.

import (
	"context"
	"encoding/json"
	"fmt"
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

// gemPlaced: the app says where Google places this IP — it serves Gemini there.
const gemPlaced = "From your IP address"

// gemAnonWait: a signed-out app that has not said where it places the IP after this long never
// does (it showed within 14 s on every exit Google serves).
const gemAnonWait = 24 * time.Second

// gemAnonVerdict is gemVerdict for the page without an account: ok only once Google has placed
// the IP; the app without that line stays undecided (gemProbe calls it refused after gemAnonWait).
func gemAnonVerdict(p gemPage) string {
	switch v := gemVerdict(p); v {
	case "refused", "captcha":
		return v
	}
	if p.Input && strings.Contains(p.Text, gemPlaced) {
		return "ok"
	}
	return ""
}

// gemProbe opens Gemini through proxy ("socks5://ip:port") without the test account, in a
// browser context of its own, and returns the verdict and what the page showed. proxy "" is the
// test account itself on its home exit.
func gemProbe(ctx context.Context, proxy string) (string, gemPage, error) {
	return gemProbeAs(ctx, proxy, proxy == "")
}

// gemProbeAs: signed = with the test account (its one cookie jar; the browser's own proxy is
// switched to the exit for the visit, see gemjar.go).
func gemProbeAs(ctx context.Context, proxy string, signed bool) (string, gemPage, error) {
	var page gemPage
	w, err := cdpDial(ctx, gemCDPAddr)
	if err != nil {
		return "", page, fmt.Errorf("Google test browser: %w", err)
	}
	defer w.Close()
	tp := map[string]any{"url": "about:blank", "background": true}
	verdict := gemVerdict
	if signed && proxy != "" {
		release, err := gemHold(ctx, strings.TrimPrefix(proxy, "socks5://"))
		if err != nil {
			return "", page, err
		}
		defer release()
	} else if !signed {
		var bc struct {
			ID string `json:"browserContextId"`
		}
		if err := w.call(ctx, "", "Target.createBrowserContext", map[string]any{"proxyServer": proxy, "disposeOnDetach": true}, &bc); err != nil {
			return "", page, err
		}
		defer func() {
			c2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = w.call(c2, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": bc.ID}, nil)
		}()
		tp["browserContextId"] = bc.ID
		verdict = gemAnonVerdict
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
	start := time.Now()
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
		switch v := verdict(page); v {
		case "ok":
			if ok.IsZero() {
				ok = time.Now()
			} else if time.Since(ok) >= 6*time.Second {
				return v, page, nil
			}
		case "":
			// the app is up without an account, and Google never said where it places the IP
			if !signed && page.Input && time.Since(start) >= gemAnonWait {
				return "refused", page, nil
			}
		default:
			return v, page, nil
		}
	}
	if !ok.IsZero() {
		return "ok", page, nil
	}
	return "noanswer", page, nil
}

// gemini-check [--signed] [socks5://ip:port]: one probe from the command line (prints what the
// page showed). Without an exit it is the test account on its home exit; --signed takes the
// account to the exit (by hand only: Google signs out an account it sees on many IPs).
func gemCheckCmd(args []string) {
	proxy, signed := "", false
	for _, a := range args {
		if a == "--signed" {
			signed = true
		} else {
			proxy = a
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	v, p, err := gemProbeAs(ctx, proxy, signed || proxy == "")
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
	if p.Input && p.SignIn {
		return "Google does not place this IP anywhere (it refuses Gemini to accounts there)"
	}
	for _, l := range ls {
		if l = strings.TrimSpace(l); l != "" {
			return clipTo(l, 80)
		}
	}
	return ""
}

// ---- the loop. The agent measures the Google country of the users' route (gdom) every 10
// minutes; when Google is about to be moved, gemFix checks each candidate in the test browser,
// without the account (see the top of this file).

const (
	gemTick        = 20 * time.Minute
	gemServerEvery = 6 * time.Hour // a server's Google is moved at most this often
)

func (a *App) gemLoop() {
	moved := map[string]time.Time{}
	var signedOutSent time.Time
	time.Sleep(3 * time.Minute)
	relays := newRelayState()
	for ; ; time.Sleep(gemTick) {
		var list []*Server
		a.store.View(func(s *State) {
			for _, x := range s.Servers {
				if x.Igproxy && x.IPv4 != "" {
					list = append(list, x)
				}
			}
		})
		a.relaySync(list, relays)
		// one move per round at most: few signed-in visits
		for _, s := range list {
			want := gemWantDom(s)
			if s.Owner != "" || want == "" || time.Since(moved[s.ID]) < gemServerEvery {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			inf := a.igInfo(ctx, s)
			cancel()
			if d := inf["gdom"]; d == "" || d == "-" || d == want {
				continue
			}
			moved[s.ID] = time.Now()
			res := a.gemFix(s, inf)
			if strings.Contains(res, "signed out") { // tried again next round; told once a day
				delete(moved, s.ID)
				if time.Since(signedOutSent) < 24*time.Hour {
					break
				}
				signedOutSent = time.Now()
			}
			a.push(fmt.Sprintf("🌍 Google places the users of %s in .%s (not .%s)\n→ %s", igLabel(s), inf["gdom"], want, res))
			break
		}
	}
}
