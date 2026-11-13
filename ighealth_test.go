package main

import (
	"strings"
	"testing"
)

// the Tests tab's traffic filter: the page's own hint is "google, instagram …", which was refused
// as a "bad filter" (one word only); a list now goes to the agent's grep as one alternation
func TestIgTrafficFilterList(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "",
		"google":             "google",
		"google, instagram":  `google\|instagram`,
		" google  instagram": `google\|instagram`,
		"gemini،youtube":     `gemini\|youtube`,
		"cdninstagram.com":   "cdninstagram.com",
	} {
		c, err := igBuild("recent", map[string]any{"word": in})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		got := ""
		if len(c.args) > 1 {
			got = c.args[1]
		}
		if got != want {
			t.Errorf("%q: sent %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"a;b", "$(id)", "x'y", strings.Repeat("a ", 9)} {
		if _, err := igBuild("watch", map[string]any{"word": bad}); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestIgParseHealth(t *testing.T) {
	out := strings.Join([]string{
		"E\tdirect\t200\t164\t1.2.3.4\tDE\t",
		"E\tipv6\tdns\t0\t\t\t",
		"S\tIG\t404\t0.271474\t",
		"S\tGOOGLE\t204\t0.18\t",
		"S\tGEMINI\t302\t0.35\thttps://www.google.com/sorry/index?x",
		"E\twarp2\t000\t0\t\t\tip",
		"E\twarp10\t000\t0\t\t\t",
		"E\twarp1\t200\t184\t104.28.1.1\tNL\t",
		"A\tgem\tFAIL\t75",
		"A\tpanel\tBLOCK|Google -> 'block' [rule 2]",
	}, "\n")
	r := igParseHealth(strings.Split(out, "\n"))
	ks := []string{}
	for _, e := range r.Exits {
		ks = append(ks, e.K)
	}
	if strings.Join(ks, " ") != "direct ipv6 warp1 warp2 warp10" {
		t.Fatalf("order: %v", ks)
	}
	if e := r.Exits[0]; !e.OK || e.MS != 164 || e.Loc != "DE" {
		t.Errorf("direct: %+v", e)
	}
	if !r.Exits[1].OK {
		t.Errorf("ipv6 by DNS should count as working: %+v", r.Exits[1])
	}
	if e := r.Exits[3]; e.OK || !e.Idle || e.Why != "ip" {
		t.Errorf("standby WARP is not a failure: %+v", e)
	}
	if e := r.Exits[4]; e.OK || e.Idle || e.Why != "no answer" {
		t.Errorf("down WARP: %+v", e)
	}
	if s := r.Svcs[0]; s.K != "IG" || !s.OK || s.MS != 271 {
		t.Errorf("IG (any http answer = reachable): %+v", s)
	}
	if s := r.Svcs[2]; s.K != "GEMINI" || s.OK || !strings.Contains(s.Why, "CAPTCHA") {
		t.Errorf("Gemini captcha: %+v", s)
	}
	if r.Gem != "FAIL" || r.GemAge != 75 || r.IgpAge != -1 || r.PanelWhy != "Google -> 'block' [rule 2]" {
		t.Errorf("agent: %+v", r)
	}
	if r.Exits[0].Why != "" || igHProxy(&igProxyRow{N: 2}).Why != "no answer" {
		t.Error("why")
	}
	p := igHProxy(&igProxyRow{N: 3, Bad: true, Test: &igProxyTest{OK: true, MS: 90, Google: true}})
	if !p.OK || !p.Warn || p.K != "proxy3" {
		t.Errorf("bad proxy: %+v", p)
	}
}

// Gemini's line follows the browser check of the users' route, not the plain HTTP answer: on
// 2026-11-13 HTTP said OK on a WARP Google refused to accounts, and CAPTCHA on an IPv6 exit a
// browser opened.
func TestIgHGemini(t *testing.T) {
	mk := func(ok bool, why string) IgHealth {
		return IgHealth{Svcs: []IgHCheck{{K: "IG", OK: true}, {K: "GEMINI", OK: ok, Why: why}}}
	}
	placed := gemPage{Input: true, SignIn: true, Text: "Gemini\nSettings\nGermany\nFrom your IP address\nSign in"}
	r := mk(false, "Google shows its \"unusual traffic\" page (CAPTCHA) for this exit IP")
	igHGemini(&r, "ok", placed)
	if g := r.Svcs[1]; !g.OK || !g.Warn || g.Loc != "Germany" || !strings.Contains(g.Why, "a browser opens it") {
		t.Fatalf("captcha over HTTP, browser ok: %+v", g)
	}
	r = mk(true, "")
	igHGemini(&r, "ok", placed)
	if g := r.Svcs[1]; !g.OK || g.Warn || g.Why != "" || g.Loc != "Germany" {
		t.Fatalf("both ok: %+v", g)
	}
	r = mk(true, "")
	igHGemini(&r, "refused", gemPage{Input: true, SignIn: true, Text: "Gemini\nSign in"})
	if g := r.Svcs[1]; g.OK || !strings.Contains(g.Why, "refuses accounts") {
		t.Fatalf("HTTP 200 on a refused exit: %+v", g)
	}
	r = mk(true, "")
	igHGemini(&r, "noanswer", gemPage{})
	if g := r.Svcs[1]; !g.OK || g.Why != "" {
		t.Fatalf("no browser verdict must keep the HTTP answer: %+v", g)
	}
	if !r.Svcs[0].OK || r.Svcs[0].Why != "" {
		t.Fatalf("other services touched: %+v", r.Svcs[0])
	}
}
