package main

import (
	"testing"
	"time"
)

func TestGemReauthURL(t *testing.T) {
	for u, want := range map[string]bool{
		"https://accounts.google.com/v3/signin/challenge/pwd?TL=x": true,
		"https://accounts.google.com/v3/signin/identifier":         true,
		"https://accounts.google.com/ServiceLogin?continue=x":      true,
		"https://accounts.google.com/signin/v2/challenge/pwd":      true,
		"https://accounts.google.com/RotateCookies":                false,
		"https://myaccount.google.com/":                            false,
		"https://gemini.google.com/app":                            false,
		"about:blank":                                              false,
	} {
		if gemReauthURL(u) != want {
			t.Errorf("%s: %v", u, !want)
		}
	}
}

func TestGemKeepPlan(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	blank := gemPage1{ID: "b", Typ: "page", URL: "about:blank"}
	keep := gemPage1{ID: "k", Typ: "page", URL: "https://myaccount.google.com/?pli=1"}
	pwd := gemPage1{ID: "p", Typ: "page", URL: "https://accounts.google.com/v3/signin/challenge/pwd"}
	// nothing of Google open: open the keep page
	if open, reload, reauth := gemKeepPlan([]gemPage1{blank}, time.Time{}, now); !open || reload != "" || reauth {
		t.Fatalf("blank: %v %q %v", open, reload, reauth)
	}
	// a keep page reloaded an hour ago or more: reload it
	if open, reload, _ := gemKeepPlan([]gemPage1{blank, keep}, now.Add(-gemKeepEvery), now); open || reload != "k" {
		t.Fatalf("due: %v %q", open, reload)
	}
	// reloaded just now: nothing
	if open, reload, _ := gemKeepPlan([]gemPage1{keep}, now.Add(-time.Minute), now); open || reload != "" {
		t.Fatalf("fresh: %v %q", open, reload)
	}
	// Google's password step: told, and no new page over it
	if open, _, reauth := gemKeepPlan([]gemPage1{pwd}, time.Time{}, now); open || !reauth {
		t.Fatalf("pwd: %v %v", open, reauth)
	}
}

// Gemini's refusal with a typographic apostrophe (U+2019) is a refusal.
func TestGemVerdictCurly(t *testing.T) {
	p := gemPage{URL: "https://gemini.google.com/?pli=1", Input: false,
		Text: "Gemini\nChat to start writing\n\nGemini isn’t currently supported in your country. Stay tuned!"}
	if v := gemVerdict(p); v != "refused" {
		t.Fatalf("curly: %q", v)
	}
	if gemWhy(p) == "" {
		t.Fatal("no why")
	}
}
