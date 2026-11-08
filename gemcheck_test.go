package main

import "testing"

func TestGemVerdict(t *testing.T) {
	for _, c := range []struct {
		p    gemPage
		want string
		why  string
	}{
		{gemPage{URL: gemURL, Input: true, Text: "Gemini\nActivity\nNuremberg, Germany\nFrom your IP address\nWhere should we start?"}, "ok", "Nuremberg, Germany"},
		{gemPage{URL: gemURL, Text: "403. That’s an error.\n\nYour client does not have permission to get URL /app from this server."}, "refused", "403. That’s an error."},
		{gemPage{URL: gemURL, Input: true, Text: "Gemini isn't currently supported in your country. Stay tuned!"}, "refused", "isn't currently supported"},
		{gemPage{URL: "https://accounts.google.com/v3/signin/identifier?continue=x"}, "signedout", ""},
		{gemPage{URL: gemURL, SignIn: true, Text: "Meet Gemini\nSign in"}, "signedout", "Meet Gemini"},
		{gemPage{URL: "https://www.google.com/sorry/index?continue=x", Text: "Our systems have detected unusual traffic"}, "captcha", ""},
		{gemPage{URL: gemURL, Text: "Gemini"}, "", "Gemini"},
	} {
		if v := gemVerdict(c.p); v != c.want {
			t.Errorf("%q: verdict %q, want %q", c.p.Text, v, c.want)
		}
		if c.why != "" && gemWhy(c.p) != c.why {
			t.Errorf("%q: why %q, want %q", c.p.Text, gemWhy(c.p), c.why)
		}
	}
}

func TestGemWantDom(t *testing.T) {
	for cc, want := range map[string]string{"US": "com", "us": "com", "DE": "de", "GB": "co.uk", "FR": "fr", "": ""} {
		if got := gemWantDom(&Server{Country: cc}); got != want {
			t.Errorf("%q: got %q, want %q", cc, got, want)
		}
	}
}

func TestRelayAllowLists(t *testing.T) {
	list := []*Server{
		{ID: "a1", IPv4: "198.51.100.1"},
		{ID: "a2", IPv4: "198.51.100.2"},
		{ID: "r1", IPv4: "198.51.100.2", Owner: "arshad"}, // the admin's machine, added by arshad too
		{ID: "r2", IPv4: "203.0.113.5", Owner: "arshad"},
		{ID: "r3", IPv4: "203.0.113.6", Owner: "arshad"},
	}
	got := relayAllowLists(list)
	want := map[string]string{
		"a1": "198.51.100.1\n198.51.100.2",
		"a2": "198.51.100.1\n198.51.100.2",
		"r2": "203.0.113.5\n203.0.113.6",
		"r3": "203.0.113.5\n203.0.113.6",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lists %v, want %d", len(got), got, len(want))
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: got %q, want %q", id, got[id], w)
		}
	}
}
