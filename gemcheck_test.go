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

// Without the account: only an exit Google places somewhere is ok; the bare app is undecided
// (gemProbe turns it into refused after gemAnonWait).
func TestGemAnonVerdict(t *testing.T) {
	app := "Gemini\nNew chat\nSign in to save activity\nSettings\n"
	for _, c := range []struct {
		p    gemPage
		want string
	}{
		{gemPage{URL: gemURL, Input: true, SignIn: true, Text: app + "London, UK\nFrom your IP address\nSign in\nHi, I'm Gemini."}, "ok"},
		{gemPage{URL: gemURL, Input: true, SignIn: true, Text: app + "Sign in\nHi, I'm Gemini."}, ""},
		{gemPage{URL: gemURL, SignIn: true, Text: "Gemini isn't currently supported in your country. Stay tuned!"}, "refused"},
		{gemPage{URL: "https://www.google.com/sorry/index?continue=x", Text: "Our systems have detected unusual traffic"}, "captcha"},
		{gemPage{URL: gemURL, Text: "Gemini"}, ""},
	} {
		if v := gemAnonVerdict(c.p); v != c.want {
			t.Errorf("%q: verdict %q, want %q", c.p.Text, v, c.want)
		}
	}
	bare := gemPage{URL: gemURL, Input: true, SignIn: true, Text: app + "Sign in\nHi, I'm Gemini."}
	if w := gemWhy(bare); w != "Google does not place this IP anywhere (it refuses Gemini to accounts there)" {
		t.Errorf("why of the bare app: %q", w)
	}
}

func TestGemWantDom(t *testing.T) {
	for cc, want := range map[string]string{"US": "com", "us": "com", "DE": "de", "GB": "co.uk", "FR": "fr", "": ""} {
		if got := gemWantDom(&Server{Country: cc}); got != want {
			t.Errorf("%q: got %q, want %q", cc, got, want)
		}
	}
}
