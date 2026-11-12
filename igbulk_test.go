package main

import "testing"

func TestIgVerdict(t *testing.T) {
	cases := []struct {
		act, said string
		rc        int
		st, say   string
	}{
		{"status_short", "IG=warp6 GOOGLE=direct YTM=ipv6 | proxy 3/3 OK | WARP 1/7 OK | router active | caught 538", 0, "ok", "proxy 3/3 OK · WARP 1/7 OK · router active · caught 538"},
		{"status_short", "IG=warp6 | proxy 0/3 OK | WARP 1/7 OK | router active | caught 5", 0, "warn", ""},
		{"status_short", "IG=warp6 | proxy 0/0 OK | WARP 0/0 OK | router failed | caught 0", 0, "fail", ""},
		{"google_rotate", "x\n  Google now uses WARP 3 (US)\n", 0, "ok", "Google now uses WARP 3 (US)"},
		{"google_rotate", "  Google is not on WARP here (route: direct)", 0, "skip", "Google is not on WARP here"},
		{"google_rotate", "  no other WARP works + opens Gemini now", 0, "warn", "not moved: no other WARP works + opens Gemini now"},
		{"gemusers", "  Gemini connections from users, last 10 min: direct:1 warp3:4 ", 0, "ok", "direct:1 warp3:4"},
		{"gemusers", "  Gemini connections from users, last 10 min: ", 0, "ok", "none"},
		{"logs", "a\nb\n\nc", 0, "ok", "3 lines"},
		{"panel_fix", "dial tcp: timeout", 255, "fail", "not reached: dial tcp: timeout"},
		{"panel_fix", "a\n!! failed", 1, "fail", "!! failed"},
	}
	for _, c := range cases {
		st, say := igVerdict(c.act, c.rc, c.said)
		if st != c.st || (c.say != "" && say != c.say) {
			t.Errorf("%s %q rc=%d: got %s %q, want %s %q", c.act, c.said, c.rc, st, say, c.st, c.say)
		}
	}
}
