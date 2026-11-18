package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIgExVerdict(t *testing.T) {
	cases := []struct {
		svc, code, dom, flag, want string
	}{
		{"GOOGLE", "200", "ru", "", "bad"},    // the outbound server's WARP IPv6, 2026-11-14
		{"GOOGLE", "200", "com", "", "ok"},    // its own IPv4 (Google: US)
		{"GOOGLE", "200", "com.tr", "", "ok"}, // Turkey
		{"GOOGLE", "200", "de", "", "ok"},
		{"GOOGLE", "403", "", "", "bad"}, // usa-kharej's own IP
		{"GOOGLE", "000", "", "", "bad"},
		{"GOOGLE", "200", "", "", ""}, // no country: no verdict
		{"GOOGLE", "502", "", "", ""},
		{"GOOGLE", "200", "de", "region", "bad"},
		{"YTM", "200", "DE", "", "ok"},
		{"YTM", "200", "IR", "region", "bad"},
		{"YTM", "503", "", "", ""},
	}
	for _, c := range cases {
		v, why := igExVerdict(c.svc, &igExRead{Code: c.code, Dom: c.dom, Flag: c.flag})
		if v != c.want {
			t.Errorf("%s %s %q %s: %q (%s), want %q", c.svc, c.code, c.dom, c.flag, v, why, c.want)
		}
		if v == "bad" && why == "" {
			t.Errorf("%s %s %q: bad without a reason", c.svc, c.code, c.dom)
		}
	}
	if _, why := igExVerdict("GOOGLE", &igExRead{Code: "200", Dom: "ru"}); why != "Gemini not offered in RU" {
		t.Errorf("why = %q", why)
	}
	if v, _ := igExVerdict("GOOGLE", nil); v != "" {
		t.Errorf("nil reading: %q", v)
	}
}

func TestIgExDomCC(t *testing.T) {
	for d, want := range map[string]string{"ru": "RU", "com.tr": "TR", "co.uk": "GB", "com": "", "": "", "de": "DE", "co.jp": "JP"} {
		if got := igExDomCC(d); got != want {
			t.Errorf("igExDomCC(%q) = %q, want %q", d, got, want)
		}
	}
}

func TestIgExParse(t *testing.T) {
	m, ok := igExParse([]string{"X GOOGLE 200 ru -", "X YTM 200 DE -", "junk", "X GOOGLE2 1"})
	if !ok || m["GOOGLE"].Dom != "ru" || m["YTM"].Dom != "DE" || m["GOOGLE"].Flag != "" {
		t.Fatalf("parse: %+v %v", m, ok)
	}
	m, _ = igExParse([]string{"X GOOGLE 403 - -", "X YTM 200 - region"})
	if m["GOOGLE"].Dom != "" || m["YTM"].Flag != "region" {
		t.Fatalf("parse 2: %+v", m)
	}
	if _, ok := igExParse([]string{"NORELAY"}); ok {
		t.Fatal("NORELAY must say no relay")
	}
}

func TestIgExLadder(t *testing.T) {
	srv := &Server{IPv4: "51.195.47.137", IPv6: "2001:db8::1"}
	inf := map[string]string{"warps": "6", "proxies": "2", "prelay": ""}
	got := strings.Join(igExLadder("GOOGLE", srv, inf, "warp6"), " ")
	if got != "direct ipv6 warp warp6+ proxy1 proxy2 relay" {
		t.Errorf("GOOGLE on warp6: %s", got)
	}
	got = strings.Join(igExLadder("YTM", srv, inf, "ipv6"), " ")
	if got != "direct warp warp6 proxy1 proxy2 relay" {
		t.Errorf("YTM on ipv6: %s", got)
	}
	// no WARP, no IPv6, a proxy that is a relay through the panel host
	srv2 := &Server{IPv4: "1.2.3.4"}
	inf2 := map[string]string{"warps": "0", "proxies": "2", "prelay": "2:" + gemHomeHost() + ":12371"}
	got = strings.Join(igExLadder("GOOGLE", srv2, inf2, "direct"), " ")
	if got != "proxy1 relay" {
		t.Errorf("no WARP: %s", got)
	}
	// the panel host: never its own IP
	home := &Server{IPv4: gemHomeHost(), IPv6: "2001:db8::2"}
	for _, v := range igExLadder("GOOGLE", home, inf, "ipv6") {
		if v == "direct" {
			t.Fatal("the panel host's own IP offered for Google")
		}
	}
	for _, v := range igExLadder("YTM", home, inf, "ipv6") {
		if v == "direct" {
			t.Fatal("the panel host's own IP offered for YouTube Music")
		}
	}
}

func TestIgExBackAfter(t *testing.T) {
	if igExBackAfter(0) != 30*time.Minute || igExBackAfter(1) != time.Hour || igExBackAfter(3) != 4*time.Hour || igExBackAfter(4) != 6*time.Hour || igExBackAfter(50) != 6*time.Hour {
		t.Error("back-off is 30 min doubling to 6 h")
	}
}

func TestIgExIsAuto(t *testing.T) {
	if !igExIsAuto(nil) || !igExIsAuto(&IgAutoSvc{Want: "warp6"}) || igExIsAuto(&IgAutoSvc{Pin: "warp"}) || igExIsAuto(&IgAutoSvc{Off: true}) {
		t.Error("a pin or off is never moved; everything else is Auto")
	}
}

func TestIgExScript(t *testing.T) {
	s := igExScript([]string{"GOOGLE", "YTM"}, 12370)
	for _, w := range []string{"socks5h://127.0.0.1:12370", "':12370 '", "\ng\n", "\ny\n", "__RC=0", "%{http_code}"} {
		if !strings.Contains(s, w) {
			t.Errorf("script lacks %q", w)
		}
	}
	if strings.Contains(s, "%!") {
		t.Error("format error in the script")
	}
	// the users' route asks IPv6 through the WARPs; the own-IP read (12371) does not
	if !strings.Contains(s, "v6(){\n  [ \"$(awk") ||!strings.Contains(s, "2606:4700:4700::1111") || !strings.Contains(s, "$(v6 GOOGLE)") {
		t.Error("users' route: no IPv6 check")
	}
	if o := igExScript([]string{"GOOGLE"}, 12371); strings.Contains(o, "2606:4700") || !strings.Contains(o, "v6(){ echo -; }") {
		t.Error("own IP: the IPv6 check is for the users' route only")
	}
	// v6 is defined before g / y run
	if strings.Index(s, "v6(){") > strings.LastIndex(s, "\ng\n") {
		t.Error("v6 defined after it is used")
	}
}

// Ger-hertzener, 2026-11-14: Google on warp6, the WARP's IPv6 dead (IPv6-only hosts: no answer),
// so Gemini left through Cloudflare's shared IPv4: page 200, google.com - "ok" on the keyless read,
// refused to the signed-in users. Now bad, and the ladder moves on.
// Google on a WARP that it places in no country (google.com) fails outside the US: that is
// Cloudflare's shared exit, where signed-in users get no Gemini (Ger-hertzener 2026-11-15).
func TestIgExVerdictWarpNoCountry(t *testing.T) {
	for _, c := range []struct {
		route, home, dom, want string
	}{
		{"warp", "DE", "com", "bad"},
		{"warp6", "TR", "com", "bad"},
		{"warp", "US", "com", "ok"},    // a US server: google.com is its own country
		{"warp", "DE", "de", "ok"},     // placed in Germany
		{"direct", "DE", "com", "ok"},  // not a WARP: unchanged
		{"warp", "", "com", "ok"},      // no country known for the server
		{"warp6", "GB", "co.uk", "ok"}, // co.uk is a country
	} {
		v, why := igExVerdict("GOOGLE", &igExRead{Code: "200", Dom: c.dom, Route: c.route, Home: c.home})
		if v != c.want {
			t.Errorf("%+v: %s %q", c, v, why)
		}
		if v == "bad" && !strings.Contains(why, "not "+c.home) {
			t.Errorf("%+v: why %q", c, why)
		}
	}
	m, _ := igExParse([]string{"X GOOGLE 200 com - - warp", "X YTM 200 DE - - -", "X GOOGLE2 200 com - ok"})
	if m["GOOGLE"].Route != "warp" || m["YTM"].Route != "" {
		t.Fatalf("route %q %q", m["GOOGLE"].Route, m["YTM"].Route)
	}
}

// An undecided reading is kept as such; the third in a row is a fail. "none" (no reading)
// touches neither count.
func TestIgExMarkUndecided(t *testing.T) {
	id := "test-undecided"
	defer func() { igExMem.Lock(); delete(igExMem.live, id); igExMem.Unlock() }()
	if n, v, _ := igExMarkV(id, "GOOGLE", nil, "", ""); n != 0 || v != "" {
		t.Fatalf("1st: %d %q", n, v)
	}
	igExMarkV(id, "GOOGLE", nil, "none", "x")
	igExMarkV(id, "GOOGLE", nil, "", "")
	n, v, why := igExMarkV(id, "GOOGLE", nil, "", "")
	if v != "bad" || n != 1 || why == "" {
		t.Fatalf("3rd: %d %q %q", n, v, why)
	}
	if _, v, _ := igExMarkV(id, "GOOGLE", nil, "ok", ""); v != "ok" {
		t.Fatal("ok")
	}
	if _, v, _ := igExMarkV(id, "GOOGLE", nil, "", ""); v != "" {
		t.Fatal("count not reset by ok")
	}
}

// The card's view: a reading that never came is "none" once the panel has run long enough.
func TestIgExViewNoRead(t *testing.T) {
	a := &App{}
	old := igExStarted
	defer func() { igExStarted = old }()
	igExStarted = time.Now()
	if v := a.igExViewOf("test-noread", nil)["GOOGLE"]; v.OK != "" {
		t.Fatalf("just started: %+v", v)
	}
	igExStarted = time.Now().Add(-igExNoRead)
	v := a.igExViewOf("test-noread", nil)["GOOGLE"]
	if v.OK != "none" || v.Bad == "" {
		t.Fatalf("after the deadline: %+v", v)
	}
	if v := a.igExViewOf("test-noread", map[string]*IgAutoSvc{"GOOGLE": {Off: true}})["GOOGLE"]; v.OK != "" {
		t.Fatalf("off: %+v", v)
	}
}

// Colab refused on Google's exit fails the exit; not read ("-", an old agent) or no
// answer ("000") says nothing.
func TestIgExVerdictColab(t *testing.T) {
	m, _ := igExParse([]string{"X GOOGLE 200 de - - proxy2 404", "X YTM 200 DE - - - -"})
	if m["GOOGLE"].Colab != "404" {
		t.Fatalf("colab %q", m["GOOGLE"].Colab)
	}
	if v, why := igExVerdict("GOOGLE", m["GOOGLE"]); v != "bad" || why != "Google Colab refuses the IP (404)" {
		t.Fatalf("404: %s %q", v, why)
	}
	for _, l := range []string{"X GOOGLE 200 de - - direct 200", "X GOOGLE 200 de - - direct -", "X GOOGLE 200 de - - direct 000", "X GOOGLE 200 de - - direct"} {
		m, _ := igExParse([]string{l})
		if v, why := igExVerdict("GOOGLE", m["GOOGLE"]); v != "ok" {
			t.Errorf("%q: %s %q", l, v, why)
		}
	}
	if v, _ := igExVerdict("GOOGLE", &igExRead{Code: "200", Dom: "de", Colab: "403"}); v != "bad" {
		t.Fatal("403 passed")
	}
	if !strings.Contains(igExScript([]string{"GOOGLE"}, gemRelayPort), "colab.research.google.com") {
		t.Fatal("script reads no Colab")
	}
}

func TestIgExVerdictV6(t *testing.T) {
	m, ok := igExParse([]string{"X GOOGLE 200 com - no", "X YTM 200 DE - ok", "X GOOGLE2 200 de -"})
	if !ok || m["GOOGLE"].V6 != "no" || m["YTM"].V6 != "ok" || m["GOOGLE2"].V6 != "" {
		t.Fatalf("parse: %+v %+v %+v", m["GOOGLE"], m["YTM"], m["GOOGLE2"])
	}
	if v, why := igExVerdict("GOOGLE", m["GOOGLE"]); v != "bad" || why != "WARP IPv6 passes no IPv6" {
		t.Errorf("dead WARP IPv6: %q %q", v, why)
	}
	if v, _ := igExVerdict("YTM", m["YTM"]); v != "ok" {
		t.Errorf("YTM with IPv6: %q", v)
	}
	if v, _ := igExVerdict("YTM", &igExRead{Code: "200", Dom: "DE", V6: "no"}); v != "bad" {
		t.Errorf("YTM on a dead WARP IPv6: %q", v)
	}
	// an older script's line (no v6 field) reads as before
	if m2, _ := igExParse([]string{"X GOOGLE 200 com -"}); m2["GOOGLE"].V6 != "" {
		t.Error("no field = not measured")
	}
	if v, _ := igExVerdict("GOOGLE", &igExRead{Code: "200", Dom: "com"}); v != "ok" {
		t.Error("not on warp6: unchanged")
	}
}

// What the browser is told decides. xe108 2026-11-17: Google on the server's own IPv6 read
// google.com, 200, Colab 200 - "fine" - while the signed-out app said "Tehran Province, Iran" and
// signed-in users had no Gemini. And a place in a served country passes even on a WARP that reads
// google.com.
func TestIgExVerdictPlace(t *testing.T) {
	r := &igExRead{Code: "200", Dom: "com", Route: "ipv6", Home: "DE", Colab: "200"}
	if v, _ := igExVerdict("GOOGLE", r); v != "ok" {
		t.Fatalf("no place known: the keyless reading stands, got %q", v)
	}
	r.Place = "Tehran Province, Iran"
	v, why := igExVerdict("GOOGLE", r)
	if v != "bad" || !strings.Contains(why, "Tehran Province, Iran") {
		t.Fatalf("placed in Iran: %s %q", v, why)
	}
	if w := igExWhere("GOOGLE", r); w != "Tehran Province, Iran" {
		t.Errorf("the card must say the place, got %q", w)
	}
	w := &igExRead{Code: "200", Dom: "com", Route: "warp6", Home: "DE", Place: "Nuremberg, Germany"}
	if v, _ := igExVerdict("GOOGLE", w); v != "ok" {
		t.Errorf("a WARP the browser places in Germany passes, got %q", v)
	}
	w.Place = ""
	if v, _ := igExVerdict("GOOGLE", w); v != "bad" {
		t.Errorf("without a place the no-country rule for WARP stands, got %q", v)
	}
	// Google's own refusals still win over a place
	if v, _ := igExVerdict("GOOGLE", &igExRead{Code: "403", Place: "France"}); v != "bad" {
		t.Error("403 with a place must fail")
	}
	if v, _ := igExVerdict("GOOGLE", &igExRead{Code: "200", Dom: "fr", Colab: "404", Place: "France"}); v != "bad" {
		t.Error("Colab refused with a place must fail")
	}
}

func TestGemPlace(t *testing.T) {
	page := func(place string) gemPage {
		t := "Gemini\nNew chat\nImages\nSign in to save activity\nSettings\n"
		if place != "" {
			t += place + "\nFrom your IP address\n"
		}
		return gemPage{URL: gemURL, Input: true, SignIn: true, Text: t + "Sign in\nGet App\nHi, I'm Gemini."}
	}
	if p := gemPlace(page("Nuremberg, Germany")); p != "Nuremberg, Germany" {
		t.Fatalf("place %q", p)
	}
	if gemPlace(page("")) != "" {
		t.Fatal("no line: no place")
	}
	if v := gemAnonVerdict(page("London, UK")); v != "ok" {
		t.Errorf("London: %q", v)
	}
	if v := gemAnonVerdict(page("Tehran Province, Iran")); v != "refused" {
		t.Errorf("an exit placed in Iran must not pass, got %q", v)
	}
	if v := gemAnonVerdict(page("")); v != "" {
		t.Errorf("no place: undecided, got %q", v)
	}
	if w := gemWhy(page("Tehran Province, Iran")); !strings.Contains(w, "Iran") || !strings.Contains(w, "no Gemini") {
		t.Errorf("why %q", w)
	}
	for _, c := range []string{"Moscow, Russia", "Hong Kong", "Minsk, Belarus"} {
		if !gemPlaceBad(c) {
			t.Errorf("%s offers no Gemini", c)
		}
	}
	for _, c := range []string{"France", "Istanbul, Türkiye", "Helsinki, Finland", ""} {
		if gemPlaceBad(c) {
			t.Errorf("%q is served", c)
		}
	}
}

// The browser is asked once per 30 minutes while the route stays the same, at once after a move,
// and an answer that never comes changes nothing.
func TestIgExPlaceCache(t *testing.T) {
	old := igExPlaceProbe
	defer func() { igExPlaceProbe = old }()
	calls, place, fail := 0, "Tehran Province, Iran", false
	igExPlaceProbe = func(ctx context.Context, proxy string) (string, gemPage, error) {
		calls++
		if fail {
			return "", gemPage{}, errors.New("test browser down")
		}
		if proxy != "socks5://9.9.9.9:12370" {
			t.Errorf("probed %s", proxy)
		}
		return "refused", gemPage{URL: gemURL, Input: true, SignIn: true, Text: "Settings\n" + place + "\nFrom your IP address\nSign in"}, nil
	}
	a := &App{}
	srv := &Server{ID: "place-test", IPv4: "9.9.9.9"}
	r := &igExRead{Code: "200", Dom: "com", Route: "ipv6"}
	a.igExPlace(context.Background(), srv, r, false)
	a.igExPlace(context.Background(), srv, r, false)
	if calls != 1 || r.Place != place {
		t.Fatalf("calls %d place %q", calls, r.Place)
	}
	r2 := &igExRead{Code: "200", Dom: "fr", Route: "proxy1"} // the route changed: asked again
	place = "France"
	a.igExPlace(context.Background(), srv, r2, false)
	if calls != 2 || r2.Place != "France" {
		t.Fatalf("after a route change: calls %d place %q", calls, r2.Place)
	}
	a.igExPlace(context.Background(), srv, r2, true) // right after a move
	if calls != 3 {
		t.Fatalf("fresh: calls %d", calls)
	}
	fail = true
	r3 := &igExRead{Code: "200", Dom: "de", Route: "direct"}
	a.igExPlace(context.Background(), srv, r3, false)
	if r3.Place != "" || r3.Flag != "" {
		t.Fatalf("no answer must change nothing: %+v", r3)
	}
	if v, _ := igExVerdict("GOOGLE", r3); v != "ok" {
		t.Errorf("the keyless reading stands, got %q", v)
	}
	// no reading of the route at all: the browser is not asked
	a.igExPlace(context.Background(), srv, &igExRead{Code: "000"}, true)
	if calls != 4 {
		t.Errorf("asked the browser for a route that gives no answer: calls %d", calls)
	}
}

// A ladder that found nothing is not climbed again every ten minutes: each try moves the route
// through every exit, and most moves restart the server's router.
func TestIgExFixBackoff(t *testing.T) {
	id, now := "fix-backoff", time.Now()
	if ok, _ := igExFixWait(id, "GOOGLE", now); !ok {
		t.Fatal("never tried: may try")
	}
	igExFixDone(id, "GOOGLE", false, now)
	if ok, next := igExFixWait(id, "GOOGLE", now.Add(10*time.Minute)); ok || next.Sub(now) != igExBackMin {
		t.Fatalf("after one failed try: ok %v next in %s", ok, next.Sub(now))
	}
	if ok, _ := igExFixWait(id, "GOOGLE", now.Add(igExBackMin)); !ok {
		t.Fatal("after the pause: may try")
	}
	igExFixDone(id, "GOOGLE", false, now)
	if _, next := igExFixWait(id, "GOOGLE", now); next.Sub(now) != 2*igExBackMin {
		t.Fatalf("second failed try: next in %s", next.Sub(now))
	}
	for i := 0; i < 10; i++ {
		igExFixDone(id, "GOOGLE", false, now)
	}
	if _, next := igExFixWait(id, "GOOGLE", now); next.Sub(now) != igExBackMax {
		t.Fatalf("capped at 6 h, got %s", next.Sub(now))
	}
	if ok, _ := igExFixWait(id, "YTM", now); !ok {
		t.Fatal("another service is not held")
	}
	igExFixDone(id, "GOOGLE", true, now)
	if ok, _ := igExFixWait(id, "GOOGLE", now); !ok {
		t.Fatal("an exit passed: the count starts anew")
	}
}

// "No place" is a verdict while the app is known to print places. xe108 2026-11-18: its own IPv6
// went from "Tehran Province, Iran" to no place at all; the keyless page still read google.com and
// the ladder took Google back to that exit. When no exit anywhere gets a place (the app stopped
// printing it on 2026-11-14), silence says nothing.
func TestIgExNoPlaceIsRefusedWhilePlacesAreSeen(t *testing.T) {
	old := igExPlaceProbe
	defer func() {
		igExPlaceProbe = old
		igExPlaceMem.Lock()
		igExPlaceMem.seen = time.Time{}
		igExPlaceMem.Unlock()
	}()
	app := func(place string) gemPage {
		t := "Gemini\nNew chat\nSettings\n"
		if place != "" {
			t += place + "\nFrom your IP address\n"
		}
		return gemPage{URL: gemURL, Input: true, SignIn: true, Text: t + "Sign in\nGet App"}
	}
	place := ""
	igExPlaceProbe = func(ctx context.Context, proxy string) (string, gemPage, error) {
		if place == "" {
			return "refused", app(""), nil // the probe's own word after its wait
		}
		return "ok", app(place), nil
	}
	a := &App{}
	igExPlaceMem.Lock()
	igExPlaceMem.seen = time.Time{}
	igExPlaceMem.Unlock()
	silent := &Server{ID: "noplace-a", IPv4: "9.9.9.1"}
	r := &igExRead{Code: "200", Dom: "com", Route: "ipv6", Home: "DE", Colab: "200"}
	a.igExPlace(context.Background(), silent, r, true)
	if r.NoPlace {
		t.Fatal("no exit has shown a place yet: silence must say nothing")
	}
	if v, _ := igExVerdict("GOOGLE", r); v != "ok" {
		t.Fatalf("the keyless reading stands, got %q", v)
	}
	// another server's exit gets a place: the app prints places these hours
	place = "Nuremberg, Germany"
	a.igExPlace(context.Background(), &Server{ID: "noplace-b", IPv4: "9.9.9.2"}, &igExRead{Code: "200", Dom: "de", Route: "direct"}, true)
	place = ""
	r = &igExRead{Code: "200", Dom: "com", Route: "ipv6", Home: "DE", Colab: "200"}
	a.igExPlace(context.Background(), silent, r, true)
	if !r.NoPlace {
		t.Fatal("places are seen elsewhere: a silent exit is refused")
	}
	v, why := igExVerdict("GOOGLE", r)
	if v != "bad" || !strings.Contains(why, "nowhere") {
		t.Fatalf("verdict %s %q", v, why)
	}
	// the last place anywhere is too old: silence says nothing again
	igExPlaceMem.Lock()
	igExPlaceMem.seen = time.Now().Add(-igExPlaceTrust - time.Minute)
	igExPlaceMem.Unlock()
	r = &igExRead{Code: "200", Dom: "com", Route: "ipv6", Home: "DE"}
	a.igExPlace(context.Background(), silent, r, false) // from the 30-minute memory
	if r.NoPlace {
		t.Fatal("no place seen for 6 h: silence must say nothing")
	}
	// a page that is not the app (an error page, a redirect) is not "silent"
	igExPlaceProbe = func(ctx context.Context, proxy string) (string, gemPage, error) {
		return "refused", gemPage{URL: "https://accounts.google.com/x", Text: "Sign in"}, nil
	}
	igExPlaceMem.Lock()
	igExPlaceMem.seen = time.Now()
	igExPlaceMem.Unlock()
	r = &igExRead{Code: "200", Dom: "com", Route: "ipv6"}
	a.igExPlace(context.Background(), silent, r, true)
	if r.NoPlace {
		t.Fatal("not the Gemini app: no verdict from it")
	}
}

// A move back needs a country: google.com without a place is not enough.
func TestIgExStrong(t *testing.T) {
	if igExStrong("GOOGLE", &igExRead{Code: "200", Dom: "com"}) {
		t.Fatal("bare google.com is strong")
	}
	if !igExStrong("GOOGLE", &igExRead{Code: "200", Dom: "de"}) || !igExStrong("GOOGLE", &igExRead{Code: "200", Dom: "com", Place: "Helsinki, Finland"}) {
		t.Fatal("country or place not strong")
	}
	if !igExStrong("YTM", &igExRead{Code: "200"}) {
		t.Fatal("YTM")
	}
}

// Want failing within igExHeld of a move back is a flap; later, or while on a fallback, it is not.
func TestIgExFlap(t *testing.T) {
	now := time.Now()
	rec := &IgAutoSvc{Want: "warp6", Back: now.Add(-time.Hour).Unix()}
	if !igExFlap(rec, "warp6", now) {
		t.Fatal("1 h after a back: flap")
	}
	if igExFlap(rec, "warp6", now.Add(igExHeld)) {
		t.Fatal("held 6 h: no flap")
	}
	if igExFlap(&IgAutoSvc{Want: "warp6", Cur: "direct", Back: rec.Back}, "direct", now) {
		t.Fatal("fallback failing: no flap")
	}
	if igExFlap(nil, "warp6", now) || igExFlap(&IgAutoSvc{Want: "warp6"}, "warp6", now) {
		t.Fatal("never went back: no flap")
	}
}
