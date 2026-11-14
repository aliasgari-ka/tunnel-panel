package main

import (
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
