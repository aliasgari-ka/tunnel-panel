package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIgSiteNorm(t *testing.T) {
	ok := map[string]string{
		"https://www.sub.example.co.uk/x":   "example.co.uk",
		"WWW.Example.COM":                   "example.com",
		"example.com:8443/path?q=1":         "example.com",
		"http://user@shop.example.com.au/a": "example.com.au",
		"*.example.org":                     "example.org",
		"domain:cdn.example.net":            "example.net",
		"https://bücher.de/":                "xn--bcher-kva.de",
		"xn--bcher-kva.de":                  "xn--bcher-kva.de",
		"d123abc.cloudfront.net":            "d123abc.cloudfront.net",
		"a.b.d123abc.cloudfront.net/x.js":   "d123abc.cloudfront.net",
		"myapp.github.io":                   "myapp.github.io",
		"instagram.com":                     "instagram.com",
	}
	for in, want := range ok {
		if got, err := igSiteNorm(in); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "co.uk", "1.2.3.4", "cloudfront.net", "bad_name.com", "http://", "com"} {
		if got, err := igSiteNorm(in); err == nil {
			t.Errorf("%q: want an error, got %q", in, got)
		}
	}
}

func TestIgIsGoogle(t *testing.T) {
	for _, d := range []string{"google.com", "google.de", "google.co.uk", "fonts.googleapis.com", "gstatic.com", "youtube.com", "domain:googleusercontent.com"} {
		if !igIsGoogle(d) {
			t.Errorf("%s should be Google", d)
		}
	}
	for _, d := range []string{"example.com", "googlefan.net", "notgoogle.com", "cdninstagram.com"} {
		if igIsGoogle(d) {
			t.Errorf("%s is not Google", d)
		}
	}
}

func TestIgSiteCards(t *testing.T) {
	raw := "domain:win90.win warp\ndomain:bluestacks.com\ndomain:cdninstagram.com direct\ndomain:fbcdn.net direct\ndomain:example.com proxy\ndomain:excdn.net proxy\ndomain:img.example.com proxy\nregexp:^x[0-9]+\\.foo\\.com$ warp\n"
	rel := map[string]string{"excdn.net": "example.com"}
	lists := map[string][]string{"IG": {"domain:instagram.com", "domain:cdninstagram.com", "domain:fbcdn.net"}}
	cards := igSiteCards(raw, rel, lists)
	by := map[string]igSiteCard{}
	for _, c := range cards {
		by[c.Site] = c
	}
	if len(cards) != 6 {
		t.Fatalf("cards: %+v", cards)
	}
	ex := by["example.com"]
	if len(ex.Doms) != 3 || ex.Route != "proxy" {
		t.Errorf("example.com: %+v", ex)
	}
	for _, d := range ex.Doms {
		if d.D == "img.example.com" && d.Covered != "example.com" {
			t.Errorf("img not covered: %+v", d)
		}
	}
	if c := by["cdninstagram.com"]; len(c.Doms) != 1 || strings.Join(c.Doms[0].Also, ",") != "IG" {
		t.Errorf("overlap: %+v", c)
	}
	if c := by["bluestacks.com"]; c.Route != "" {
		t.Errorf("default route: %+v", c)
	}
}

// a real fetch (only with TP_NET=1): the related domains of a few sites
func TestIgSiteFindLive(t *testing.T) {
	if os.Getenv("TP_NET") == "" {
		t.Skip("set TP_NET=1")
	}
	for _, s := range strings.Split(os.Getenv("TP_SITES"), ",") {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		rel, left, err := igSiteFind(ctx, s)
		cancel()
		var ds []string
		for _, r := range rel {
			ds = append(ds, r.D)
		}
		t.Logf("%s: %v (left out %d) %v", s, ds, left, err)
	}
}
