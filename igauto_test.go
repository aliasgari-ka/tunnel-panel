package main

import (
	"reflect"
	"testing"
)

// Ger-hertzener (2026-11-13): IG=warp6, 0 WARPs, 0 proxies, Instagram sees IR — the card said "healthy".
func TestIgStateHonest(t *testing.T) {
	base := "ig=warp6 google=warp6 ytm=ipv6 proxies=0 warps=0 router=active redirect=ON panel=OK gem=OK igp=OK guard=ON paused=NO igcc=IR gdom=de sum=x"
	cases := []struct{ info, want string }{
		{base, "IGIR"},
		{"ig=warp6 google=warp6 ytm=ipv6 proxies=0 warps=0 router=active redirect=ON panel=OK gem=OK igp=OK guard=ON paused=NO igcc=DE sum=x", "NOEXIT"},
		{"ig=warp6 google=warp6 ytm=ipv6 proxies=2 warps=0 router=active redirect=ON panel=OK gem=OK igp=OK guard=ON paused=NO igcc=DE sum=x", "NOWARP"},
		{"ig=proxy2 google=direct ytm=ipv6 proxies=2 warps=0 router=active redirect=ON panel=OK gem=OK igp=OK guard=ON paused=NO igcc=DE sum=x", "OK"},
		{"ig=warp6 google=warp6 ytm=ipv6 proxies=0 warps=5 router=active redirect=ON panel=OK gem=OK igp=OK guard=ON paused=NO igcc=DE sum=x", "OK"},
		{"ig=warp6 google=warp6 ytm=ipv6 proxies=0 warps=5 router=active redirect=ON panel=OK gem=OK igp=OK guard=ON paused=NO igcc=- sum=x", "OK"},
		{"ig=warp6 google=warp6 proxies=0 warps=0 router=stopped redirect=OFF igcc=IR sum=x", "DOWN"},
	}
	for _, c := range cases {
		if got := igParseInfo(0, c.info, "x")["state"]; got != c.want {
			t.Errorf("%s\n  state %s, want %s", c.info, got, c.want)
		}
	}
}

func TestIgParseProbe(t *testing.T) {
	p := igParseProbe([]string{"L IR", "F ", "R warp6", "O IR", "P 1 82.22.105.198 DE ok", "P 2 151.242.109.172 DE", "P 3 1.2.3.4", "W 1 IR", "W 2 "})
	if !p.Relay || p.Live != "IR" || p.Route != "warp6" || p.FB != "" {
		t.Fatalf("head: %+v", p)
	}
	want := []igExitCC{{Route: "direct", CC: "IR"}, {Route: "proxy1", Host: "82.22.105.198", CC: "DE", Music: "ok"},
		{Route: "proxy2", Host: "151.242.109.172", CC: "DE"}, {Route: "proxy3", Host: "1.2.3.4"}, {Route: "warp1", CC: "IR"}}
	if !reflect.DeepEqual(p.Exits, want) {
		t.Fatalf("exits:\n got %+v\nwant %+v", p.Exits, want)
	}
	if q := igParseProbe([]string{"L none"}); q.Relay {
		t.Fatal("no relay must read as no relay")
	}
	if q := igParseProbe([]string{"L -"}); !q.Relay || q.Live != "" {
		t.Fatal("no answer through the relay")
	}
}

func TestIgCandidates(t *testing.T) {
	p := igProbe{Route: "warp6", Exits: []igExitCC{{Route: "direct", CC: "DE"}, {Route: "proxy1", CC: "RU"}, {Route: "proxy2", CC: "US"},
		{Route: "proxy3", CC: "DE"}, {Route: "proxy4", CC: "IR"}, {Route: "proxy5", CC: "NL", Music: "ok"}, {Route: "warp1", CC: "IR"}}}
	// WARP reads IR: not a candidate; DE server: own country first, then Europe (music-tested first), the own IP after the proxies, RU last
	got := igCandidates(p, "warp6", "DE")
	want := []string{"proxy3", "proxy5", "proxy2", "direct", "proxy1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// a WARP in a music country: back to the route it should be on, first
	p.Exits = append(p.Exits, igExitCC{Route: "warp2", CC: "DE"})
	p.Route = "proxy3"
	if got := igCandidates(p, "warp6", "DE"); got[0] != "warp6" || contains(got, "proxy3") {
		t.Fatalf("got %v", got)
	}
}

func TestIgWarpMissing(t *testing.T) {
	if got := igWarpMissing(map[string]string{"ig": "warp6", "google": "warp", "ytm": "ipv6", "warps": "0"}); got != "IG,GOOGLE" {
		t.Fatal(got)
	}
	if igWarpMissing(map[string]string{"ig": "warp6", "warps": "3"}) != "" {
		t.Fatal("has WARPs")
	}
}
