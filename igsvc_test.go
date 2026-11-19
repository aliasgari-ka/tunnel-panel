package main

import (
	"strings"
	"testing"
)

func TestIgSvcParse(t *testing.T) {
	live, relay := igSvcParse([]string{
		"S OPENAI 401 DE -", "S CLAUDE 403 DE -", "S X 000 - -", "S NETFLIX 302 DE -",
		"S PERPLEX 200 XX -", "S GROK 503 - -", "S COPILOT 200 - region", "junk", "S NOPE 200 - -",
	})
	if !relay {
		t.Fatal("relay")
	}
	want := map[string]bool{"OPENAI": true, "CLAUDE": false, "X": false, "NETFLIX": true, "PERPLEX": true, "GROK": false, "COPILOT": false}
	for k, ok := range want {
		if live[k] == nil || live[k].OK != ok {
			t.Errorf("%s: got %+v want ok=%v", k, live[k], ok)
		}
	}
	if live["OPENAI"].CC != "DE" || live["PERPLEX"].CC != "" || live["NOPE"] != nil {
		t.Errorf("cc/unknown: %+v %+v", live["OPENAI"], live["PERPLEX"])
	}
	if _, relay := igSvcParse([]string{"NORELAY"}); relay {
		t.Error("NORELAY")
	}
}

func TestIgSvcCandsNext(t *testing.T) {
	c := igSvcCands(igAutoAI, map[string]string{"warps": "3", "proxies": "0"})
	if strings.Join(c, ",") != "warp,direct" {
		t.Fatal(c)
	}
	if igSvcNext(c, "warp") != "direct" || igSvcNext(c, "direct") != "" || igSvcNext(c, "proxy") != "direct" {
		t.Error("next")
	}
	if c := igSvcCands(igAutoAI, map[string]string{"warps": "0", "proxies": "0"}); strings.Join(c, ",") != "direct" {
		t.Error(c)
	}
	if igSvcKind("warp6") != "warp" || igSvcKind("proxy2") != "proxy" || igSvcKind("direct") != "direct" {
		t.Error("kind")
	}
}

func TestIgSvcIsAuto(t *testing.T) {
	cases := []struct {
		rec  *IgAutoSvc
		svc  string
		want bool
	}{
		{nil, "OPENAI", true}, {nil, "SPOTIFY", false}, {nil, "YTM", false}, {nil, "CUSTOM", false},
		{&IgAutoSvc{Pin: "warp"}, "OPENAI", false}, {&IgAutoSvc{Auto: true}, "SPOTIFY", true},
		{&IgAutoSvc{}, "SPOTIFY", false}, {&IgAutoSvc{}, "DEV", true},
	}
	for _, c := range cases {
		if got := igSvcIsAuto(c.rec, c.svc); got != c.want {
			t.Errorf("%s %+v: %v", c.svc, c.rec, got)
		}
	}
}

// every service the panel knows has a name, and every checked one is in the route list
func TestIgSvcDefs(t *testing.T) {
	for _, d := range igSvcStart {
		if !contains(igServices, d.Key) || igSvcName(d.Key) == "" {
			t.Errorf("%s: not in igServices or no name", d.Key)
		}
		if strings.ContainsAny(d.URL+d.Trace, "'\n") {
			t.Errorf("%s: quote in url", d.Key)
		}
	}
	for k := range igSvcNew {
		if igSvcByKey[k] == nil {
			t.Errorf("%s: new but no def", k)
		}
	}
	for k, n := range igSvcTries {
		if d := igSvcByKey[k]; d == nil || d.Block == "" || n < 2 {
			t.Errorf("%s: several tries need a def with a Block code", k)
		}
	}
	s := igSvcScript([]string{"OPENAI", "NETFLIX", "SHAZAM"}, gemRelayPort)
	for _, want := range []string{
		"p OPENAI 'https://api.openai.com/v1/models' 'chatgpt.com' 1 '403' &",
		"p NETFLIX 'https://www.netflix.com/' '' 1 '' &",
		"p SHAZAM 'https://amp.shazam.com/' '' 6 '403' &", // asked 6 times: one 403 is the answer
		"grep -q ':12370 '", "socks5h://127.0.0.1:12370",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in %s", want, s)
		}
	}
	if own := igSvcScript([]string{"SHAZAM"}, igSvcOwnPort); !strings.Contains(own, "socks5h://127.0.0.1:12371") || strings.Contains(own, "12370") {
		t.Error(own)
	}
}

// Shazam: Google's front end refuses (403) a server IP it places in Iran; 404 is its API's normal
// answer to "/". Auto starts on the server's own IP and has WARP / a proxy to move to.
func TestIgSvcShazam(t *testing.T) {
	d := igSvcByKey["SHAZAM"]
	if d == nil || !igSvcNew["SHAZAM"] || !igSvcIsAuto(nil, "SHAZAM") || igSvcIsAuto(&IgAutoSvc{Pin: "warp"}, "SHAZAM") {
		t.Fatal("SHAZAM: a new service on Auto unless pinned")
	}
	live, _ := igSvcParse([]string{"S SHAZAM 403 - -"})
	if live["SHAZAM"] == nil || live["SHAZAM"].OK {
		t.Errorf("403 = refused: %+v", live["SHAZAM"])
	}
	if live, _ = igSvcParse([]string{"S SHAZAM 404 - -"}); !live["SHAZAM"].OK {
		t.Error("404 = the API answers")
	}
	c := igSvcCands(igSvcPref(d, &Server{Country: "DE"}, nil), map[string]string{"warps": "2", "proxies": "1"})
	if strings.Join(c, ",") != "direct,warp,proxy" || igSvcNext(c, "direct") != "warp" {
		t.Errorf("exits: %v", c)
	}
}

// an agent older than a service does not report it: Auto must not ask it for that route (the
// refused "routeset" would stop every other service's Auto on that server)
func TestIgSvcKnown(t *testing.T) {
	old := map[string]string{"ig": "warp", "openai": "warp", "apple": "direct"}
	if igSvcKnown(old, "SHAZAM") || !igSvcKnown(old, "APPLE") || !igSvcKnown(map[string]string{"shazam": "direct"}, "SHAZAM") {
		t.Error("known")
	}
	if keys := igSvcCheckKeys(&Server{}, old); contains(keys, "SHAZAM") || !contains(keys, "APPLE") {
		t.Errorf("check keys of an old agent: %v", keys)
	}
}

// a moved service goes back to the server's own IP only when that IP answers it again
func TestIgSvcOwnHoldsAndBack(t *testing.T) {
	own, _ := igSvcParse([]string{"S SHAZAM 403 - -", "S X 200 - -"})
	if !igSvcOwnHolds(own, "SHAZAM") || igSvcOwnHolds(own, "X") {
		t.Error("held while refused, released when it answers")
	}
	if igSvcOwnHolds(nil, "SHAZAM") || igSvcOwnHolds(own, "REDDIT") {
		t.Error("not asked (no own relay) = the old way: try it")
	}
	if igSvcBack(0) != igSvcBackMin || igSvcBack(1) != 2*igSvcBackMin || igSvcBack(9) != igSvcBackMax || igSvcBack(-1) != igSvcBackMin {
		t.Errorf("back: %v %v %v", igSvcBack(0), igSvcBack(1), igSvcBack(9))
	}
}

// A part-time service on the own IP is asked on the own IP's relay too; a refusal there is its
// answer (a "My sites" entry hid it on the users' route) and moves it at once.
func TestIgSvcOwnAsk(t *testing.T) {
	keys := []string{"X", "SHAZAM", "APPLE"}
	if a := igSvcOwnAsk(keys, map[string]string{"shazam": "direct", "x": "direct", "apple": "direct"}); strings.Join(a, ",") != "SHAZAM" {
		t.Fatalf("on the own IP: %v", a)
	}
	if a := igSvcOwnAsk(keys, map[string]string{"shazam": "warp6", "x": "direct"}); len(a) != 0 {
		t.Fatalf("moved already: %v", a)
	}
	live, _ := igSvcParse([]string{"S SHAZAM 404 - -", "S X 200 - -"})
	own, _ := igSvcParse([]string{"S SHAZAM 403 - -", "S X 403 - -"})
	igSvcOwnMerge(live, own)
	if live["SHAZAM"].OK || live["SHAZAM"].Code != "403" || !live["X"].OK {
		t.Fatalf("refused on the own IP: %+v %+v", live["SHAZAM"], live["X"])
	}
	live, _ = igSvcParse([]string{"S SHAZAM 404 - -"})
	slow, _ := igSvcParse([]string{"S SHAZAM 000 - -"})
	igSvcOwnMerge(live, slow)
	if !live["SHAZAM"].OK {
		t.Fatal("a dead own relay is not a refusal")
	}
	if !igSvcMoveNow("SHAZAM", own["SHAZAM"], 1) || igSvcMoveNow("SHAZAM", slow["SHAZAM"], 1) || !igSvcMoveNow("SHAZAM", slow["SHAZAM"], igSvcBadTimes) {
		t.Error("Shazam: a refusal moves at once, a timeout after igSvcBadTimes")
	}
	if igSvcMoveNow("X", own["X"], 1) || !igSvcMoveNow("X", own["X"], igSvcBadTimes) {
		t.Error("other services: after igSvcBadTimes failures in a row, as before")
	}
}

// Shazam follows Google's judgement of the server's IP: WARP first where Google is off the own IP.
func TestIgSvcPrefShazam(t *testing.T) {
	d := igSvcByKey["SHAZAM"]
	for g, want := range map[string]string{"direct": "direct,warp,proxy", "": "direct,warp,proxy", "warp6": "warp,proxy,direct", "ipv6": "warp,proxy,direct", "proxy2": "warp,proxy,direct"} {
		inf := map[string]string{"google": g, "warps": "2", "proxies": "1"}
		if c := igSvcCands(igSvcPref(d, &Server{Country: "DE"}, inf), inf); strings.Join(c, ",") != want {
			t.Errorf("google=%q: %v, want %s", g, c, want)
		}
	}
	inf := map[string]string{"google": "ipv6", "warps": "0", "proxies": "0"}
	if c := igSvcCands(igSvcPref(d, nil, inf), inf); strings.Join(c, ",") != "direct" {
		t.Errorf("no WARP and no proxy: %v", c)
	}
	if c := igSvcPref(igSvcByKey["APPLE"], nil, map[string]string{"google": "warp6"}); c[0] != "direct" {
		t.Errorf("only Shazam: %v", c)
	}
}

// Adult sites: WARP first on a server in a country that blocks them, own IP first elsewhere.
func TestIgSvcPrefAdult(t *testing.T) {
	d := igSvcByKey["ADULT"]
	inf := map[string]string{"warps": "2", "proxies": "1"}
	if c := igSvcCands(igSvcPref(d, &Server{Country: "TR"}, nil), inf); strings.Join(c, ",") != "warp,proxy,direct" {
		t.Fatalf("TR: %v", c)
	}
	if c := igSvcCands(igSvcPref(d, &Server{Country: "tr "}, nil), map[string]string{"warps": "0", "proxies": "0"}); strings.Join(c, ",") != "direct" {
		t.Fatalf("TR without WARP or proxy: %v", c)
	}
	if c := igSvcCands(igSvcPref(d, &Server{Country: "DE"}, nil), inf); c[0] != "direct" {
		t.Fatalf("DE: %v", c)
	}
	if c := igSvcCands(igSvcPref(igSvcByKey["X"], &Server{Country: "TR"}, nil), inf); c[0] != "direct" {
		t.Fatalf("another service in TR: %v", c)
	}
	if c := igSvcPref(d, nil, nil); strings.Join(c, ",") != strings.Join(igAutoOwn, ",") {
		t.Fatalf("no server: %v", c)
	}
}
