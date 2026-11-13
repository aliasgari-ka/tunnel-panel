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
	s := igSvcScript([]string{"OPENAI", "NETFLIX"})
	if !strings.Contains(s, "p OPENAI 'https://api.openai.com/v1/models' 'chatgpt.com' &") {
		t.Error(s)
	}
}
