package main

import (
	"strings"
	"testing"
	"time"
)

// The outages the log was full of (England, 2026-11-13 05:02 and 05:14; France 11-12 12:13):
// the users' path failed a probe at two one-minute reads while the switcher, checking every
// 2 s, never saw it down for its 30 s grace — the users stayed up. They are no outage now;
// every path down, or the users left on a dead path past the switcher's grace, still is.
func TestHSUsersCut(t *testing.T) {
	now := int64(1_800_000_000)
	v := func(active int, ok []bool, downAgo int64) *hsView {
		ch := make([]int64, len(ok))
		if active >= 0 && active < len(ok) {
			ch[active] = now - downAgo
		}
		return &hsView{Active: active, OK: ok, Changed: ch, Clock: now}
	}
	cases := []struct {
		name string
		v    *hsView
		cut  bool
		code string
	}{
		{"users' path works", v(0, []bool{true, false}, 0), false, ""},
		{"probe failed 10 s ago, another path works", v(6, []bool{true, false, true, false, false, false, false}, 10), false, "moving"},
		{"down past the grace, switcher still moving", v(1, []bool{true, false}, hsGrace+20), false, "moving"},
		{"left on a dead path", v(1, []bool{true, false}, hsMoveWait+5), true, "not_moved"},
		{"every path down", v(1, []bool{false, false}, 5), true, "all_down"},
		{"no users' path", &hsView{Active: -1}, true, "no_path"},
		{"nil view", nil, true, "no_path"},
		// an old switcher (no clock, no since): the old rule
		{"no since", &hsView{Active: 1, OK: []bool{true, false}}, true, "not_moved"},
	}
	for _, c := range cases {
		cut, code := hsUsersCut(c.v)
		if cut != c.cut || code != c.code {
			t.Errorf("%s: got %v %q, want %v %q", c.name, cut, code, c.cut, c.code)
		}
	}
}

func TestHSDownSince(t *testing.T) {
	first := time.Now()
	v := &hsView{Active: 0, OK: []bool{false}, Changed: []int64{1000}, Clock: 1100}
	if got := hsDownSince(v, first); first.Sub(got) < 99*time.Second || first.Sub(got) > 101*time.Second {
		t.Errorf("down 100 s ago on the switcher's clock, got %v before the first read", first.Sub(got))
	}
	if got := hsDownSince(nil, first); !got.Equal(first) {
		t.Errorf("no view: %v", got)
	}
	v.Clock = 0
	if got := hsDownSince(v, first); !got.Equal(first) {
		t.Errorf("no switcher clock: %v", got)
	}
}

// The causes are specific and in both languages.
func TestTunnelWhy(t *testing.T) {
	a := &App{}
	tun := &Tunnel{ID: "t1", HotStandby: true}
	all := &hsView{Active: 0, OK: []bool{false, false, false}, Paths: []string{"a", "b", "c"}}
	if w := a.tunnelWhy(tun, "tunnel link down (no traffic between the servers)", all); w.Code != "all_down" || !strings.Contains(w.En, "All 3 paths") || !strings.Contains(w.Fa, "هر 3 مسیر") {
		t.Errorf("all down: %+v", w)
	}
	stuck := &hsView{Active: 1, OK: []bool{true, false}, Paths: []string{"GRE (v4)", "BackPack (v4)"}}
	if w := a.tunnelWhy(tun, "tunnel link down", stuck); w.Code != "not_moved" || !strings.Contains(w.En, "BackPack (v4)") {
		t.Errorf("not moved: %+v", w)
	}
	if w := a.tunnelWhy(tun, "Iran service the switcher isn't running on the Iran server", nil); w.Code != "switcher" {
		t.Errorf("switcher: %+v", w)
	}
	if w := a.tunnelWhy(&Tunnel{ID: "t2"}, "Iran service failed", nil); w.Code != "iran_service" || !strings.Contains(w.En, "(failed)") {
		t.Errorf("service: %+v", w)
	}
	if w := a.tunnelWhy(&Tunnel{ID: "t2"}, "tunnel link down (no traffic between the servers)", nil); w.Code != "link" || w.Fa == "" {
		t.Errorf("link: %+v", w)
	}
}

// The old rule's hot-standby entries are marked, kept, and left out of the uptime.
func TestMarkProbeOnly(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	now := time.Now().Unix()
	_ = st.Update(func(s *State) error {
		s.Tunnels = []*Tunnel{{ID: "hs", HotStandby: true}, {ID: "one"}}
		s.OutagesFrom = now - 7*day
		s.Outages = []Outage{
			{ID: "a", Kind: "tunnel", Target: "hs", Start: now - 3600, End: now - 3480, Cause: "both servers answer on SSH → the tunnel itself (or its route) dropped, not the servers"},
			{ID: "b", Kind: "tunnel", Target: "one", Start: now - 3600, End: now - 3480, Cause: "both servers answer on SSH → the tunnel itself (or its route) dropped, not the servers"},
			{ID: "c", Kind: "tunnel", Target: "hs", Start: now - 1800, End: now - 1700, Cause: "both servers answer on SSH", Code: "all_down"},
			{ID: "d", Kind: "tunnel", Target: "hs", Start: now - 600, Cause: "Iran server x doesn't answer on SSH"},
		}
		return nil
	})
	a := &App{store: st}
	a.markProbeOnly()
	got := map[string]string{}
	a.store.View(func(s *State) {
		for _, o := range s.Outages {
			got[o.ID] = o.Old
		}
	})
	if got["a"] != "probe" || got["b"] != "" || got["c"] != "" || got["d"] != "" {
		t.Errorf("marks: %v", got)
	}
	var outs []Outage
	a.store.View(func(s *State) { outs = append(outs, s.Outages...) })
	if sp := spans(outs, "tunnel", "hs", now); len(sp) != 2 {
		t.Errorf("the old probe-only entry still counts in the uptime: %v", sp)
	}
}
