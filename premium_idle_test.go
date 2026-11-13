package main

import (
	"strings"
	"testing"
	"time"
)

// An ipx core with the tcp carrier narrows its raw-socket filter once it runs (both sides,
// each with the other server as peer); other carriers and modes are left as they were.
func TestPremiumCarrierFilterInUnit(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	tun := func(opts map[string]string) *Tunnel {
		return &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "443", Index: 3,
			Options: map[string]map[string]string{"premium": opts}, Secrets: map[string]string{}}
	}
	ir, kh, err := buildPlans(methodPremium, tun(nil), srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		side string
		p    SidePlan
		peer string
	}{{"Iran", ir, "198.51.100.2"}, {"foreign", kh, "192.0.2.1"}} {
		post := c.p.Unit.ExecStartPost
		for _, want := range []string{"-/bin/sh -c '", probeBin + " pktfilter", "-pid $MAINPID", "-unit %n", "-peer " + c.peer + " ", "-sport 443 -dport 443", "-watch &'"} {
			if !strings.Contains(post, want) {
				t.Errorf("%s ExecStartPost %q lacks %q", c.side, post, want)
			}
		}
		has := false
		for _, a := range c.p.Artifacts {
			has = has || a.Dest == probeArt.Dest
		}
		if !has {
			t.Errorf("%s side doesn't get the probe binary the filter needs", c.side)
		}
		u := renderUnit(c.p.Unit)
		if !strings.Contains(u, "\nExecStartPost="+post+"\n") || strings.Index(u, "ExecStartPost=") < strings.Index(u, "ExecStart=") {
			t.Errorf("%s unit doesn't run it after ExecStart:\n%s", c.side, u)
		}
	}
	for name, opts := range map[string]map[string]string{
		"gre carrier":  {"profile": "gre"},
		"icmp carrier": {"profile": "icmp"},
		"tcpmux mode":  {"mode": "tcpmux"},
		"anytls mode":  {"mode": "anytls"},
	} {
		ir, kh, err := buildPlans(methodPremium, tun(opts), srv, fsrv, Settings{})
		if err != nil {
			t.Fatal(err)
		}
		if ir.Unit.ExecStartPost != "" || kh.Unit.ExecStartPost != "" {
			t.Errorf("%s: a carrier filter where there is no tcp carrier: %q", name, ir.Unit.ExecStartPost)
		}
		if strings.Contains(renderUnit(ir.Unit), "ExecStartPost") {
			t.Errorf("%s: unit has an ExecStartPost line", name)
		}
	}
}

// The sweep narrows the cores already running: the tcp-carrier Premium paths of a tunnel.
func TestPremiumTCPUnits(t *testing.T) {
	hs := &Tunnel{ID: "abc", Active: "gre", Family: "v4", HotStandby: true, Paths: []HSPath{
		{Method: "gre", Family: "v4", Index: 1},
		{Method: "premium", Family: "v4", Index: 18},
		{Method: "bp_reverse", Family: "v4", Index: 20},
	}}
	if got := premiumTCPUnits(hs); len(got) != 1 || got[0] != "tp-abcx18.service" {
		t.Fatalf("units = %v", got)
	}
	hs.Paths[1].Opts = map[string]string{"profile": "gre"}
	if got := premiumTCPUnits(hs); len(got) != 0 {
		t.Fatalf("a gre-carrier path was listed: %v", got)
	}
	hs.Paths[1].Opts, hs.Paths[1].Failed = nil, "no license"
	if got := premiumTCPUnits(hs); len(got) != 0 {
		t.Fatalf("a failed path was listed: %v", got)
	}
	plain := &Tunnel{ID: "def", Active: "premium", Family: "v4"}
	if got := premiumTCPUnits(plain); len(got) != 1 || got[0] != "tp-def.service" {
		t.Fatalf("plain tunnel units = %v", got)
	}
	plain.Options = map[string]map[string]string{"premium": {"mode": "tcpmux"}}
	if got := premiumTCPUnits(plain); len(got) != 0 {
		t.Fatalf("a tcpmux tunnel was listed: %v", got)
	}
	s := premiumFilterScript([]string{"tp-abcx18.service"}, "81.12.32.18")
	for _, want := range []string{"P=" + probeBin, "MainPID --value 'tp-abcx18.service'", "pktfilter -pid \"$pid\" -unit 'tp-abcx18.service' -peer '81.12.32.18'", "-wait 0s"} {
		if !strings.Contains(s, want) {
			t.Errorf("sweep script lacks %q:\n%s", want, s)
		}
	}
}

func TestMethodEmulatedOn(t *testing.T) {
	cases := []struct {
		m    *Method
		arch string
		want bool
	}{
		{methodPremium, "aarch64", true},
		{methodPremium, "x86_64", false},
		{methodByID["tpk"], "aarch64", true},
		{methodByID["tpk"], "x86_64", false},
		{methodPremiumV1, "x86_64", true},
		{methodPremiumV1, "aarch64", false},
		{methodByID["gre"], "aarch64", false},
		{methodByID["bp_reverse"], "aarch64", false},
		{methodPremium, "", false},
	}
	for _, c := range cases {
		if got := methodEmulatedOn(c.m, c.arch); got != c.want {
			t.Errorf("methodEmulatedOn(%s, %q) = %v, want %v", c.m.ID, c.arch, got, c.want)
		}
	}
	small := &Server{Name: "usa-kharej", Arch: "aarch64", HW: &Hardware{Cores: 2}}
	big := &Server{Name: "IRAN-USA", Arch: "x86_64", HW: &Hardware{Cores: 3}}
	if why := hsCostlyOn(methodPremium, big, small); !strings.Contains(why, "usa-kharej") {
		t.Errorf("premium on a 2-core arm64 server: %q", why)
	}
	if why := hsCostlyOn(methodPremium, big, &Server{Name: "x", Arch: "aarch64", HW: &Hardware{Cores: 4}}); why != "" {
		t.Errorf("premium on a 4-core arm64 server is costly: %q", why)
	}
	if why := hsCostlyOn(methodPremium, big, &Server{Name: "x", Arch: "aarch64"}); why != "" {
		t.Errorf("unknown size counts as small: %q", why)
	}
	if why := hsCostlyOn(methodByID["gre"], big, small); why != "" {
		t.Errorf("a native kernel path is costly: %q", why)
	}
}

// Auto mode doesn't add an emulated core as a standby on a 2-core server while cheaper paths
// work; it keeps one that runs and one the user asked for by hand.
func TestHSLeaveOutCostlyStandby(t *testing.T) {
	a, st := hsRemoveFixture(t)
	tun := st.Tunnel("aaaaaaaaaaaa")
	_ = st.Update(func(s *State) error {
		for _, sv := range s.Servers {
			if sv.ID == "kh1" {
				sv.Arch, sv.HW = "aarch64", &Hardware{Cores: 2}
			}
			if sv.ID == "ir1" {
				sv.Arch, sv.HW = "x86_64", &Hardware{Cores: 3}
			}
		}
		return nil
	})
	premium := methodPremium
	a.benchRes = map[string][]BenchResult{benchKey("ir1", "kh1", "v4"): {
		{Method: "premium", OK: true, Score: 90},
	}}
	// no cheaper path has worked yet: premium stays a candidate
	if !a.hsCandidate(tun, premium, "v4") {
		t.Fatal("left out with no cheaper working path")
	}
	a.benchRes[benchKey("ir1", "kh1", "v4")] = []BenchResult{
		{Method: "premium", OK: true, Score: 90},
		{Method: "gre", OK: true, Score: 60},
		{Method: "bp_reverse", OK: true, Score: 50},
		{Method: "tpk", OK: true, Score: 80}, // emulated too: not a cheaper path
	}
	if a.hsCandidate(tun, premium, "v4") {
		t.Fatal("emulated premium on a 2-core server is still added as a standby")
	}
	if !a.hsCandidateBase(tun, premium, "v4") {
		t.Fatal("the base check (what a hand choice uses) leaves it out")
	}
	for _, p := range a.hsPlan(tun, "gre", "v4") {
		if p.Method == "premium" || p.Method == "tpk" {
			t.Fatalf("hsPlan planned %s as a standby", p.Method)
		}
	}
	// asked for by hand: kept
	a.hsWantPath(tun, "premium|v4", true)
	if !a.hsCandidate(tun, premium, "v4") {
		t.Fatal("a path the user asked for is left out")
	}
	a.hsWantPath(tun, "premium|v4", false)
	// running already: kept
	_ = st.Update(func(*State) error {
		tun.Paths = append(tun.Paths, HSPath{Method: "premium", Family: "v4", Index: 9})
		return nil
	})
	if !a.hsCandidate(tun, premium, "v4") {
		t.Fatal("a running path is left out")
	}
	if drop, _ := a.hsPathDiff(tun); len(drop) != 0 {
		for _, p := range drop {
			if p.Method == "premium" {
				t.Fatal("Repair's diff would take out a running costly path")
			}
		}
	}
	// a bigger server: nothing left out
	_ = st.Update(func(s *State) error {
		tun.Paths = tun.Paths[:len(tun.Paths)-1]
		for _, sv := range s.Servers {
			if sv.ID == "kh1" {
				sv.HW = &Hardware{Cores: 4}
			}
		}
		return nil
	})
	if !a.hsCandidate(tun, premium, "v4") {
		t.Fatal("left out on a 4-core server")
	}
}

// Put back and "use" record the hand choice; a removal by hand clears it.
func TestHSWantFollowsHandChoices(t *testing.T) {
	a, st := hsRemoveFixture(t)
	tun := st.Tunnel("aaaaaaaaaaaa")
	j, err := a.hsRemovePath(tun, "paqet", "v4")
	if err != nil {
		t.Fatal(err)
	}
	hsWaitJob(t, j)
	if j, err = a.hsRestorePath(tun, "paqet", "v4"); err != nil {
		t.Fatal(err)
	}
	if j != nil {
		hsWaitJob(t, j)
	}
	st.View(func(*State) {
		if !contains(tun.HSWant, "paqet|v4") {
			t.Fatalf("put back not recorded: %v", tun.HSWant)
		}
	})
	_ = st.Update(func(*State) error {
		has := false
		for _, p := range tun.Paths {
			has = has || p.Method == "paqet"
		}
		if !has {
			tun.Paths = append(tun.Paths, HSPath{Method: "paqet", Family: "v4", Index: 3})
		}
		return nil
	})
	if j, err = a.hsRemovePath(tun, "paqet", "v4"); err != nil {
		t.Fatal(err)
	}
	hsWaitJob(t, j)
	st.View(func(*State) {
		if contains(tun.HSWant, "paqet|v4") {
			t.Fatalf("removed by hand but still wanted: %v", tun.HSWant)
		}
	})
}

// The hourly standby check's CPU readings reach the page's view, per side, for the paths the
// users aren't on; a reading with traffic, an old one, or the users' path shows nothing.
func TestIdleCPUOnView(t *testing.T) {
	a := &App{hsViews: map[string]*hsView{}}
	tun := &Tunnel{ID: "t9"}
	a.hsViews["t9"] = &hsView{Active: 1, Keys: []string{"premium|v4", "bp_reverse|v4", "gre|v4"}, OK: []bool{true, true, true}}
	keyOf := map[string]string{"tp-t9x18.service": "premium|v4", "tp-t9x20.service": "bp_reverse|v4", "tp-t9x45.service": "gre|v4"}
	a.noteIdleUse(tun, keyOf, []standbyUse{{unit: "tp-t9x18.service", cpu: 44}, {unit: "tp-t9x45.service", cpu: 1, kbit: 5000}}, true)
	a.noteIdleUse(tun, keyOf, []standbyUse{{unit: "tp-t9x18.service", cpu: 30}, {unit: "tp-t9x20.service", cpu: 70}}, false)
	v := a.hsViewCause("t9")
	if v == a.hsViews["t9"] {
		t.Fatal("the cached view was handed out (it is shared)")
	}
	if len(v.IdleIR) != 3 || v.IdleIR[0] != 44 || v.IdleKH[0] != 30 {
		t.Fatalf("premium idle = %v / %v, want 44 / 30", v.IdleIR, v.IdleKH)
	}
	if v.IdleIR[1] != -1 || v.IdleKH[1] != -1 {
		t.Fatalf("the users' path shows idle CPU: %v / %v", v.IdleIR, v.IdleKH)
	}
	if v.IdleIR[2] != -1 {
		t.Fatalf("a path with traffic counts as idle: %v", v.IdleIR)
	}
	if a.hsViews["t9"].IdleIR != nil {
		t.Fatal("the cached view was changed")
	}
	// old readings are not shown
	a.healthMu.Lock()
	for k, c := range a.idleUse {
		c.At = time.Now().Unix() - idleShowAge - 1
		a.idleUse[k] = c
	}
	a.healthMu.Unlock()
	if v := a.hsViewCause("t9"); v.IdleIR != nil {
		t.Fatalf("old readings shown: %v", v.IdleIR)
	}
}
