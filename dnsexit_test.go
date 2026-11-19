package main

import (
	"strings"
	"testing"
	"time"
)

func TestDNSExitParse(t *testing.T) {
	// the USA server on 2026-11-18: a US exit, netcup's resolvers in Germany
	line := "D\tUnited States\t0\t" + `{"dns":{"geo":"Germany - netcup GmbH","ip":"46.38.225.220"}}` + "\t" +
		`{"dns":{"geo":"Germany - netcup GmbH","ip":"46.38.225.221"}}` + "\t"
	d, ok := dnsExitParse([]string{"S\tIG\t200\t0.3\t", line})
	if !ok || d.Exit != "United States" || len(d.DNS) != 1 || d.DNS[0] != "Germany - netcup GmbH" || d.Mine {
		t.Fatalf("parse = %+v %v", d, ok)
	}
	if v := d.Verdict(); v != "bad" {
		t.Fatalf("verdict = %q, want bad", v)
	}
	c := dnsExitCheck(d)
	if !c.OK || !c.Warn || !strings.Contains(c.Why, "Germany - netcup GmbH") || !strings.Contains(c.Why, "United States") {
		t.Fatalf("check = %+v", c)
	}
	// after the fix: Cloudflare answers from the US, and the panel's entry is there
	d, ok = dnsExitParse([]string{"D\tUnited States\t1\t" + `{"dns":{"geo":"United States - Cloudflare, Inc.","ip":"172.71.193.107"}}`})
	if !ok || d.Verdict() != "ok" || !d.Mine {
		t.Fatalf("after fix = %+v %v %q", d, ok, d.Verdict())
	}
	if c := dnsExitCheck(d); c.Warn || c.Why != "" || !c.Mine {
		t.Fatalf("check after fix = %+v", c)
	}
	// resolvers in two countries, one of them the exit's
	d, _ = dnsExitParse([]string{"D\tFinland\t0\t" + `{"dns":{"geo":"Finland - Hetzner Online GmbH"}}` + "\t" + `{"dns":{"geo":"Germany - Hetzner Online GmbH"}}`})
	if d.Verdict() != "mixed" || dnsExitCheck(d).Warn {
		t.Fatalf("mixed = %+v %q", d, d.Verdict())
	}
	d, _ = dnsExitParse([]string{"D\tThe Netherlands\t0\t" + `{    "dns": {        "geo": "Netherlands - Cloudflare, Inc.",        "ip": "1.2.3.4"    }}`})
	if d.Verdict() != "ok" {
		t.Fatalf("The Netherlands = %+v %q", d, d.Verdict())
	}
	// no reading: ip-api gave nothing (rate limit), a redirect page, no exit country
	for _, l := range []string{"D\tGermany\t0\t\t\t", "D\tGermany\t0\t<a href=\"http://x\">Found</a>.", "D\t\t0\t" + `{"dns":{"geo":"Germany - x"}}`, "S\tIG\t200"} {
		if d, ok := dnsExitParse([]string{l}); ok {
			t.Errorf("%q gave a reading: %+v", l, d)
		}
	}
}

func TestDNSExitStep(t *testing.T) {
	st := &dnsExitState{}
	now := time.Now()
	if dnsExitStep(st, "bad", now) {
		t.Fatal("one round reported")
	}
	if !dnsExitStep(st, "bad", now) {
		t.Fatal("second round in a row not reported")
	}
	if dnsExitStep(st, "bad", now.Add(24*time.Hour)) {
		t.Fatal("reported again within dnsExitAlert")
	}
	if dnsExitStep(st, "", now.Add(48*time.Hour)) || st.bad != 3 {
		t.Fatal("a round without a reading changed the count")
	}
	if dnsExitStep(st, "mixed", now) || st.bad != 0 {
		t.Fatal("a resolver in the exit's country did not clear the count")
	}
	if dnsExitStep(st, "bad", now.Add(8*24*time.Hour)) {
		t.Fatal("reported after one round")
	}
	if !dnsExitStep(st, "bad", now.Add(8*24*time.Hour)) {
		t.Fatal("not reported again after dnsExitAlert")
	}
}

func TestIgParseHealthDNS(t *testing.T) {
	r := igParseHealth([]string{"S\tIG\t200\t0.2\t", "D\tUnited States\t0\t" + `{"dns":{"geo":"Germany - netcup GmbH"}}`, "S\tGOOGLE\t204\t0.1\t"})
	if len(r.Svcs) != 3 || r.Svcs[2].K != "DNS" || !r.Svcs[2].Warn {
		t.Fatalf("svcs = %+v", r.Svcs)
	}
	if !strings.Contains(igHealthScript, "dnx >") || !strings.Contains(igHealthScript, "dnx(){") {
		t.Fatal("the health script does not run the DNS probe")
	}
}
