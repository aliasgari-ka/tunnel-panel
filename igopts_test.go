package main

import "testing"

// the answer of server "nl" on 2026-11-12: 3 WARPs only for Google, no country list saved
const igOptsNL = "F\tmin_warps\t5\nF\tgrot_min\t0\nF\tmusic_min\t0\nF\tgwarps_n\t3\nE\tautokey\n" +
	"C\tminspeed\t200\nC\tgrotate\t20\nC\tmusiccheck\t5\nC\tgcountries\tUS GB DE FR NL FI SE CH AT BE IT ES PL CA JP SG AU\nC\tminwarps\t3\nC\tgwarps\t2\n" +
	"K\tminspeed\nK\tminwarps\nK\tgrotate\nK\tmusiccheck\nK\tgwarps\nK\tgcountries\nK\tmode\nK\tguard\nK\tautokey\nK\tgeosite\nK\tgspread\nK\tgall\nK\twarpauto\nK\tkwg\n"

// Regression: the page took "WARPs only for Google" from the WARPs Google uses now (the info
// line has no gwarps) and left the country box empty (no gcountries either).
func TestIgOptsLoadsSavedValues(t *testing.T) {
	o := igParseOpts(igOptsNL)
	want := map[string]string{"gwarps": "3", "minwarps": "5", "grotate": "0", "musiccheck": "0", "minspeed": "200",
		"gcountries": "US GB DE FR NL FI SE CH AT BE IT ES PL CA JP SG AU", "autokey": "on", "mode": "failover", "guard": "on", "geosite": "on", "kwg": "off"}
	for k, v := range want {
		if o.Val[k] != v {
			t.Errorf("%s = %q, want %q", k, o.Val[k], v)
		}
	}
	for k, own := range map[string]bool{"gwarps": true, "minwarps": true, "minspeed": false, "gcountries": false, "autokey": true, "guard": false} {
		if o.Own[k] != own {
			t.Errorf("own[%s] = %v, want %v", k, o.Own[k], own)
		}
	}
	if len(o.Keys) != 14 || o.Def["gwarps"] != "2" || o.Def["minwarps"] != "3" {
		t.Errorf("keys %v def %v", o.Keys, o.Def)
	}
}

func TestIgOptsOldAgent(t *testing.T) {
	o := igParseOpts("E\twarp_spread\nE\tguard_off\nC\tminspeed\t\nK\tminspeed\nK\tmode\n")
	if o.Val["mode"] != "balance" || o.Val["guard"] != "off" || o.Def["minspeed"] != "200" || o.Val["minspeed"] != "200" || len(o.Keys) != 2 {
		t.Errorf("%+v", o)
	}
	if !igParseOpts("N\t1\n").None {
		t.Error("no agent not seen")
	}
}

func TestIgOptVal(t *testing.T) {
	ok := map[[2]string]string{
		{"minspeed", "۱۵۰"}: "150", {"minwarps", " 20 "}: "20", {"gwarps", "٣"}: "3", {"musiccheck", "0"}: "0",
		{"grotate", "0"}: "0", {"grotate", "10"}: "10", {"grotate", "1440"}: "1440", {"grotate", "020"}: "20",
		{"gcountries", "us, gb،de"}: "US GB DE", {"mode", "BALANCE"}: "balance", {"guard", "On"}: "on",
	}
	for in, want := range ok {
		if got, err := igOptVal(in[0], in[1]); err != nil || got != want {
			t.Errorf("%v -> %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range [][2]string{{"minwarps", "21"}, {"gwarps", "10"}, {"musiccheck", "61"}, {"grotate", "5"}, {"grotate", "1441"},
		{"minspeed", "-1"}, {"minspeed", "1.5"}, {"minspeed", ""}, {"gcountries", "USA"}, {"gcountries", ""}, {"mode", "x"}, {"guard", "toggle"}, {"nope", "1"}} {
		if got, err := igOptVal(in[0], in[1]); err == nil {
			t.Errorf("%v accepted as %q", in, got)
		}
	}
}

// the old one-setting path takes the same values (and the agent's "toggle" for a switch)
func TestIgBuildSetUsesOptVal(t *testing.T) {
	c, err := igBuild("set", map[string]any{"key": "minwarps", "val": "۶"})
	if err != nil || c.args[2] != "6" {
		t.Fatalf("%v %v", c.args, err)
	}
	if _, err := igBuild("set", map[string]any{"key": "musiccheck", "val": "90"}); err == nil {
		t.Error("musiccheck 90 accepted (the agent refuses > 60)")
	}
	if c, err := igBuild("set", map[string]any{"key": "gspread", "val": "toggle"}); err != nil || c.args[2] != "toggle" {
		t.Errorf("toggle: %v %v", c.args, err)
	}
}
