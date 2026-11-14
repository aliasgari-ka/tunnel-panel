package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIgViaRank(t *testing.T) {
	if !(igViaRank("DE") < igViaRank("NL") && igViaRank("NL") < igViaRank("US")) {
		t.Error("Germany, then Europe, then the rest")
	}
	for _, cc := range []string{"IR", "RU", "CN", ""} {
		if igViaRank(cc) != -1 {
			t.Errorf("%q must not be a donor", cc)
		}
	}
}

func TestIgInsertVia(t *testing.T) {
	cases := []struct{ in, want []string }{
		{[]string{"warp", "proxy3", "direct"}, []string{"warp", "via", "proxy3", "direct"}},
		{[]string{"warp6", "warp", "proxy1"}, []string{"warp6", "warp", "via", "proxy1"}},
		{[]string{"proxy1", "direct"}, []string{"proxy1", "direct"}}, // no WARP candidate: no via
		{nil, nil},
	}
	for _, c := range cases {
		if got := igInsertVia(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: got %v want %v", c.in, got, c.want)
		}
	}
}

func TestIgViaOn(t *testing.T) {
	if igViaOn("  warp-via: off (WARPs connect to Cloudflare directly)") {
		t.Error("off")
	}
	if !igViaOn("  warp-via: 159.195.78.190:24080 (WARPs that are not Google's own connect through these)") {
		t.Error("on")
	}
	if igViaOn("unknown command") {
		t.Error("an old agent is not on")
	}
}

func TestIgViaFwdScript(t *testing.T) {
	if s := igViaFwdScript("add", "1.2.3.4; rm -rf /"); !strings.Contains(s, "__RC=2") || strings.Contains(s, "rm -rf") {
		t.Fatal("a bad address must not reach the shell")
	}
	if s := igViaFwdScript("drop", "1.2.3.4"); !strings.Contains(s, "__RC=2") {
		t.Fatal("unknown op")
	}
	s := igViaFwdScript("add", "91.107.137.157")
	for _, w := range []string{"IP=91.107.137.157", "ulimit -u", `[ "add" = add ]`, "igwarp-fwd.srcs", "--dport $PORT", "DST=162.159.192.1", "FORWARD", "echo __RC=0"} {
		if !strings.Contains(s, w) {
			t.Errorf("script lacks %q", w)
		}
	}
	if strings.Contains(s, "%!") {
		t.Error("format error")
	}
	// bash parses both scripts (the outer one and the forward it writes)
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"outer.sh": s, "fwd.sh": igViaFwd} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}
