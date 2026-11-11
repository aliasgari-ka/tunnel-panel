package main

import (
	"strings"
	"testing"
)

// the shape the agent's state files give on a BALANCE server (live xe107, IPs replaced)
func TestIgParseWarps(t *testing.T) {
	out := strings.Join([]string{
		"W\tn=2\tep=engage.cloudflareclient.com:2408\told=\tkey=\tip=\tloc=\twarp=\tsel=\tselage=\tout=ip\tnew=\tfail=\tgcc=\tgccage=",
		"W\tn=1\tep=engage.cloudflareclient.com:2408\told=\tkey=1\tip=2a09:bac5::1\tloc=DE\twarp=plus\tsel=ok 324\tselage=1973\tout=\tnew=\tfail=\tgcc=\tgccage=",
		"W\tn=3\tep=e:2408\told=1\tkey=\tip=\tloc=\twarp=\tsel=no 0 audio 403\tselage=60\tout=\tnew=no Instagram music\tfail=2\tgcc=US\tgccage=55",
		"W\tn=4\tep=e:2408\told=\tkey=\tip=104.28.0.1\tloc=NL\twarp=on\tsel=? 278\tselage=10\tout=\tnew=only 9 Mbps\tfail=\tgcc=\tgccage=",
		"W\tn=5\tep=e:2408\told=\tkey=\tip=\tloc=\twarp=\tsel=down 0\tselage=5\tout=\tnew=\tfail=\tgcc=\tgccage=",
		"S\tactive=\tgact=7\tsel=ok\tpoolip=2a09:bac5::1\tselago=900",
	}, "\r\n")
	r := igParseWarps(out)
	if len(r.Warps) != 5 || r.GAct != 7 || r.Active != 0 || r.PoolIP != "2a09:bac5::1" || r.SelAgo != 900 || r.Sel != "ok" {
		t.Fatalf("server line / count: %+v", r)
	}
	for i, w := range r.Warps {
		if w.N != i+1 {
			t.Fatalf("not sorted: %+v", r.Warps)
		}
	}
	w := r.Warps
	if w[0].State != "ok" || !w[0].Plus || !w[0].Key || w[0].Music != "ok" || w[0].Mbps != 324 || w[0].Loc != "DE" {
		t.Errorf("WARP 1: %+v", w[0])
	}
	if w[1].State != "out" || w[1].Why != "ip" || w[1].TestAge != -1 {
		t.Errorf("WARP 2: %+v", w[1])
	}
	if w[2].State != "repair" || w[2].Fails != 2 || w[2].Music != "no" || w[2].MusicWhy != "audio 403" || !w[2].Old || w[2].GCC != "US" {
		t.Errorf("WARP 3: %+v", w[2])
	}
	if w[3].State != "ok" || w[3].Plus || w[3].Next != "only 9 Mbps" || w[3].Music != "?" {
		t.Errorf("WARP 4: %+v", w[3])
	}
	if w[4].State != "down" {
		t.Errorf("WARP 5: %+v", w[4])
	}
	if e := igParseWarps("S\tnone=1\n"); len(e.Warps) != 0 || e.Warps == nil {
		t.Errorf("no WARPs: %+v", e)
	}
}

// the script never prints a key: only whether one exists
func TestIgWarpScriptNoSecrets(t *testing.T) {
	if strings.Count(igWarpScript, "$k") != 1 || !strings.Contains(igWarpScript, `[ -z "$k" ]`) || strings.Contains(igWarpScript, `cat "$D/warp-acc`) {
		t.Fatal("the WARP script prints a key")
	}
}
