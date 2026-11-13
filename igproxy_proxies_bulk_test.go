package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func pxRows(lines ...string) []*igProxyRow {
	var rows []*igProxyRow
	for i, l := range lines {
		f := strings.Fields(l)
		u := f[3]
		if u == "-" {
			u = ""
		}
		rows = append(rows, &igProxyRow{N: i + 1, Type: f[0], Host: f[1], Port: f[2], user: u, Key: igProxyKey(f[0], f[1], f[2], u)})
	}
	return rows
}

func TestIgPxPlan(t *testing.T) {
	rows := pxRows("http 10.0.0.1 80 a", "http 10.0.0.2 80 b", "socks5 10.0.0.3 80 -", "http 10.0.0.4 80 d")
	info := map[string]string{"ig": "proxy4", "google": "proxy", "ytm": "proxy2", "spotify": "warp"}
	k := func(n int) string { return rows[n-1].Key }

	// 2 and 4 go: IG (on 4) moves to 3 by what it is, YTM (on 2) to all the others by default
	pl, err := igPxPlan(rows, info, []string{k(2), k(4)}, map[string]string{"IG": "key:" + k(3)})
	if err != nil {
		t.Fatal(err)
	}
	if pl.Del[0].N != 4 || pl.Del[1].N != 2 || pl.Left != 2 {
		t.Fatalf("order/left: %+v", pl)
	}
	mv := map[string]string{}
	for _, m := range pl.Moves {
		mv[m.Svc] = m.Via
	}
	if mv["IG"] != "proxy3" || mv["YTM"] != "proxy" || len(mv) != 2 {
		t.Fatalf("moves: %v", mv)
	}

	// every proxy goes: Google on "all proxies" and IG need a new way out
	all := []string{k(1), k(2), k(3), k(4)}
	if _, err := igPxPlan(rows, info, all, map[string]string{"IG": "warp"}); err == nil || !strings.Contains(err.Error(), "GOOGLE") {
		t.Fatalf("pool with nothing left: %v", err)
	}
	if _, err := igPxPlan(rows, info, all, map[string]string{"IG": "warp", "GOOGLE": "proxy", "YTM": "direct"}); err == nil {
		t.Fatal("all proxies accepted with nothing left")
	}
	if _, err := igPxPlan(rows, info, []string{k(3)}, map[string]string{"IG": "key:" + k(3)}); err != nil {
		t.Fatalf("an unaffected move is ignored: %v", err)
	}
	if _, err := igPxPlan(rows, info, []string{k(4)}, map[string]string{"IG": "key:" + k(4)}); err == nil {
		t.Fatal("moved onto a proxy that is deleted")
	}
	if _, err := igPxPlan(rows, info, []string{"nope"}, nil); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := igPxPlan(rows, info, []string{k(1)}, map[string]string{"IG": "proxy4;reboot"}); err != nil {
		t.Fatal(err) // IG is not affected by deleting 1: its move is not used
	}
	if _, err := igPxPlan(rows, info, []string{k(4)}, map[string]string{"IG": "warp;reboot"}); err == nil {
		t.Fatal("bad route accepted")
	}
}

// The script itself, in bash, against an agent that deletes and renumbers like the real one.
const fakeAgent = `#!/bin/bash
D=$FAKE; f=$D/proxies
route_of(){ cat "$D/route_$1" 2>/dev/null; }
echo "$*" >> "$D/calls"
case "$1 $2" in
  "route "*) [ -f "$D/fail_route" ] && { echo "  !! no"; exit 1; }; echo "$3" > "$D/route_$2"; echo "  $2 -> $3";;
  "proxy del") n=$3; sed -i "${n}d" "$f"
     for t in IG GOOGLE YTM; do h=$(route_of $t); [[ "$h" =~ ^proxy([0-9]+)$ ]] || continue; p=${BASH_REMATCH[1]}
       if [ "$p" = "$n" ]; then echo proxy > "$D/route_$t"; elif [ "$p" -gt "$n" ]; then echo "proxy$((p-1))" > "$D/route_$t"; fi; done
     echo "  proxy $n removed";;
esac
`

func runBulk(t *testing.T, d string, sc string) string {
	sc = strings.ReplaceAll(sc, igProxyFile, filepath.ToSlash(filepath.Join(d, "proxies")))
	sc = strings.ReplaceAll(sc, "timeout 150 igproxy", "timeout 150 "+filepath.ToSlash(filepath.Join(d, "igproxy")))
	cmd := exec.Command("bash", "-c", sc)
	cmd.Env = append(os.Environ(), "FAKE="+filepath.ToSlash(d))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	return string(out)
}

func TestIgPxBulkScriptBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil || runtime.GOOS == "windows" && os.Getenv("TP_BASH_TEST") == "" {
		t.Skip("bash test (set TP_BASH_TEST=1 on Windows)")
	}
	lines := []string{"http 10.0.0.1 80 a x", "http 10.0.0.2 80 b x", "socks5 10.0.0.3 80 - -", "http 10.0.0.4 80 d x", "http 10.0.0.5 80 e x"}
	setup := func() string {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "proxies"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
		os.WriteFile(filepath.Join(d, "igproxy"), []byte(fakeAgent), 0o755)
		os.WriteFile(filepath.Join(d, "route_IG"), []byte("proxy4\n"), 0o644)
		os.WriteFile(filepath.Join(d, "route_GOOGLE"), []byte("proxy5\n"), 0o644)
		os.WriteFile(filepath.Join(d, "route_YTM"), []byte("proxy2\n"), 0o644)
		return d
	}
	rd := func(d, n string) string {
		b, _ := os.ReadFile(filepath.Join(d, n))
		return strings.TrimSpace(string(b))
	}
	rows := pxRows(lines...)
	info := map[string]string{"ig": "proxy4", "google": "proxy5", "ytm": "proxy2"}

	// delete 2 and 4; IG (on 4) moves to proxy 5 first; Google on 5 stays on 5 (now 3)
	d := setup()
	pl, err := igPxPlan(rows, info, []string{rows[1].Key, rows[3].Key}, map[string]string{"IG": "key:" + rows[4].Key})
	if err != nil {
		t.Fatal(err)
	}
	out := runBulk(t, d, igPxBulkScript(pl, 150))
	if !strings.Contains(out, "__D 4 0") || !strings.Contains(out, "__D 2 0") || !strings.Contains(out, "__M IG 0") || !strings.HasSuffix(strings.TrimSpace(out), "__RC=0") {
		t.Fatalf("out:\n%s", out)
	}
	if got := rd(d, "proxies"); got != "http 10.0.0.1 80 a x\nsocks5 10.0.0.3 80 - -\nhttp 10.0.0.5 80 e x" {
		t.Fatalf("left:\n%s", got)
	}
	if rd(d, "route_IG") != "proxy3" || rd(d, "route_GOOGLE") != "proxy3" || rd(d, "route_YTM") != "proxy" {
		t.Fatalf("routes: IG %s GOOGLE %s YTM %s", rd(d, "route_IG"), rd(d, "route_GOOGLE"), rd(d, "route_YTM"))
	}

	// the list changed under the page: nothing is touched
	d = setup()
	os.WriteFile(filepath.Join(d, "proxies"), []byte(strings.Join(lines[1:], "\n")+"\n"), 0o600)
	out = runBulk(t, d, igPxBulkScript(pl, 150))
	if !strings.Contains(out, "__CHANGED") || rd(d, "calls") != "" {
		t.Fatalf("changed list: %s / calls %q", out, rd(d, "calls"))
	}

	// a move that fails stops it before any proxy is deleted
	d = setup()
	os.WriteFile(filepath.Join(d, "fail_route"), nil, 0o644)
	out = runBulk(t, d, igPxBulkScript(pl, 150))
	if !strings.Contains(out, "__M IG 1") || strings.Contains(out, "__D") || len(strings.Split(rd(d, "proxies"), "\n")) != 5 {
		t.Fatalf("failed move: %s", out)
	}
}
