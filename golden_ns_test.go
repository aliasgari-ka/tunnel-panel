package main

// Two Golden-GRE (dns) tunnels from one Iran server to two foreign servers, in network
// namespaces on one switch. Both relays on Iran use its single public address and port 53;
// a TPROXY rule per peer hands each its own packets. Also runs with the first tunnel in
// the old layout (its relay bound to port 53 itself), as on a server not re-applied yet.
// Run as root with TP_GOLDEN_E2E=1.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func goldenTopology(t *testing.T) {
	t.Helper()
	script := `set -e
for n in tir tkh tk2 tus tsw; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null || true; done
for n in tir tkh tk2 tus tsw; do ip netns add $n; ip -n $n link set lo up; done
ip -n tsw link add br0 type bridge; ip -n tsw link set br0 up
i=0
for n in tir tkh tk2; do
  i=$((i+1))
  ip link add v$n type veth peer name s$n
  ip link set v$n netns $n; ip link set s$n netns tsw
  ip -n tsw link set s$n master br0; ip -n tsw link set s$n up
  ip -n $n addr add 10.99.0.$i/24 dev v$n; ip -n $n link set v$n up
done
ip link add vus type veth peer name vui; ip link set vus netns tus; ip link set vui netns tir
ip -n tus addr add 10.98.0.2/24 dev vus; ip -n tus link set vus up
ip -n tir addr add 10.98.0.1/24 dev vui; ip -n tir link set vui up
ip -n tus route add default via 10.98.0.1
for n in tir tkh tk2; do
  ip netns exec $n iptables -w -P INPUT DROP; ip netns exec $n iptables -w -P FORWARD DROP
  ip netns exec $n iptables -w -A INPUT -i lo -j ACCEPT
  ip netns exec $n iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
mkdir -p /tmp/tp-e2e-www && head -c 2097152 /dev/urandom > /tmp/tp-e2e-www/blob.bin
`
	if out, err := execBash(script); err != nil {
		t.Fatalf("topology: %v\n%s", err, out)
	}
	execBash("ip netns exec tkh setsid python3 -m http.server 28579 --bind 0.0.0.0 -d /tmp/tp-e2e-www >/dev/null 2>&1 &")
	execBash("ip netns exec tk2 setsid python3 -m http.server 28580 --bind 0.0.0.0 -d /tmp/tp-e2e-www >/dev/null 2>&1 &")
	time.Sleep(time.Second)
}

func execBash(s string) (string, error) {
	out, err := exec.Command("bash", "-c", s).CombinedOutput()
	return string(out), err
}

func TestGoldenMultiNS(t *testing.T) {
	if os.Getenv("TP_GOLDEN_E2E") == "" {
		t.Skip("set TP_GOLDEN_E2E=1 (root, network namespaces, fou)")
	}
	goldenTopology(t)
	defer sh(t, "for n in tir tkh tk2 tus tsw; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")
	ir := &Server{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}
	k1 := &Server{ID: "k1", Name: "germany", IPv4: "10.99.0.2", Role: "foreign"}
	k2 := &Server{ID: "k2", Name: "usa", IPv4: "10.99.0.3", Role: "foreign"}
	get := func(port string) string {
		var got string
		for k := 0; k < 10; k++ {
			got = sh(t, "ip netns exec tus curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 8 http://10.98.0.1:"+port+"/blob.bin")
			if strings.HasPrefix(got, "200 2097152") {
				return "✓ 2 MB passes"
			}
			time.Sleep(2 * time.Second)
		}
		return "✕ FAILS (" + got + ")"
	}
	type combo struct {
		label    string
		mids     [2]string
		oldFirst bool
	}
	combos := []combo{
		{"Golden + Golden, both relays new", [2]string{"golden", "golden"}, false},
		{"Golden + Golden, first relay in the old layout (bound to :53 itself)", [2]string{"golden", "golden"}, true},
		{"Plain GRE + Plain GRE", [2]string{"gre", "gre"}, false},
		{"Golden + Plain GRE", [2]string{"golden", "gre"}, false},
	}
	if only := os.Getenv("TP_MULTI_ONLY"); only != "" {
		var keep []combo
		for _, c := range combos {
			if strings.Contains(c.label, only) {
				keep = append(keep, c)
			}
		}
		combos = keep
	}
	for _, cb := range combos {
		label, oldFirst := cb.label, cb.oldFirst
		var sides []*e2eSide
		var tns []*Tunnel
		var report []string
		for i, fg := range []*Server{k1, k2} {
			m := methodByID[cb.mids[i]]
			tn := &Tunnel{ID: fmt.Sprintf("g%d", i), Name: m.ID + "-" + fg.Name, ServerID: "ir", ForeignID: fg.ID, Family: "v4",
				Ports: fmt.Sprint(28579 + i), Index: 40 + i, Options: map[string]map[string]string{}, Secrets: map[string]string{}}
			irP, khP, err := buildPlans(m, tn, ir, fg, Settings{})
			if err != nil {
				t.Fatal(err)
			}
			if oldFirst && i == 0 {
				// what the previous version deployed: no steering rule, relay listening on :53
				for _, p := range []*SidePlan{&irP, &khP} {
					dir := tunnelDir(tn)
					for _, f := range []string{dir + "/up.sh", dir + "/down.sh"} {
						var keep []string
						for _, l := range strings.Split(string(p.Files[f].Content), "\n") {
							if !strings.Contains(l, "tpg-") {
								keep = append(keep, l)
							}
						}
						p.Files[f] = FileSpec{Content: []byte(strings.Join(keep, "\n")), Mode: 0o755}
					}
					p.Unit.ExecStart = strings.Replace(p.Unit.ExecStart, fmt.Sprintf(" --listen %d", deriveFor(tn, ir, fg, Settings{}).BasePort+3), "", 1)
				}
			}
			ns := map[string]string{"k1": "tkh", "k2": "tk2"}[fg.ID]
			base := t.TempDir()
			sk := &e2eSide{ns: ns, label: "KH", dir: base + "/kh", h: nsHost{ns}, plan: khP}
			si := &e2eSide{ns: "tir", label: "IR", dir: base + "/ir", h: nsHost{"tir"}, plan: irP}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			j := &Job{Status: "running"}
			if err := sk.up(ctx, t, j, tn); err != nil {
				t.Fatalf("%s foreign: %v", tn.Name, err)
			}
			if err := si.up(ctx, t, j, tn); err != nil {
				t.Fatalf("%s iran: %v", tn.Name, err)
			}
			cancel()
			sides = append(sides, sk, si)
			tns = append(tns, tn, tn)
		}
		time.Sleep(2 * time.Second)
		report = append(report, "tunnel to germany: "+get("28579"), "tunnel to usa:     "+get("28580"))
		report = append(report, "relays on Iran: "+strings.ReplaceAll(sh(t, "ip netns exec tir ss -Hlunp | grep golden | awk '{print $4}' | sort | tr '\\n' ' '"), "\n", " "))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		for i := len(sides) - 1; i >= 0; i-- {
			sides[i].down(ctx, tns[i])
		}
		cancel()
		left := sh(t, "for n in tir tkh tk2; do ip netns exec $n iptables-save 2>/dev/null; done | grep -cE 'tpg-|TPI_|TPF_|TPM_|TP_tp'")
		report = append(report, "firewall rules left after stop: "+left)
		t.Logf("\n== %s ==\n  %s", label, strings.Join(report, "\n  "))
		for _, r := range report[:2] {
			if !strings.Contains(r, "✓") {
				t.Errorf("%s: %s", label, r)
			}
		}
		if left != "0" {
			t.Errorf("%s: %s firewall rules left", label, left)
		}
	}
}

func TestGoldenConflict(t *testing.T) {
	st := &State{Tunnels: []*Tunnel{
		{ID: "a", Name: "first", ServerID: "ir", ForeignID: "k1", Family: "v4", Active: "golden"},
		{ID: "b", Name: "icmp-one", ServerID: "ir", ForeignID: "k3", Family: "v4", Active: "golden", Options: map[string]map[string]string{"golden": {"facade": "icmp"}}},
	}}
	cases := []struct {
		t    *Tunnel
		want string
	}{
		{&Tunnel{ID: "x", ServerID: "ir", ForeignID: "k2", Family: "v4"}, ""},      // another foreign server: fine
		{&Tunnel{ID: "x", ServerID: "ir", ForeignID: "k1", Family: "v4"}, "first"}, // same pair, same port 53
		{&Tunnel{ID: "x", ServerID: "ir", ForeignID: "k1", Family: "v4", Options: map[string]map[string]string{"golden": {"dnsport": "5353"}}}, ""},
		{&Tunnel{ID: "a", ServerID: "ir", ForeignID: "k1", Family: "v4"}, ""},          // itself (re-apply)
		{&Tunnel{ID: "x", ServerID: "ir", ForeignID: "k3", Family: "v4"}, ""},          // the other one is icmp
		{&Tunnel{ID: "bench", ServerID: "ir", ForeignID: "k1", Family: "v4"}, "first"}, // benchmark slot
	}
	for i, c := range cases {
		if got := goldenConflict(st, c.t); got != c.want {
			t.Errorf("case %d: got %q, want %q", i, got, c.want)
		}
	}
}
