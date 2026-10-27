package main

// End-to-end test of the real method plans in network namespaces:
//
//	tus (user, IPv4) ── tir (Iran) ══ underlay (v4 or v6 only) ══ tkh (foreign, runs the service)
//
// Both servers run a ufw-like firewall (INPUT and FORWARD policy DROP) so the panel's own
// firewall openings are exercised. Each method's files, setup, unit hooks and daemon are
// deployed exactly as the panel would, with the per-tunnel dir remapped per side (the
// namespaces share one filesystem). Run as root with TP_E2E=v4 or TP_E2E=v6; the method
// binaries must already be in the panel cache (no network needed).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sh(t *testing.T, cmd string) string {
	out, _ := exec.Command("bash", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func e2eTopology(t *testing.T, fam string) {
	t.Helper()
	sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")
	script := `set -e
for n in tir tkh tus; do ip netns add $n; ip -n $n link set lo up; done
ip link add vir type veth peer name vkh; ip link set vir netns tir; ip link set vkh netns tkh
ip link add vus type veth peer name vui; ip link set vus netns tus; ip link set vui netns tir
ip -n tir link set vir up; ip -n tkh link set vkh up; ip -n tus link set vus up; ip -n tir link set vui up
`
	if fam == "v6" {
		script += "ip -n tir -6 addr add 2001:db8:99::1/64 dev vir nodad; ip -n tkh -6 addr add 2001:db8:99::2/64 dev vkh nodad\n"
	} else {
		script += "ip -n tir addr add 10.99.0.1/24 dev vir; ip -n tkh addr add 10.99.0.2/24 dev vkh\n"
	}
	script += `ip -n tus addr add 10.98.0.2/24 dev vus; ip -n tir addr add 10.98.0.1/24 dev vui
ip -n tus route add default via 10.98.0.1
for n in tir tkh; do
  for ipt in iptables ip6tables; do
    ip netns exec $n $ipt -w -P INPUT DROP; ip netns exec $n $ipt -w -P FORWARD DROP
    ip netns exec $n $ipt -w -A INPUT -i lo -j ACCEPT
    ip netns exec $n $ipt -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done
  ip netns exec $n ip6tables -w -A INPUT -p ipv6-icmp -j ACCEPT
done
mkdir -p /tmp/tp-e2e-www && head -c 2097152 /dev/urandom > /tmp/tp-e2e-www/blob.bin
`
	if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("topology: %v\n%s", err, out)
	}
	bind := "0.0.0.0"
	if fam == "v6" {
		bind = "::"
	}
	// the user's service on the foreign server
	exec.Command("bash", "-c", "ip netns exec tkh setsid python3 -m http.server 28579 --bind "+bind+" -d /tmp/tp-e2e-www >/dev/null 2>&1 &").Run()
	time.Sleep(time.Second)
}

type e2eSide struct {
	ns, label, dir string
	h              Host
	plan           SidePlan
	pidFile        string
}

func remap(s, from, to string) string { return strings.ReplaceAll(s, from, to) }

func (sd *e2eSide) up(ctx context.Context, t *testing.T, j *Job, tn *Tunnel) error {
	from := tunnelDir(tn)
	if err := pushArtifacts(ctx, j, sd.label, sd.h, sd.plan.Artifacts); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	for path, f := range sd.plan.Files {
		if os.Getenv("TP_E2E_DEBUG") != "" {
			f.Content = []byte(strings.ReplaceAll(string(f.Content), `log_level = "info"`, `log_level = "debug"`))
		}
		if err := sd.h.WriteFile(remap(path, from, sd.dir), []byte(remap(string(f.Content), from, sd.dir)), f.Mode); err != nil {
			return err
		}
	}
	run := func(what, cmd string) error {
		if cmd == "" {
			return nil
		}
		out, err := sd.h.Run(ctx, cmd, nil)
		if err != nil {
			return fmt.Errorf("%s: %v: %s", what, err, lastLine(out))
		}
		return nil
	}
	u := sd.plan.Unit
	if err := run("setup", "set -e\n"+remap(sd.plan.Setup, from, sd.dir)); err != nil {
		return err
	}
	pre := []string{u.ExecStartPre}
	pre = append(pre, u.ExtraPre...)
	for _, p := range pre {
		if err := run("pre", strings.TrimPrefix(remap(p, from, sd.dir), "-")); err != nil {
			return err
		}
	}
	start := remap(u.ExecStart, from, sd.dir)
	if w := os.Getenv("TP_E2E_EMU"); w != "" { // run the Premium core through the emulation wrapper
		start = strings.Replace(start, "/opt/backhaul-premium/backhaul_premium", w, 1)
	}
	if u.Type == "oneshot" {
		return run("start", start)
	}
	sd.pidFile = sd.dir + "/daemon.pid"
	return run("start", fmt.Sprintf("setsid nohup %s >%s/daemon.log 2>&1 </dev/null & echo $! > %s", start, sd.dir, sd.pidFile))
}

func (sd *e2eSide) down(ctx context.Context, tn *Tunnel) {
	from := tunnelDir(tn)
	u := sd.plan.Unit
	if sd.pidFile != "" {
		sd.h.Run(ctx, "kill $(cat "+sd.pidFile+") 2>/dev/null; sleep 1", nil)
	}
	for _, c := range append([]string{u.ExecStop, u.ExecStopPost}, u.ExtraPost...) {
		if c != "" {
			sd.h.Run(ctx, strings.TrimPrefix(remap(c, from, sd.dir), "-"), nil)
		}
	}
}

func TestE2EMethods(t *testing.T) {
	fam := os.Getenv("TP_E2E")
	if fam == "" {
		t.Skip("set TP_E2E=v4 or v6 (root, network namespaces)")
	}
	e2eTopology(t, fam)
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")

	ir := &Server{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}
	kh := &Server{ID: "kh", Name: "foreign", IPv4: "10.99.0.2", Role: "foreign"}
	if fam == "v6" {
		ir.IPv4, ir.IPv6 = "", "2001:db8:99::1"
		kh.IPv4, kh.IPv6 = "", "2001:db8:99::2"
	}
	set := Settings{FRPVersion: "0.61.1"}
	type tc struct {
		name, mid string
		opts      map[string]string
	}
	cases := []tc{
		{"Plain GRE", "gre", nil},
		{"BackPack L3 (Iran dials)", "bp_l3", nil},
		{"BackPack L3 (reverse: foreign dials)", "bp_l3", map[string]string{"dialer": "foreign"}},
		{"BackPack L3, port held on Iran (haproxy)", "bp_l3", nil},
		{"BackPack reverse, port held → redirect", "bp_reverse", nil},
		{"Backhaul, port held → redirect", "backhaul", nil},
		{"BackPack reverse", "bp_reverse", nil},
		{"Backhaul (reverse)", "backhaul", nil},
		{"FRP (reverse)", "frp", nil},
		{"Paqet-plus (raw TCP)", "paqet", nil},
	}
	if fam == "v6" {
		cases = append(cases, tc{"Direct v6 (ip6gre)", "direct6", nil},
			tc{"Direct v6 carrier udp, GRE dropped", "direct6", map[string]string{"carrier": "udp"}})
	} else {
		cases = append(cases, tc{"Golden-GRE (dns)", "golden", nil},
			tc{"FRP, target host 10.99.0.2", "frp", nil})
	}
	if os.Getenv("TP_E2E_PREMIUM") != "" && fam == "v4" {
		// the Premium core refuses to run without a public address: public-looking ones
		sh(t, "ip -n tir addr add 198.51.100.1/24 dev vir; ip -n tkh addr add 198.51.100.2/24 dev vkh")
		ir.IPv4, kh.IPv4 = "198.51.100.1", "198.51.100.2"
		// these modes need the core's online license, which a VM without internet can't get
		// (the tunnel comes up, users' connections are closed): only with TP_E2E_LICENSED
		if os.Getenv("TP_E2E_LICENSED") != "" {
			for _, mode := range []string{"tcp", "tcpmux", "wssmux", "anytls"} {
				cases = append(cases, tc{"Backhaul Premium " + mode, "premium", map[string]string{"mode": mode}})
			}
		}
		for _, prof := range []string{"tcp", "gre", "icmp", "ipip", "bip", "udp"} {
			cases = append(cases, tc{"Backhaul Premium ipx/" + prof, "premium", map[string]string{"mode": "ipx", "profile": prof}})
		}
		for _, tr := range []string{"tcp", "tcpmux", "wssmux"} {
			cases = append(cases, tc{"Backhaul Premium v1 " + tr, "premium1", map[string]string{"transport": tr}})
		}
	}
	if one := os.Getenv("TP_E2E_CASE"); one != "" { // just this case (by its exact name)
		var keep []tc
		for _, c := range cases {
			if c.name == one {
				keep = append(keep, c)
			}
		}
		cases = keep
	}
	if only := os.Getenv("TP_E2E_ONLY"); only != "" {
		var keep []tc
		for _, c := range cases {
			if strings.Contains(only, c.mid) {
				keep = append(keep, c)
			}
		}
		cases = keep
	}
	var report []string
	for i, c := range cases {
		m := methodByID[c.mid]
		tn := &Tunnel{ID: fmt.Sprintf("e2e%d", i), Name: c.name, ServerID: "ir", ForeignID: "kh", Family: fam,
			Ports: map[bool]string{false: "28579", true: "28579=10.99.0.2:28579"}[strings.Contains(c.name, "target host")], Index: 20 + i, Options: map[string]map[string]string{}, Secrets: map[string]string{}}
		if c.opts != nil {
			tn.Options[c.mid] = c.opts
		}
		var redir map[int]int
		if strings.Contains(c.name, "→ redirect") { // what Apply does when another program holds the port
			redir = map[int]int{28579: 50000 + tn.Index*20}
		}
		irP, khP, err := buildPlansRedirect(m, tn, ir, kh, set, redir)
		if err != nil {
			report = append(report, fmt.Sprintf("%-38s BUILD ERROR %v", c.name, err))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		j := &Job{Status: "running"}
		base := t.TempDir()
		sk := &e2eSide{ns: "tkh", label: "KH", dir: base + "/kh", h: nsHost{"tkh"}, plan: khP}
		si := &e2eSide{ns: "tir", label: "IR", dir: base + "/ir", h: nsHost{"tir"}, plan: irP}
		res := ""
		// "GRE dropped": the path drops protocol 47, as many providers do
		block47 := strings.Contains(c.name, "GRE dropped")
		// "port held": another program already listens on the users' port on Iran
		if strings.Contains(c.name, "port held") {
			sh(t, "mkdir -p /tmp/tp-e2e-empty; ip netns exec tir setsid python3 -m http.server 28579 --bind 0.0.0.0 -d /tmp/tp-e2e-empty >/dev/null 2>&1 & sleep 1")
		}
		if block47 {
			sh(t, "for n in tir tkh; do ip netns exec $n ip6tables -w -t raw -I PREROUTING -p 47 -j DROP; ip netns exec $n iptables -w -t raw -I PREROUTING -p 47 -j DROP; done")
		}
		if err := sk.up(ctx, t, j, tn); err != nil {
			res = "FOREIGN DEPLOY FAILED: " + err.Error()
		} else if err := si.up(ctx, t, j, tn); err != nil {
			res = "IRAN DEPLOY FAILED: " + err.Error()
		}
		if res == "" {
			// users (IPv4) → Iran:28579 → tunnel → foreign service
			var got string
			if !benchIsL3(m, tn.Options[c.mid]) {
				sh(t, "ip netns exec tir bash -c "+shq(acctScript(tn))) // counters start now, as on a panel page
			}
			for k := 0; k < 12; k++ {
				got = sh(t, "ip netns exec tus curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 8 http://10.98.0.1:28579/blob.bin")
				if strings.HasPrefix(got, "200 2097152") {
					break
				}
				time.Sleep(2 * time.Second)
			}
			if strings.HasPrefix(got, "200 2097152") {
				res = "✓ user traffic passes (2 MB over HTTP from an IPv4 client)"
				if !benchIsL3(m, tn.Options[c.mid]) {
					// the panel's traffic counters must see it (also when the port is redirected)
					f := strings.Fields(sh(t, "ip netns exec tir bash -c "+shq(acctScript(tn))+" 2>/dev/null | tail -1"))
					if d := 0; len(f) == 4 {
						d, _ = strconv.Atoi(f[2])
						if d >= 2000000 {
							res += fmt.Sprintf("; counted ↓%d KB", d/1024)
						} else {
							res += "; traffic counters FAIL (" + strings.Join(f, " ") + ")"
						}
					}
				}
			} else {
				res = "✕ user traffic FAILS (" + got + ")"
				res += " | IR: " + sh(t, "tail -2 "+si.dir+"/daemon.log 2>/dev/null") + " | KH: " + sh(t, "tail -2 "+sk.dir+"/daemon.log 2>/dev/null")
				if os.Getenv("TP_E2E_DEBUG") != "" {
					t.Logf("DEBUG %s:\n--- curl -v from the user\n%s\n--- Iran listeners\n%s\n--- Iran INPUT\n%s\n--- Iran conns\n%s\n--- foreign conns\n%s\n--- Iran log\n%s\n--- foreign log\n%s\n--- foreign: the service itself\n%s", c.name,
						sh(t, "ip netns exec tus curl -sv -o /dev/null --max-time 6 http://10.98.0.1:28579/blob.bin 2>&1 | tail -8"),
						sh(t, "ip netns exec tir ss -ltnp 2>/dev/null | grep -E '28579|400[0-9][0-9]'"),
						sh(t, "ip netns exec tir iptables -w -S INPUT; ip netns exec tir iptables -w -nvL "+inboundChain(tn)+" 2>&1 | head -12"),
						sh(t, "ip netns exec tir ss -tnp 2>/dev/null | head -20"),
						sh(t, "ip netns exec tkh ss -tnp 2>/dev/null | head -20"),
						sh(t, "grep -v -i 'tuning\\|sysctl\\|rmem\\|wmem\\|RLIMIT' "+si.dir+"/daemon.log 2>/dev/null | tail -25"),
						sh(t, "grep -v -i 'tuning\\|sysctl\\|rmem\\|wmem\\|RLIMIT' "+sk.dir+"/daemon.log 2>/dev/null | tail -25"),
						sh(t, "ip netns exec tkh curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 5 http://127.0.0.1:28579/blob.bin; echo; ip netns exec tkh curl -s -o /dev/null -w '%{http_code}' --max-time 5 'http://[::1]:28579/blob.bin'"))
				}
			}
			if benchIsL3(m, tn.Options[c.mid]) {
				d := deriveFor(tn, ir, kh, set)
				if sh(t, fmt.Sprintf("ip netns exec tir timeout 5 bash -c '</dev/tcp/%s/28579' && echo open", d.KHv4)) == "open" {
					res += "; inner link " + d.KHv4 + " ok"
				} else {
					res += "; inner link " + d.KHv4 + " FAILS"
				}
			}
			if fam == "v6" {
				// the underlay really is v6: the daemons' sockets / tunnel endpoints
				res += "; underlay: " + strings.ReplaceAll(sh(t, "ip netns exec tir ss -Htn state established 2>/dev/null | awk '{print $4}' | grep -c 2001:db8:99"), "\n", "") + " v6 TCP conns"
			}
		}
		si.down(ctx, tn)
		sk.down(ctx, tn)
		if block47 {
			sh(t, "for n in tir tkh; do ip netns exec $n ip6tables -w -t raw -D PREROUTING -p 47 -j DROP; ip netns exec $n iptables -w -t raw -D PREROUTING -p 47 -j DROP; done")
		}
		if strings.Contains(c.name, "port held") {
			sh(t, "pkill -f 'tp-e2e-empty'") // the stand-in for haproxy, only for its own case
		}
		sh(t, "ip netns exec tir bash -c "+shq(acctDown(tn)))
		left := sh(t, "for n in tir tkh; do ip netns exec $n iptables-save 2>/dev/null; ip netns exec $n ip6tables-save 2>/dev/null; done | grep -cE 'TPI_|TPF_|TPM_|TP_tp|tpr-' ")
		if left != "0" {
			res += "; LEFTOVER firewall rules: " + left
		}
		cancel()
		report = append(report, fmt.Sprintf("%-38s %s", c.name, res))
	}
	t.Log("\n==== E2E " + fam + " ====\n" + strings.Join(report, "\n"))
	for _, r := range report {
		if !strings.Contains(r, "✓") || strings.Contains(r, "FAIL") || strings.Contains(r, "LEFTOVER") {
			t.Error("failed: " + r)
		}
	}
}

// The IPv6 fixes on a real kernel: the RA repair, and a clear error for an IPv6 address
// the server doesn't have. Runs with TP_E2E=v6.
func TestIPv6HostFixesNS(t *testing.T) {
	if os.Getenv("TP_E2E") != "v6" {
		t.Skip("set TP_E2E=v6 (root, network namespaces)")
	}
	e2eTopology(t, "v6")
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")
	ctx := context.Background()
	h := nsHost{"tir"}
	sh(t, "ip netns exec tir sysctl -qw net.ipv6.conf.all.forwarding=1; ip netns exec tir sysctl -qw net.ipv6.conf.vir.accept_ra=1")
	_, _ = h.Run(ctx, ipv6RAFix, nil)
	if got := sh(t, "ip netns exec tir cat /proc/sys/net/ipv6/conf/vir/accept_ra"); got != "2" {
		t.Errorf("forwarding on: accept_ra on the uplink is %s, want 2", got)
	} else {
		t.Log("✓ forwarding on → uplink accept_ra=2 (keeps taking router advertisements)")
	}
	out, err := h.Run(ctx, localAddr("2001:db8:99::77", "2001:db8:99::2")+"echo TPL=$TPL", nil)
	if err == nil || !strings.Contains(out, "is not on this server") || !strings.Contains(out, "2001:db8:99::1") {
		t.Errorf("wrong IPv6 not reported: err=%v out=%q", err, out)
	} else {
		t.Log("✓ wrong IPv6: " + strings.TrimSpace(out))
	}
	out, err = h.Run(ctx, localAddr("2001:db8:99::1", "2001:db8:99::2")+"echo TPL=$TPL", nil)
	if err != nil || !strings.Contains(out, "TPL=2001:db8:99::1") {
		t.Errorf("right IPv6 rejected: err=%v out=%q", err, out)
	}
}
