package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPeerIPsSpoof: a Spoof-Tunnel's foreign side sends from its forged address, so that
// address is counted for the pair too (else its route looked measured at ~0 bytes).
func TestPeerIPsSpoof(t *testing.T) {
	f := &Server{ID: "de", IPv4: "203.0.113.5", IPv6: "2001:db8::5"}
	sp := &Tunnel{Active: "spoof", ForeignID: "de",
		Options: map[string]map[string]string{"spoof": {"spoof_ip": "192.0.2.9", "peer_spoof_ip": " 198.51.100.7 "}}}
	got := strings.Join(peerIPs(sp, f, Settings{}), ",")
	if got != "203.0.113.5,2001:db8::5,198.51.100.7" {
		t.Fatalf("spoof peers %q", got)
	}
	// other methods (even with spoof options kept from before a switch): the server's only
	sp.Active = "backhaul"
	if got := strings.Join(peerIPs(sp, f, Settings{}), ","); got != "203.0.113.5,2001:db8::5" {
		t.Fatalf("backhaul peers %q", got)
	}
	// no foreign server: the panel host's addresses
	if got := strings.Join(peerIPs(&Tunnel{Active: "gre"}, nil, Settings{LocalIPv4: "192.0.2.1"}), ","); got != "192.0.2.1" {
		t.Fatalf("local peers %q", got)
	}
}

// TestUsagePartReset: one part of a summed counter restarting (one card, the ip6tables
// chain) counts that part only, not the others' whole lifetime again.
func TestUsagePartReset(t *testing.T) {
	const tb, gb = uint64(1) << 40, uint64(1) << 30
	now := time.Date(2026, 11, 1, 10, 1, 0, 0, tehran)
	u := &usageLog{Last: map[string]*usageLast{}}
	u.addPartsLocked(now, "s", "ir", "nic eth0+eth1", 10*tb+5*gb, 0, [][2]uint64{{10 * tb, 0}, {5 * gb, 0}})
	u.addPartsLocked(now.Add(time.Minute), "s", "ir", "nic eth0+eth1", 10*tb+gb+100, 0, [][2]uint64{{10*tb + 100, 0}, {gb, 0}})
	if x := u.Days[0].Servers["ir"]; x.Down != gb+100 {
		t.Fatalf("parts: booked %d, want %d (eth1 restarted at 1 GB, eth0 +100)", x.Down, gb+100)
	}
	// without parts (an older reading): the sum went down but is over half the old value,
	// so only the baseline moves
	u = &usageLog{Last: map[string]*usageLast{}}
	u.addSrcLocked(now, "s", "ir", "nic eth0+eth1", 10*tb+5*gb, 0)
	u.addSrcLocked(now.Add(time.Minute), "s", "ir", "nic eth0+eth1", 10*tb+gb, 0)
	u.addSrcLocked(now.Add(2*time.Minute), "s", "ir", "nic eth0+eth1", 10*tb+gb+500, 0)
	if x := u.Days[0].Servers["ir"]; x.Down != 500 {
		t.Fatalf("sum: booked %d, want 500", x.Down)
	}
	// a single counter's restart still counts its new value
	u = &usageLog{Last: map[string]*usageLast{}}
	u.addPartsLocked(now, "t", "x", "", 5000, 50, [][2]uint64{{5000, 50}})
	u.addPartsLocked(now.Add(time.Minute), "t", "x", "", 4000, 40, [][2]uint64{{4000, 40}})
	if x := u.Days[0].Tunnels["x"]; x.Down != 4000 || x.Up != 40 {
		t.Fatalf("restart: %+v", x)
	}
}

// TestTrafficParts: the scripts' per-part fields reach the stats.
func TestTrafficParts(t *testing.T) {
	a := &App{traffic: newTrafficMon()}
	a.trafficParse("ir", nil, "N 300 30 eth0+eth1 100/10+200/20\nT p1 7 3 ports 5/1+2/2\nT p2 9 9 ports\nT l3 4 4 iface tp3\nT hs 6 6\n")
	tm := a.traffic
	for _, c := range []struct {
		s    *TrafficStat
		want string
	}{{tm.servers["ir"], "[[100 10] [200 20]]"}, {tm.tunnels["p1"], "[[5 1] [2 2]]"}, {tm.tunnels["p2"], "[[9 9]]"},
		{tm.tunnels["l3"], "[[4 4]]"}, {tm.tunnels["hs"], "[[6 6]]"}} {
		if got := fmt.Sprint(c.s.parts); got != c.want {
			t.Errorf("%s parts %s, want %s", c.s.ID, got, c.want)
		}
	}
	if !strings.Contains(nicRead, `echo "N $R $X $L $P"`) {
		t.Fatal("nicRead does not list the cards' counters")
	}
}

// fakeIpt is a bash stand-in for iptables/ip6tables keeping each hook's jumps in a file;
// a counting chain always exists (as after a firewall reload that dropped only the jumps)
// and every rule in it shows $FAKE_BYTES.
const fakeIpt = `fake() {
  st=$1.state; shift; touch "$st"
  a=(); while [ $# -gt 0 ]; do case "$1" in -w) ;; -t) shift ;; *) a+=("$1") ;; esac; shift; done
  set -- "${a[@]}"
  case "$1" in
    -S) case "$2" in INPUT|OUTPUT|PREROUTING|POSTROUTING) grep -- "^-A $2 " "$st"; return 0 ;; esac
        echo "-A $2 -p tcp -m conntrack --ctdir ORIGINAL --ctorigdstport 1" ;;
    -D) grep -qxF -- "-A $2 $3 $4" "$st" || return 1
        awk -v l="-A $2 $3 $4" 'f || $0 != l {print; next} {f=1}' "$st" > "$st.t"; mv "$st.t" "$st" ;;
    -I) echo "-A $2 $3 $4" >> "$st" ;;
    -nvxL) echo "Chain $2"; echo " pkts bytes target"; echo " 1 $FAKE_BYTES all" ;;
  esac
  return 0
}
iptables() { fake ipt4 "$@"; }
ip6tables() { fake ipt6 "$@"; }
FAKE_BYTES=5000000000
`

func runFake(t *testing.T, dir, script string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	cmd := exec.Command(bash, "-c", fakeIpt+script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	return string(out)
}

func jumps(t *testing.T, dir, file string) string {
	b, _ := os.ReadFile(filepath.Join(dir, file))
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\r", ""))
}

// TestAcctJumpsRestored: a read puts back counting jumps a firewall reload removed (the
// chains survived, so they were never rebuilt and the counters froze), and leaves exactly
// one when there were two. Counts over 2^31 come out whole.
func TestAcctJumpsRestored(t *testing.T) {
	tn := &Tunnel{ID: "x1", Ports: "443"}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "ipt6.state"), []byte("-A INPUT -j TPAI_x1\n-A INPUT -j TPAI_x1\n-A INPUT -j OTHER\n"), 0o600)
	out := runFake(t, dir, acctScript(tn))
	if !strings.Contains(out, "T x1 10000000000 10000000000 ports 5000000000/5000000000+5000000000/5000000000") {
		t.Fatalf("output %q", out)
	}
	if got := jumps(t, dir, "ipt4.state"); got != "-A INPUT -j TPAI_x1\n-A OUTPUT -j TPAO_x1" && got != "-A OUTPUT -j TPAO_x1\n-A INPUT -j TPAI_x1" {
		t.Fatalf("iptables jumps:\n%s", got)
	}
	if got := jumps(t, dir, "ipt6.state"); strings.Count(got, "-A INPUT -j TPAI_x1") != 1 || !strings.Contains(got, "OTHER") || strings.Count(got, "TPAO_x1") != 1 {
		t.Fatalf("ip6tables jumps:\n%s", got)
	}
	// hot standby's mangle chains
	ht := &Tunnel{ID: "h1", Ports: "443"}
	out = runFake(t, dir, hsAcct(ht))
	if !strings.Contains(out, "T h1 5000000000 5000000000") {
		t.Fatalf("hs output %q", out)
	}
	if got := jumps(t, dir, "ipt4.state"); strings.Count(got, "-A PREROUTING -j TPHA_h1") != 1 || strings.Count(got, "-A POSTROUTING -j TPHB_h1") != 1 {
		t.Fatalf("mangle jumps:\n%s", got)
	}
	runFake(t, dir, hsAcct(ht)) // again: still one each
	if got := jumps(t, dir, "ipt4.state"); strings.Count(got, "TPHA_h1") != 1 || strings.Count(got, "TPHB_h1") != 1 {
		t.Fatalf("mangle jumps after a second read:\n%s", got)
	}
}

// TestUsagePaidIdleSplit: in an hour no tunnel downloaded, the pair's intake goes to the
// tunnels that have a row in it, not shared with ones that don't (their shares vanished).
func TestUsagePaidIdleSplit(t *testing.T) {
	pairs := map[string][2]string{"a": {"ir", "fr"}, "b": {"ir", "fr"}, "c": {"ir", "fr"}}
	b := &usageBucket{Tunnels: map[string]*UsageBytes{"a": {Up: 10}},
		Servers: map[string]*UsageBytes{"ir": {Down: 900}},
		Peers:   map[string]*UsageBytes{"ir|fr": {Down: 600}}}
	paid, _ := usagePaid(b, pairs)
	if paid["a"] != 610 || len(paid) != 1 {
		t.Fatalf("paid %v, want a=610 only", paid)
	}
	b.Peers = nil // before the peer counters: the card's intake, the same way
	paid, est := usagePaid(b, pairs)
	if paid["a"] != 900 || !est["a"] || len(paid) != 1 {
		t.Fatalf("estimated paid %v", paid)
	}
}

// TestUsageHourBoundary: a read whose interval crosses an hour (and Tehran's midnight) is
// split between the buckets by time.
func TestUsageHourBoundary(t *testing.T) {
	u := &usageLog{Last: map[string]*usageLast{}}
	t0 := time.Date(2026, 11, 1, 10, 58, 0, 0, tehran)
	u.addLocked(t0, "t", "x", 1000, 0)
	u.addLocked(t0.Add(5*time.Minute), "t", "x", 1500, 0) // 2 min in 10:00, 3 in 11:00
	if len(u.Buckets) != 2 || u.Buckets[0].Tunnels["x"].Down != 200 || u.Buckets[1].Tunnels["x"].Down != 300 {
		t.Fatalf("hours %+v %+v", u.Buckets[0].Tunnels["x"], u.Buckets[len(u.Buckets)-1].Tunnels["x"])
	}
	// another counter read in the same round books 10:00 after 11:00 exists: no duplicate
	u.addLocked(t0.Add(-8*time.Minute), "t", "y", 0, 0)
	u.addLocked(t0.Add(2*time.Minute), "t", "y", 0, 1000) // 10:50 -> 11:00, all in 10:00
	u.addLocked(t0.Add(5*time.Minute), "t", "y", 0, 1300) // 11:00 -> 11:03
	if len(u.Buckets) != 2 || u.Buckets[0].Tunnels["y"].Up != 1000 || u.Buckets[1].Tunnels["y"].Up != 300 {
		t.Fatalf("y over %d buckets", len(u.Buckets))
	}
	// Tehran midnight
	d := &usageLog{Last: map[string]*usageLast{}}
	m := time.Date(2026, 11, 1, 23, 56, 0, 0, tehran)
	d.addLocked(m, "s", "ir", 0, 0)
	d.addLocked(m.Add(10*time.Minute), "s", "ir", 1000, 100)
	if len(d.Days) != 2 || d.Days[0].Servers["ir"].Down != 400 || d.Days[1].Servers["ir"].Down != 600 ||
		d.Days[0].Servers["ir"].Up+d.Days[1].Servers["ir"].Up != 100 {
		t.Fatalf("days %+v", d.Days)
	}
	if d.Days[0].Hour != dayStart(m) || d.Days[1].Hour != dayStart(m.Add(time.Hour)) {
		t.Fatal("day buckets not at Tehran midnights")
	}
	// a restarted counter is not split: its bytes are from after the restart
	d.addLocked(m.Add(70*time.Minute), "s", "ir", 50, 5)
	if x := d.Days[1].Servers["ir"]; x.Down != 650 {
		t.Fatalf("after restart %+v", x)
	}
}

func TestBucketInOrder(t *testing.T) {
	var l []*usageBucket
	b11 := bucketIn(&l, 11, 5)
	b10 := bucketIn(&l, 10, 5)
	b12 := bucketIn(&l, 12, 5)
	if len(l) != 3 || l[0] != b10 || l[1] != b11 || l[2] != b12 || bucketIn(&l, 10, 5) != b10 || bucketIn(&l, 11, 5) != b11 {
		t.Fatalf("order %v %v %v", l[0].Hour, l[1].Hour, l[2].Hour)
	}
}

// TestWithProbePortRange: a range the user gave that covers the probe port already
// forwards it; adding it again made the forwarder listen twice.
func TestWithProbePortRange(t *testing.T) {
	m := methodByID["backhaul"]
	tn := &Tunnel{Index: 2, Options: map[string]map[string]string{}} // probe 40010
	for ports, want := range map[string]string{
		"40000-40020":       "40000-40020",
		"443,40005-40015=1": "443,40005-40015=1",
		"1.2.3.4:40010":     "1.2.3.4:40010",
		"[::]:40010":        "[::]:40010",
		"40011-40020":       "40011-40020,40010",
		"443":               "443,40010",
	} {
		tn.Ports = ports
		if got := withProbePort(m, tn); got != want {
			t.Errorf("%q: got %q, want %q", ports, got, want)
		}
	}
}
