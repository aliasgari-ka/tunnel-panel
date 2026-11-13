package pktfilter

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Main runs "pktfilter" and returns the exit code. It narrows every packet socket of the
// core (-pid, and with -unit every process of that systemd unit: a wrapper that doesn't exec
// keeps the core as its child) whose filter is the vendor's for this spec, waiting up to
// -wait for the core to attach it; with -watch it then keeps looking (every -every) while
// the core runs, for a socket the core opens again after a reconnect.
func Main(args []string) int {
	fs := flag.NewFlagSet("pktfilter", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "the core's process id")
	unit := fs.String("unit", "", "the core's systemd unit (its cgroup's processes are looked at too)")
	peer := fs.String("peer", "", "the peer server's public IPv4")
	proto := fs.Uint("proto", 6, "IP protocol of the carrier")
	sport := fs.Uint("sport", 443, "carrier source port (packets from the peer)")
	dport := fs.Uint("dport", 443, "carrier destination port (packets from the peer)")
	wait := fs.Duration("wait", 3*time.Minute, "how long to wait for the core's own filter")
	watch := fs.Bool("watch", false, "keep watching while the core runs")
	every := fs.Duration("every", time.Minute, "how often -watch looks again")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ip := net.ParseIP(*peer)
	if (*pid <= 0 && *unit == "") || ip == nil || ip.To4() == nil || *proto > 255 || *sport == 0 || *sport > 65535 || *dport == 0 || *dport > 65535 {
		fmt.Fprintln(os.Stderr, "pktfilter: -pid or -unit, and an IPv4 -peer, are needed")
		return 2
	}
	s := Spec{Peer: ip, Proto: uint8(*proto), SPort: uint16(*sport), DPort: uint16(*dport)}
	end := time.Now().Add(*wait)
	done := false
	for {
		pids := targets(*pid, *unit)
		if len(pids) == 0 {
			return 0 // the core is gone
		}
		total, left := 0, 0
		var last error
		for _, p := range pids {
			n, w, err := Apply(p, s)
			total, left = total+n, left+w
			if err != nil {
				last = err
			}
		}
		if last != nil {
			fmt.Fprintln(os.Stderr, "pktfilter:", last)
		}
		if total > 0 {
			fmt.Printf("pktfilter: narrowed %d packet socket(s) to %v proto %d ports %d->%d\n", total, s.Peer, s.Proto, s.SPort, s.DPort)
			done = true
		} else if !done && time.Now().After(end) {
			fmt.Printf("pktfilter: no packet socket with the core's filter found (%d still without one) — nothing changed\n", left)
			done = true
		}
		if done && !*watch {
			return 0
		}
		if done {
			time.Sleep(*every)
		} else {
			time.Sleep(2 * time.Second)
		}
	}
}

// targets are the live processes to look at: pid, and the processes of unit's cgroup
// (cgroup v2), without this one.
func targets(pid int, unit string) []int {
	seen := map[int]bool{os.Getpid(): true}
	var out []int
	add := func(p int) {
		if p > 0 && !seen[p] {
			if _, err := os.Stat("/proc/" + strconv.Itoa(p)); err == nil {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	add(pid)
	if unit != "" && !strings.ContainsAny(unit, "/\x00") {
		if b, err := os.ReadFile("/sys/fs/cgroup/system.slice/" + unit + "/cgroup.procs"); err == nil {
			for _, f := range strings.Fields(string(b)) {
				if p, err := strconv.Atoi(f); err == nil {
					add(p)
				}
			}
		}
	}
	return out
}
