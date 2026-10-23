package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Hot standby: a tunnel keeps every compatible method (both address families when the
// route has them) running at once, each as its own path with its own index (interface,
// subnet, ports). Users' ports on Iran go through one selector chain (TP_S<id>): kernel
// DNAT into the active L3 path, or REDIRECT to the internal port an active forwarder
// listens on. A switcher on the Iran server itself (no SSH, no panel needed) checks every
// path end to end every few seconds against a probe server on the foreign side, moves the
// users to the best working path within seconds when the active one fails, and back to a
// better one once it has been stable for hsFailback. The panel only reads its state.

const (
	hsEvery    = 2  // seconds between checks on the Iran server
	hsFails    = 3  // failed checks in a row before the active path is abandoned (one lost check is no outage)
	hsFailback = 60 // seconds a better path must work before the users move back
)

// hsOnly limits the methods hot standby uses (tests).
var hsOnly []string

// HSPath is one always-on path of a hot-standby tunnel.
type HSPath struct {
	Method string            `json:"method"`
	Family string            `json:"family"`
	Index  int               `json:"index"`
	Opts   map[string]string `json:"opts,omitempty"`   // its own options (a tunnel port the preflight moved…)
	Failed string            `json:"failed,omitempty"` // why it couldn't be deployed on the last apply
}

func (p HSPath) label() string { return methodTitle(p.Method) + " (" + p.Family + ")" }

// hsProbePort is where the foreign side's permanent probe server listens for the checks.
func hsProbePort(t *Tunnel) int { return 49000 + t.Index }

func hsTag(t *Tunnel) string { return "S" + t.ID }

func hsDir(t *Tunnel) string { return tunnelDir(t) + "hs" }

// hsInternal is the internal Iran port a forwarder path listens on for the j-th users'
// port (j = 19: the probe port the switcher checks it through).
func hsInternal(p HSPath, j int) int { return 50000 + p.Index*20 + j }

// pathTunnel is the pseudo tunnel a path is built and deployed as.
func pathTunnel(t *Tunnel, p HSPath) *Tunnel {
	opts := map[string]map[string]string{}
	for k, v := range t.Options {
		cp := map[string]string{}
		for a, b := range v {
			cp[a] = b
		}
		opts[k] = cp
	}
	if len(p.Opts) > 0 {
		if opts[p.Method] == nil {
			opts[p.Method] = map[string]string{}
		}
		for a, b := range p.Opts {
			opts[p.Method][a] = b
		}
	}
	pt := &Tunnel{ID: t.ID + "x" + strconv.Itoa(p.Index), Name: t.Name + " · " + p.label(), ServerID: t.ServerID, ForeignID: t.ForeignID,
		Family: p.Family, Index: p.Index, Options: opts, Secrets: t.Secrets, Active: p.Method}
	m := methodByID[p.Method]
	if m != nil && !benchIsL3(m, opts[m.ID]) {
		var specs []string
		for j, s := range splitPorts(t.Ports) {
			specs = append(specs, fmt.Sprintf("%d=%s", hsInternal(p, j), s.dst))
		}
		specs = append(specs, fmt.Sprintf("%d=127.0.0.1:%d", hsInternal(p, 19), hsProbePort(t)))
		pt.Ports = strings.Join(specs, ",")
	}
	return pt
}

// hsUsable: hot standby forwards single ports or small ranges per path.
func hsForwarderOK(t *Tunnel) bool {
	ps := splitPorts(t.Ports)
	if len(ps) == 0 || len(ps) > 18 {
		return false
	}
	for _, p := range ps {
		if _, err := strconv.Atoi(p.listen); err != nil {
			return false
		}
	}
	return true
}

// hsCandidate: m over f can be a standby path of t (the user didn't leave it out on this route).
func (a *App) hsCandidate(t *Tunnel, m *Method, f string) bool {
	if !supportsFamily(m, f) || m.ID == "spoof" || (hsOnly != nil && !contains(hsOnly, m.ID)) || a.routeSkipped(t.ServerID, t.ForeignID, m.ID, f) {
		return false
	}
	return benchIsL3(m, t.Options[m.ID]) || hsForwarderOK(t)
}

// hsPlan lists the paths: the chosen method first, then every compatible method over every
// family the route has, best benchmark score first. Indices of existing paths are kept.
func (a *App) hsPlan(t *Tunnel, mid, fam string) []HSPath {
	have := map[string]HSPath{}
	for _, p := range t.Paths {
		have[p.Method+"|"+p.Family] = p
	}
	score := map[string]float64{}
	for _, f := range a.routeFamilies(t) {
		for _, r := range a.benchResults(t.ServerID, t.ForeignID, f) {
			if r.OK {
				score[r.Method+"|"+f] = r.Score
			} else if r.Error != "" {
				score[r.Method+"|"+f] = -1 // failed on this route: keep, but last
			}
		}
	}
	type cand struct {
		p   HSPath
		s   float64
		pos int
	}
	var cs []cand
	pos := 0
	for _, f := range a.routeFamilies(t) {
		for _, m := range methods {
			pos++
			if (m.ID == mid && f == fam) || !a.hsCandidate(t, m, f) {
				continue
			}
			s, ok := score[m.ID+"|"+f]
			if !ok {
				s = -0.5
			}
			cs = append(cs, cand{HSPath{Method: m.ID, Family: f}, s, pos})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].s != cs[j].s {
			return cs[i].s > cs[j].s
		}
		return cs[i].pos < cs[j].pos
	})
	out := []HSPath{{Method: mid, Family: fam}}
	for _, c := range cs {
		out = append(out, c.p)
	}
	// indices: the primary path keeps the tunnel's own; others keep theirs or get a free one
	_ = a.store.Update(func(st *State) error {
		used := pendingIndices(st)
		for _, o := range st.Tunnels {
			used[o.Index] = true
			if o.ID != t.ID {
				for _, p := range o.Paths {
					used[p.Index] = true
				}
			}
		}
		for i := range out {
			if i == 0 {
				out[i].Index = t.Index
				continue
			}
			if p, ok := have[out[i].Method+"|"+out[i].Family]; ok && p.Index != 0 && p.Index != t.Index {
				out[i].Index, out[i].Opts = p.Index, p.Opts
				used[p.Index] = true
			}
		}
		for i := range out {
			if out[i].Index != 0 {
				continue
			}
			for n := 1; n < 250; n++ {
				if !used[n] {
					out[i].Index, used[n] = n, true
					break
				}
			}
		}
		var keep []HSPath
		for _, p := range out {
			if p.Index != 0 {
				keep = append(keep, p)
			}
		}
		t.Paths = keep
		return nil
	})
	// the carrier the benchmark found working on this route, where the default passes nothing
	// (outside the store lock: routeOpts reads the store); options already on a path stay
	ro := make([]map[string]string, len(t.Paths))
	for i, p := range t.Paths {
		ro[i] = a.routeOpts(t, p.Method, p.Family)
	}
	_ = a.store.Update(func(*State) error {
		for i := range t.Paths {
			if i >= len(ro) || len(ro[i]) == 0 {
				continue
			}
			opts := map[string]string{}
			for k, v := range ro[i] {
				opts[k] = v
			}
			for k, v := range t.Paths[i].Opts {
				opts[k] = v
			}
			t.Paths[i].Opts = opts
		}
		return nil
	})
	return t.Paths
}

// hsSelectUp makes path p the one new users' connections go to: the selector chain
// (TP_S<id> in nat PREROUTING) is replaced in one iptables-restore transaction, so there is
// no moment without a rule, and only new connections are affected (NAT is decided once per
// connection). Old iptables without restore fall back to flush + add.
func hsSelectUp(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) string {
	rules := hsSelectRules(t, p, srv, fsrv, set)
	nat := "TP_" + hsTag(t)
	var fb strings.Builder
	fmt.Fprintf(&fb, "  iptables -w -t nat -N %[1]s 2>/dev/null || iptables -w -t nat -F %[1]s\n", nat)
	for _, r := range rules {
		fmt.Fprintf(&fb, "  iptables -w -t nat %s\n", r)
	}
	return fmt.Sprintf(`printf '%%s\n' '*nat' ':%[1]s - [0:0]' %[2]s 'COMMIT' > /tmp/.tp-sel-%[3]s
if ! iptables-restore -w -n /tmp/.tp-sel-%[3]s 2>/dev/null && ! iptables-restore -n /tmp/.tp-sel-%[3]s 2>/dev/null; then
%[4]sfi
rm -f /tmp/.tp-sel-%[3]s
iptables -w -t nat -C PREROUTING -j %[1]s 2>/dev/null || iptables -w -t nat -I PREROUTING -j %[1]s
`, nat, shqAll(rules), t.ID, fb.String())
}

func shqAll(rules []string) string {
	var q []string
	for _, r := range rules {
		q = append(q, shq(r))
	}
	return strings.Join(q, " ")
}

// hsSelectRules are the selector chain's rules for path p (iptables-restore syntax).
func hsSelectRules(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) []string {
	nat := "TP_" + hsTag(t)
	pt := pathTunnel(t, p)
	m := methodByID[p.Method]
	var out []string
	if m != nil && benchIsL3(m, pt.Options[m.ID]) {
		target := deriveFor(pt, srv, fsrv, set).KHv4
		for _, spec := range splitPorts(t.Ports) {
			dport := strings.ReplaceAll(spec.listen, "-", ":")
			dst := target
			if spec.dst != spec.listen {
				dst = target + ":" + spec.dst
			}
			for _, proto := range []string{"tcp", "udp"} {
				out = append(out, fmt.Sprintf("-A %s -m addrtype --dst-type LOCAL -p %s --dport %s -j DNAT --to-destination %s", nat, proto, dport, dst))
			}
		}
		return out
	}
	for j, sp := range splitPorts(t.Ports) {
		for _, proto := range []string{"tcp", "udp"} {
			out = append(out, fmt.Sprintf("-A %s -m addrtype --dst-type LOCAL -p %s --dport %s -j REDIRECT --to-ports %d", nat, proto, sp.listen, hsInternal(p, j)))
		}
	}
	return out
}

// hsBase is what every path needs whichever one is selected, kept for as long as the
// switcher runs: forwarding, NAT on the way out and MSS clamping on each L3 path's
// interface — so connections still on a path the users just left keep working.
func hsBase(t *Tunnel, paths []HSPath) string {
	tag := hsTag(t)
	nat, post, fwd, mss := "TP_"+tag, "TP_"+tag+"_P", "TPF_"+tag, "TPM_"+tag
	var b strings.Builder
	fmt.Fprintf(&b, "iptables -w -t nat -N %[1]s 2>/dev/null\n", nat)
	fmt.Fprintf(&b, "iptables -w -t nat -N %[1]s 2>/dev/null || iptables -w -t nat -F %[1]s\n", post)
	fmt.Fprintf(&b, "iptables -w -N %[1]s 2>/dev/null || iptables -w -F %[1]s\n", fwd)
	fmt.Fprintf(&b, "iptables -w -t mangle -N %[1]s 2>/dev/null || iptables -w -t mangle -F %[1]s\n", mss)
	for _, p := range paths {
		pt := pathTunnel(t, p)
		m := methodByID[p.Method]
		if m == nil {
			continue
		}
		if ifc := l3Iface(m, pt); ifc != "" {
			fmt.Fprintf(&b, "iptables -w -t nat -A %s -o %s -j MASQUERADE\n", post, ifc)
			fmt.Fprintf(&b, "iptables -w -A %[1]s -o %[2]s -j ACCEPT\niptables -w -A %[1]s -i %[2]s -j ACCEPT\n", fwd, ifc)
			fmt.Fprintf(&b, "iptables -w -t mangle -A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n", mss, ifc)
		}
	}
	fmt.Fprintf(&b, "iptables -w -t nat -C PREROUTING -j %[1]s 2>/dev/null || iptables -w -t nat -I PREROUTING -j %[1]s\n", nat)
	fmt.Fprintf(&b, "iptables -w -t nat -C POSTROUTING -j %[1]s 2>/dev/null || iptables -w -t nat -A POSTROUTING -j %[1]s\n", post)
	fmt.Fprintf(&b, "iptables -w -C FORWARD -j %[1]s 2>/dev/null || iptables -w -I FORWARD -j %[1]s\n", fwd)
	fmt.Fprintf(&b, "iptables -w -t mangle -C FORWARD -j %[1]s 2>/dev/null || iptables -w -t mangle -A FORWARD -j %[1]s\n", mss)
	return b.String()
}

// hsFlush clears the connections on path p (it died): for an L3 path the ones NATed to its
// far tunnel address, for a forwarder the ones REDIRECTed to its internal ports.
func hsFlush(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) string {
	var b strings.Builder
	pt := pathTunnel(t, p)
	if m := methodByID[p.Method]; m != nil && benchIsL3(m, pt.Options[m.ID]) {
		ip := deriveFor(pt, srv, fsrv, set).KHv4
		// forwarded connections: drop their NAT entries, so the next packet takes the new path
		// (where the far end answers it with a reset and the app reconnects). Without the
		// conntrack tool, reset them here on their next packet instead, for a while.
		fmt.Fprintf(&b, `if command -v conntrack >/dev/null 2>&1; then
  conntrack -D --reply-src %[1]s >/dev/null 2>&1
else
  r="-p tcp -m conntrack --ctstate ESTABLISHED --ctreplsrc %[1]s -m comment --comment %[2]s -j REJECT --reject-with tcp-reset"
  iptables -w -C FORWARD $r 2>/dev/null || iptables -w -I FORWARD $r
  (sleep 50; iptables -w -D FORWARD $r 2>/dev/null) >/dev/null 2>&1 &
fi
`, ip, hsFlushTag(t))
	} else {
		// users' connections end on this server, on the forwarder's own sockets: close them
		// now. An app waiting for a push (a chat app's open connection) sends nothing and would
		// otherwise sit on the dead path until its own keepalive gives up, a minute or more.
		var sp []string
		for j := range splitPorts(t.Ports) {
			sp = append(sp, fmt.Sprintf("sport = :%d", hsInternal(p, j)))
		}
		fmt.Fprintf(&b, "ss -K -t state established '( %s )' >/dev/null 2>&1 || true\n", strings.Join(sp, " or "))
		b.WriteString("if command -v conntrack >/dev/null 2>&1; then\n")
		for j := range splitPorts(t.Ports) {
			for _, proto := range []string{"tcp", "udp"} {
				fmt.Fprintf(&b, "  conntrack -D -p %s --reply-port-src %d >/dev/null 2>&1\n", proto, hsInternal(p, j))
			}
		}
		b.WriteString("fi\n")
	}
	b.WriteString("exit 0\n")
	return b.String()
}

func hsFlushTag(t *Tunnel) string { return "tp-hsflush-" + t.ID }

func hsSelectDown(t *Tunnel) string {
	return portForwardDownV4(hsTag(t)) + fmt.Sprintf("iptables -w -S FORWARD 2>/dev/null | grep -- '--comment %s ' | sed 's/^-A/-D/' | while read -r r; do iptables -w $r; done\ntrue\n", hsFlushTag(t))
}

// hsTarget is where the switcher checks path p end to end (through the tunnel).
func hsTarget(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) string {
	pt := pathTunnel(t, p)
	m := methodByID[p.Method]
	if m != nil && benchIsL3(m, pt.Options[m.ID]) {
		return fmt.Sprintf("%s:%d", deriveFor(pt, srv, fsrv, set).KHv4, hsProbePort(t))
	}
	return fmt.Sprintf("127.0.0.1:%d", hsInternal(p, 19))
}

// Auto mode (Tunnel.HSAuto, the "mode" file on the Iran server, so it can be switched
// without a re-apply): besides failing over, the switcher keeps each path's latency and
// packet loss (a few pings per check), measures the active path's download speed every two
// hours (hsSpeedMB, capped), and when the active path degrades — loss ≥ 5 %, speed down to
// half of its recent best or under 1 Mbit/s — or another path is clearly cheaper, it measures
// the active path and up to three stable candidates the same way and moves the users to a
// clearly better one (heavy loss ≥ 15 % loses to a clean path of at least 30 % of its speed or 20 Mbit/s, even if it measures faster). After a move it holds for hsHold; a comparison that changed nothing
// backs off (10 min, doubling to 2 h), so a bad hour costs little traffic. Standby paths
// are checked every hsStandby checks (the active one every check), for the same reason.
const (
	hsStandby  = 5    // standby paths are checked every this many checks (active: every check)
	hsSpeedMB  = 2    // one speed measurement (download, foreign → Iran)
	hsSpeedSec = 7200 // the active path's speed is measured this often (auto mode)
	hsHold     = 600  // seconds after an automatic move before the next one
	hsPlanMax  = 3    // planned moves (back to the chosen path, auto improvements) per hour
	hsLossBad  = 50   // ‰: active path loss that counts as degraded (5 %)
	hsSpeedMin = 1000 // kbit/s: active path speed that counts as degraded
)

// hsSwitcher is the switcher's loop (bash, on the Iran server); settings come from conf.
const hsSwitcher = `#!/bin/bash
# tp-switcher 4
# Hot-standby switcher (mode file: auto | manual). Checks every path end to end and keeps
# the users' ports on the best working one. Events go to events.log (epoch kind from to reason).
cd "$(dirname "$0")" || exit 1
. ./conf
mapfile -t TL < targets
for ((k=0; k<N; k++)); do read -r A[$k] H[$k] <<< "${TL[$k]}"; done
ev() { echo "$(date +%s) $*" >> events.log; tail -n 300 events.log > events.tmp && mv events.tmp events.log; }
tune() {
  # without the conntrack tool, connections on a path that died wait for their own timeout
  if [ -z "$ctwarn" ] && ! command -v conntrack >/dev/null 2>&1; then
    ctwarn=1; ev kernel - - "the conntrack tool is missing (apt install conntrack): after a switch, users of the dead path reconnect only when their app times out"
  fi
  # what the tunnels need from the kernel, kept in place while they run
  [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || sysctl -qw net.ipv4.ip_forward=1
  for f in /proc/sys/net/ipv4/conf/*/rp_filter; do [ "$(cat $f 2>/dev/null)" = 1 ] && echo 2 > $f 2>/dev/null; done
  [ "$(cat /proc/sys/net/ipv4/tcp_mtu_probing 2>/dev/null)" = 0 ] && sysctl -qw net.ipv4.tcp_mtu_probing=1
  # (reported only when the kernel took it; not retried where it refuses, e.g. in a container)
  if [ -r /proc/sys/net/netfilter/nf_conntrack_max ] && [ -z "$ctfixed" ]; then
    m=$(cat /proc/sys/net/netfilter/nf_conntrack_max); c=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0); want=0
    if [ "$m" -lt 262144 ]; then want=262144
    elif [ $((c * 10)) -gt $((m * 9)) ] && [ "$m" -lt 4194304 ]; then want=$((m * 2)); fi
    if [ $want -gt 0 ]; then
      sysctl -qw net.netfilter.nf_conntrack_max=$want 2>/dev/null
      if [ "$(cat /proc/sys/net/netfilter/nf_conntrack_max)" = $want ]; then ev kernel - - "nf_conntrack_max $m → $want (table ${c}/${m})"; else ctfixed=1; fi
    fi
  fi
}
use() { # use <k> <reason>: make-before-break — one atomic swap of the selector; only new
  # connections take the new path, the ones already open finish on the old one (it keeps
  # running). A dead path's own connections are cleared (flush), so clients reconnect at once.
  bash up-$1.sh >/dev/null 2>&1
  local old=$active
  ev switch "$active" "$1" "$2"; active=$1; echo "$1 $(date +%s)" > active
  [ "$old" -ge 0 ] && [ "${ok[$old]}" != 1 ] && flush $old
}
flush() { bash flush-$1.sh >/dev/null 2>&1; flushed[$1]=1; }
cost() { echo $(( ${qr[$1]:-999} + ${ql[$1]:-0} * 5 / 2 )); } # ms, 1 % loss ≈ 25 ms
mb() { printf '%d.%d' $(($1 / 1000)) $((($1 % 1000) / 100)); }
pc() { printf '%d.%d' $((${1:-0} / 10)) $((${1:-0} % 10)); }
# a path that keeps dropping must stay up longer before users go (back) to it: BACK, doubled
# for every drop in the last 30 min (at most 30 min)
drops() { local t c=0 keep=""; for t in ${dropat[$1]}; do [ $((now - t)) -lt 1800 ] && { keep="$keep $t"; c=$((c + 1)); }; done; dropat[$1]=$keep; echo $c; }
need() { local c=$(drops $1) w=$BACK; while [ $c -gt 1 ] && [ $w -lt 1800 ]; do w=$((w * 2)); c=$((c - 1)); done; [ $w -gt 1800 ] && w=1800; echo $w; }
stable() { [ "${ok[$1]}" = 1 ] && [ $((now - ${since[$1]:-$now})) -ge $(need $1) ]; }
# planned moves (back to the chosen path, auto improvements) at most PLANMAX an hour; a
# failure is always handled
budget() { local t c=0 keep=""; for t in $planat; do [ $((now - t)) -lt 3600 ] && { keep="$keep $t"; c=$((c + 1)); }; done; planat=$keep; [ $c -lt $PLANMAX ]; }
planned() { planat="$planat $now"; use "$@"; }
backmsg() { local c=$(drops $1); echo "path $1 worked for $(need $1)s$([ $c -gt 0 ] && echo " (it dropped ${c}× in the last 30 min)")"; }
measure() { # measure <kind> <from> <why> <k...>: speed tests in the background
  local kind=$1 from=$2 why=$3; shift 3
  echo "$kind $from $why" > cmp.run; rm -f cmp.done
  ( for k in "$@"; do s=$(timeout 20 $P probe speed -addr ${A[$k]} -max $SPMB -secs 10 2>/dev/null); echo "$k ${s:-0}"; done > cmp.tmp; mv cmp.tmp cmp.done ) &
}
declare -a ok since fails qr ql sp spb spat flushed dropat
active=-1
rm -f cmp.run cmp.done cmp.tmp
bash base.sh >/dev/null 2>&1
if [ -f active ]; then read -r a _ < active; [ -n "$a" ] && [ "$a" -lt $N ] && { bash up-$a.sh >/dev/null 2>&1; active=$a; }; fi
[ $active -ge 0 ] || use 0 "start"
tune; n=0; cmpat=0; backoff=600; hold=0; badsince=0; cmploss=0
while true; do
  M=manual; [ -s mode ] && read -r M < mode
  P0=0; [ -s pin ] && read -r P0 < pin; [ -n "$P0" ] && [ "$P0" -ge 0 ] 2>/dev/null && [ "$P0" -lt $N ] || P0=0
  all=0; [ "${fails[$active]:-0}" -gt 0 ] && all=1
  pids=()
  for ((k=0; k<N; k++)); do
    rm -f c$k
    if [ $k = $active ] || [ $all = 1 ] || [ $((n % SBY)) = 0 ]; then
      pa=""
      if [ "$M" = auto ] && [ -n "${H[$k]}" ] && { { [ $k = $active ] && [ $((n % 5)) = 0 ]; } || [ $((n % (SBY * 3))) = 0 ]; }; then pa="-ping ${H[$k]} -pn 6"; fi
      # 3 s per check (5 with pings): a dead path must not hold the whole round up
      to=3; [ -n "$pa" ] && to=5
      ( r=$(timeout $to $P probe check -addr ${A[$k]} -n 2 $pa 2>/dev/null); echo "${r:-down}" > c$k ) &
      pids+=($!)
    fi
  done
  wait "${pids[@]}"
  now=$(date +%s); : > status.tmp
  for ((k=0; k<N; k++)); do
    if [ -f c$k ]; then
      read -r r rt jt ls < c$k
      if [ "$r" = ok ]; then
        [ "${ok[$k]}" = 1 ] || since[$k]=$now; ok[$k]=1; fails[$k]=0; flushed[$k]=0
        if [ -z "${qr[$k]}" ]; then qr[$k]=$rt; else qr[$k]=$(( (3 * qr[$k] + rt) / 4 )); fi
        if [ "${ls:--1}" -ge 0 ]; then if [ -z "${ql[$k]}" ]; then ql[$k]=$((ls * 10)); else ql[$k]=$(( (ql[$k] + ls * 10) / 2 )); fi; fi
      else
        [ "${ok[$k]}" = 0 ] || since[$k]=$now; ok[$k]=0; fails[$k]=$(( ${fails[$k]:-0} + 1 ))
        [ ${fails[$k]} = $FAILS ] && dropat[$k]="${dropat[$k]} $now"
        # connections still draining on a path that just died: clear them, so they reconnect
        [ $k != $active ] && [ ${fails[$k]} -ge $FAILS ] && [ "${flushed[$k]}" != 1 ] && flush $k
      fi
    fi
    st=down; [ "${ok[$k]}" = 1 ] && st=ok
    echo "$k $st ${since[$k]:-$now} ${qr[$k]:--} ${ql[$k]:--} ${sp[$k]:--}" >> status.tmp
  done
  mv status.tmp status
  if [ "$P0" != "${lastpin:-$P0}" ] && [ "$P0" != "$active" ] && [ "${ok[$P0]}" = 1 ]; then
    use $P0 "chosen in the panel"
  elif [ "${ok[$active]}" != 1 ] && [ "${fails[$active]:-0}" -ge $FAILS ]; then
    best=-1
    for ((k=0; k<N; k++)); do
      [ "${ok[$k]}" = 1 ] || continue
      if [ $best -lt 0 ]; then best=$k; [ "$M" = auto ] || break
      elif [ $(cost $k) -lt $(cost $best) ]; then best=$k; fi
    done
    [ $best -ge 0 ] && use $best "path $active failed $FAILS checks in a row"
  elif [ "${ok[$active]}" = 1 ] && [ "$M" != auto ]; then
    # manual: back to the chosen path (the pinned one, else the first) once it is stable
    if [ $active != $P0 ] && stable $P0 && budget; then planned $P0 "$(backmsg $P0)"
    elif [ "${ok[$P0]}" != 1 ]; then
      for ((k=0; k<active; k++)); do
        [ $k != $P0 ] && stable $k && budget && { planned $k "$(backmsg $k)"; break; }
      done
    fi
  elif [ "${ok[$active]}" = 1 ] && [ -f cmp.done ]; then
    read -r kind from why < cmp.run; rm -f cmp.run
    while read -r k s; do
      [ -n "$k" ] || continue; sp[$k]=$s; spat[$k]=$now
      if [ "${s:-0}" -gt 0 ]; then
        if [ -z "${spb[$k]}" ] || [ $s -gt $((spb[$k] * 15 / 16)) ]; then spb[$k]=$s; else spb[$k]=$((spb[$k] * 15 / 16)); fi
      fi
    done < cmp.done
    if [ "$kind" = cmp ] && [ "$from" = "$active" ]; then
      a=$active; sa=${sp[$a]:-0}; best=-1; bs=0
      while read -r c _; do
        [ "$c" != "$a" ] && [ "${ok[$c]}" = 1 ] || continue
        sc=${sp[$c]:-0}; [ $sc -gt 0 ] || continue
        win=0
        if [ $sa = 0 ]; then win=1
        elif [ $((sc * 10)) -ge $((sa * 15)) ] && [ ${ql[$c]:-0} -le $(( ${ql[$a]:-0} + 20 )) ]; then win=1
        elif [ ${ql[$a]:-0} -ge $LOSSBAD ] && [ $(( ${ql[$c]:-0} * 2 )) -le ${ql[$a]:-0} ] && [ $((sc * 10)) -ge $((sa * 8)) ]; then win=1
        elif [ ${ql[$a]:-0} -ge $((LOSSBAD * 3)) ] && [ ${ql[$c]:-0} -le 20 ] && { [ $((sc * 10)) -ge $((sa * 3)) ] || [ $sc -ge 20000 ]; }; then win=1 # heavy loss breaks uploads and handshakes even where the download test still looks fast
        elif [ $(( $(cost $c) * 10 )) -le $(( $(cost $a) * 7 )) ] && [ $((sc * 10)) -ge $((sa * 9)) ]; then win=1
        elif [ $c = $P0 ] && [ $(( $(cost $c) * 10 )) -le $(( $(cost $a) * 11 )) ] && [ $((sc * 10)) -ge $((sa * 9)) ]; then win=1
        fi
        [ $win = 1 ] && [ $sc -gt $bs ] && { best=$c; bs=$sc; }
      done < cmp.done
      if [ $best -ge 0 ] && budget; then
        planned $best "auto: $(mb $bs) vs $(mb $sa) Mbit/s, loss $(pc ${ql[$best]})% vs $(pc ${ql[$a]})%, rtt ${qr[$best]:-?} vs ${qr[$a]:-?} ms${why:+ — $why}"
        hold=$((now + HOLD)); backoff=600
        # off a heavily lossy path, the connections already open move too (after a moment for
        # what is in flight): they would go on lagging there
        [ ${ql[$a]:-0} -ge $((LOSSBAD * 3)) ] && ( sleep 15; bash flush-$a.sh ) >/dev/null 2>&1 &
      else
        if [ $best -ge 0 ]; then ev keep "$a" "$a" "path $best is better, but $PLANMAX planned moves this hour already — staying"
        else ev keep "$a" "$a" "compared ${why:-paths}: none clearly better ($(mb $sa) Mbit/s here)"; fi
        cmpat=$((now + backoff)); backoff=$((backoff * 2)); [ $backoff -gt 7200 ] && backoff=7200; cmploss=${ql[$a]:-0}
      fi
    fi
    rm -f cmp.done
  elif [ "${ok[$active]}" = 1 ] && [ ! -f cmp.run ] && [ $((n % 5)) = 0 ]; then
    a=$active; why=""; better=0
    [ ${ql[$a]:-0} -ge $LOSSBAD ] && why="loss $(pc ${ql[$a]})%"
    if [ -n "${sp[$a]}" ] && [ -n "${spb[$a]}" ] && [ $((sp[$a] * 2)) -lt ${spb[$a]} ]; then why="${why:+$why, }speed $(mb ${sp[$a]}) of $(mb ${spb[$a]}) Mbit/s"
    elif [ -n "${sp[$a]}" ] && [ ${sp[$a]} -lt $SPMIN ]; then why="${why:+$why, }speed $(mb ${sp[$a]}) Mbit/s"; fi
    list=""
    for ((k=0; k<N; k++)); do
      [ $k != $a ] && stable $k || continue
      list="$list$(cost $k) $k"$'\n'
      [ $(( $(cost $k) * 10 )) -lt $(( $(cost $a) * 7 )) ] && better=1
      [ $k = $P0 ] && [ $(( $(cost $k) * 10 )) -le $(( $(cost $a) * 11 )) ] && better=1
    done
    # degraded only counts once it has lasted 30 s (one bad reading is not a reason to measure)
    if [ -n "$why" ]; then [ $badsince -gt 0 ] || badsince=$now; else badsince=0; fi
    [ -n "$why" ] && [ $((now - badsince)) -lt 30 ] && why=""
    # much worse loss than at the last "none better": compare again without waiting
    worse=0; [ ${ql[$a]:-0} -ge $((LOSSBAD * 3)) ] && [ ${ql[$a]:-0} -ge $((cmploss * 2)) ] && worse=1
    if [ -n "$list" ] && { [ -n "$why" ] || [ $better = 1 ]; } && { [ $now -ge $cmpat ] || [ $worse = 1 ]; } && [ $now -ge $hold ]; then
      measure cmp $a "$why" $a $(printf '%s' "$list" | sort -n | head -3 | cut -d' ' -f2)
    elif [ $((now - ${spat[$a]:-0})) -ge $SPEVERY ]; then
      measure speed $a "" $a
    fi
  fi
  lastpin=$P0
  n=$((n + 1)); [ $((n % 20)) = 0 ] && { tune; bash base.sh >/dev/null 2>&1; for ((k=0; k<N; k++)); do drops $k >/dev/null; done; }
  # the users' path just missed a check: look again at once instead of after EVERY, so a dead
  # path is left within seconds (still FAILS misses in a row, so a single lost check isn't one)
  if [ "${ok[$active]}" != 1 ] && [ "${fails[$active]:-0}" -gt 0 ]; then sleep 0.3; else sleep $EVERY; fi
done
`

// hsSwitcherPlan is the Iran side's switcher unit with its files.
func (a *App) hsSwitcherPlan(t *Tunnel, paths []HSPath) SidePlan {
	srv, fsrv, set := a.store.Server(t.ServerID), a.store.Server(t.ForeignID), a.settings()
	dir := hsDir(t)
	var ports []string
	for _, s := range splitPorts(t.Ports) {
		ports = append(ports, strings.ReplaceAll(s.listen, "-", ":"))
	}
	conf := fmt.Sprintf("# tunnel %q\nP=%s\nN=%d\nEVERY=%d\nFAILS=%d\nBACK=%d\nPORTS=%q\nSBY=%d\nSPMB=%d\nSPEVERY=%d\nHOLD=%d\nLOSSBAD=%d\nSPMIN=%d\nPLANMAX=%d\n",
		t.Name, probeBin, len(paths), hsEvery, hsFails, hsFailback, strings.Join(ports, " "), hsStandby, hsSpeedMB, hsSpeedSec, hsHold, hsLossBad, hsSpeedMin, hsPlanMax)
	files := map[string]FileSpec{
		dir + "/switch.sh": {Content: []byte(hsSwitcher), Mode: 0o755},
		dir + "/conf":      {Content: []byte(conf), Mode: 0o644},
		dir + "/mode":      {Content: []byte(hsModeName(t) + "\n"), Mode: 0o644},
		dir + "/down.sh":   {Content: []byte("#!/bin/bash\n" + hsSelectDown(t)), Mode: 0o755},
	}
	files[dir+"/base.sh"] = FileSpec{Content: []byte("#!/bin/bash\n" + hsBase(t, paths) + "exit 0\n"), Mode: 0o755}
	files[dir+"/pin"] = FileSpec{Content: []byte(hsPinIndex(t, paths) + "\n"), Mode: 0o644}
	var targets []string
	for k, p := range paths {
		files[fmt.Sprintf("%s/up-%d.sh", dir, k)] = FileSpec{Content: []byte("#!/bin/bash\n" + hsSelectUp(t, p, srv, fsrv, set) + "exit 0\n"), Mode: 0o755}
		files[fmt.Sprintf("%s/flush-%d.sh", dir, k)] = FileSpec{Content: []byte("#!/bin/bash\n" + hsFlush(t, p, srv, fsrv, set)), Mode: 0o755}
		targets = append(targets, hsTarget(t, p, srv, fsrv, set)+" "+hsPingTarget(t, p, srv, fsrv, set))
	}
	files[dir+"/targets"] = FileSpec{Content: []byte(strings.Join(targets, "\n") + "\n"), Mode: 0o644}
	return SidePlan{Files: files, Artifacts: []Artifact{probeArt}, Setup: hsConntrackSetup, Unit: Unit{
		Desc: "Hot standby switcher " + t.Name, ExecStart: "/bin/bash " + dir + "/switch.sh", ExecStopPost: dir + "/down.sh"}}
}

// hsConntrackSetup installs the conntrack tool the switcher clears a dead path's
// connections with (without it they wait for the client's own timeout).
// It installs in the background, so a slow mirror never holds up the apply.
const hsConntrackSetup = `if ! command -v conntrack >/dev/null 2>&1; then
  echo "note: installing the conntrack tool in the background (until then users of a failed path reconnect on their own timeout)"
  nohup sh -c '(command -v apt-get >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq conntrack) || (command -v dnf >/dev/null 2>&1 && timeout 300 dnf install -y conntrack-tools)' >/dev/null 2>&1 &
fi
true
`

// hsPinIndex is the switcher index of the path chosen in the panel ("" = the first).
func hsPinIndex(t *Tunnel, paths []HSPath) string {
	for k, p := range paths {
		if t.HSPin != "" && p.Method+"|"+p.Family == t.HSPin {
			return strconv.Itoa(k)
		}
	}
	return ""
}

func hsModeName(t *Tunnel) string {
	if t.HSAuto {
		return "auto"
	}
	return "manual"
}

// hsPingTarget is what the switcher pings for path p's packet loss: the far tunnel address
// of an L3 path, the foreign server's address on the path's family for a forwarder.
func hsPingTarget(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) string {
	pt := pathTunnel(t, p)
	d := deriveFor(pt, srv, fsrv, set)
	if m := methodByID[p.Method]; m != nil && benchIsL3(m, pt.Options[m.ID]) {
		return d.KHv4
	}
	return strings.Trim(d.KHPub, "[]")
}

// setHSMode switches a tunnel between manual and auto; a running switcher picks it up
// within seconds (it reads the mode file every check), no re-apply needed.
func (a *App) setHSMode(ctx context.Context, t *Tunnel, auto bool) (string, error) {
	_ = a.store.Update(func(*State) error { t.HSAuto = auto; return nil })
	if !t.HotStandby || t.Active == "" {
		return "saved — it takes effect when hot standby runs", nil
	}
	return a.pushHSMode(ctx, t)
}

func (a *App) pushHSMode(ctx context.Context, t *Tunnel) (string, error) {
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return "", fmt.Errorf("Iran server not found")
	}
	h, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return "", fmt.Errorf("saved, but the Iran server can't be reached now (%v) — it takes effect on the next apply", err)
	}
	dir := hsDir(t)
	out, _ := h.Run(ctx, fmt.Sprintf("cd %s 2>/dev/null || { echo NODIR; exit 0; }; echo %s > mode; grep -q 'mode file' switch.sh && echo OK || echo OLD", dir, hsModeName(t)), nil)
	switch {
	case strings.Contains(out, "OK"):
		return "switcher is now " + hsModeName(t), nil
	case strings.Contains(out, "OLD"):
		return "saved — this switcher is from an older panel version: press Re-apply once", nil
	}
	return "saved — it takes effect on the next apply", nil
}

// hsProbePlan is the foreign side's permanent probe server the checks go to, reachable only
// from inside the tunnels (10.10.x.x) and loopback (the forwarders' delivery address).
func hsProbePlan(t *Tunnel) SidePlan {
	hp, ch := hsProbePort(t), "TPHP_"+t.ID
	dir := hsDir(t)
	up := fmt.Sprintf(`iptables -w -N %[1]s 2>/dev/null || iptables -w -F %[1]s
iptables -w -A %[1]s -s 127.0.0.0/8 -j RETURN
iptables -w -A %[1]s -s 10.10.0.0/16 -j RETURN
iptables -w -A %[1]s -j DROP
iptables -w -C INPUT -p tcp --dport %[2]d -j %[1]s 2>/dev/null || iptables -w -I INPUT -p tcp --dport %[2]d -j %[1]s
ip6tables -w -C INPUT -p tcp --dport %[2]d ! -s ::1 -j DROP 2>/dev/null || ip6tables -w -I INPUT -p tcp --dport %[2]d ! -s ::1 -j DROP 2>/dev/null
iptables -w -C INPUT -i tp+ -p tcp --dport %[2]d -j ACCEPT 2>/dev/null || iptables -w -I INPUT -i tp+ -p tcp --dport %[2]d -j ACCEPT
iptables -w -C INPUT -i bhp+ -p tcp --dport %[2]d -j ACCEPT 2>/dev/null || iptables -w -I INPUT -i bhp+ -p tcp --dport %[2]d -j ACCEPT
exit 0
`, ch, hp)
	down := fmt.Sprintf(`while iptables -w -D INPUT -p tcp --dport %[2]d -j %[1]s 2>/dev/null; do :; done
iptables -w -F %[1]s 2>/dev/null; iptables -w -X %[1]s 2>/dev/null
while ip6tables -w -D INPUT -p tcp --dport %[2]d ! -s ::1 -j DROP 2>/dev/null; do :; done
while iptables -w -D INPUT -i tp+ -p tcp --dport %[2]d -j ACCEPT 2>/dev/null; do :; done
while iptables -w -D INPUT -i bhp+ -p tcp --dport %[2]d -j ACCEPT 2>/dev/null; do :; done
exit 0
`, ch, hp)
	return SidePlan{Files: map[string]FileSpec{
		dir + "/fw-up.sh":   {Content: []byte("#!/bin/bash\n" + up), Mode: 0o755},
		dir + "/fw-down.sh": {Content: []byte("#!/bin/bash\n" + down), Mode: 0o755},
	}, Artifacts: []Artifact{probeArt}, Unit: Unit{Desc: "Hot standby probe " + t.Name,
		ExecStartPre: dir + "/fw-up.sh", ExecStart: fmt.Sprintf("%s probe serve -listen :%d -life 315360000", probeBin, hp), ExecStopPost: dir + "/fw-down.sh"}}
}

// hsUnitTunnel is the pseudo tunnel the switcher (Iran) / probe server (foreign) runs as.
func hsUnitTunnel(t *Tunnel) *Tunnel { return &Tunnel{ID: t.ID + "hs", Name: t.Name} }

// hsTeardown stops every path, the switcher and the probe server of t (both sides run it).
func hsTeardown(t *Tunnel) string {
	var b strings.Builder
	b.WriteString(teardownScript(hsUnitTunnel(t)))
	for _, p := range t.Paths {
		b.WriteString(teardownScript(pathTunnel(t, p)))
	}
	b.WriteString(teardownScript(t))
	b.WriteString(hsSelectDown(t))
	b.WriteString(hsAcctDown(t))
	return b.String()
}

// applyHot deploys every path, the probe server and the switcher. Paths that fail are left
// out (the tunnel works as long as one does); the result lists them.
func (a *App) applyHot(ctx context.Context, j *Job, t *Tunnel, m *Method, srv *Server, irHost, khHost Host, fail func(string, ...any)) bool {
	old := *t
	old.Paths = append([]HSPath(nil), t.Paths...)
	paths := a.hsPlan(t, m.ID, t.Family)
	j.log("hot standby: %d paths, in this order (benchmark score first):", len(paths))
	for k, p := range paths {
		j.log("  %d. %s", k+1, p.label())
	}
	j.log("stopping what ran before on both servers")
	a.setApplying(t, m.ID)
	_, _ = irHost.Run(ctx, hsTeardown(&old), func(l string) { j.log("[IR] %s", l) })
	_, _ = khHost.Run(ctx, hsTeardown(&old), func(l string) { j.log("[KH] %s", l) })
	a.setActive(t, "")

	j.log("== probe server on the foreign side (port %d, reachable only through the tunnels) ==", hsProbePort(t))
	if err := a.deploy(ctx, j, "KH", khHost, hsUnitTunnel(t), hsProbePlan(t)); err != nil {
		fail("foreign probe server: %v", err)
		return false
	}
	var good []HSPath
	for k := range paths {
		p := paths[k]
		pt := pathTunnel(t, p)
		pm := methodByID[p.Method]
		j.log("== path %d: %s ==", k+1, p.label())
		err := func() error {
			if pm == nil {
				return fmt.Errorf("unknown method")
			}
			irP, khP, err := a.build(pm, pt, srv)
			if err != nil {
				return err
			}
			if changed, err := a.reversePreflight(ctx, j, pt, pm, irHost, khHost); err != nil {
				return err
			} else if changed {
				if irP, khP, err = a.build(pm, pt, srv); err != nil {
					return err
				}
				p.Opts = pt.Options[pm.ID]
			}
			if err := a.deploy(ctx, j, "KH", khHost, pt, khP); err != nil {
				return fmt.Errorf("foreign: %w", err)
			}
			if err := a.deploy(ctx, j, "IR", irHost, pt, irP); err != nil {
				return fmt.Errorf("Iran: %w", err)
			}
			return nil
		}()
		if err != nil {
			j.log("  ✕ left out: %v", err)
			p.Failed = err.Error()
			_, _ = irHost.Run(ctx, teardownScript(pt), nil)
			_, _ = khHost.Run(ctx, teardownScript(pt), nil)
		} else {
			j.log("  ✓ %s is up", p.label())
			p.Failed = ""
			good = append(good, p)
		}
		paths[k] = p
	}
	_ = a.store.Update(func(*State) error { t.Paths = paths; return nil })
	if len(good) == 0 {
		fail("no path could be deployed")
		return false
	}
	j.log("== switcher on the Iran server (checks every %ds, switches after %d failed checks, back after %ds stable) ==", hsEvery, hsFails, hsFailback)
	if err := a.deploy(ctx, j, "IR", irHost, hsUnitTunnel(t), a.hsSwitcherPlan(t, good)); err != nil {
		fail("switcher: %v", err)
		return false
	}
	a.setActive(t, m.ID)
	j.log("DONE — hot standby: %d of %d paths running; users go through %s now", len(good), len(paths), good[0].label())
	j.finish("ok")
	a.push(fmt.Sprintf("✅ %s: hot standby with %d paths (active: %s)", t.Name, len(good), good[0].label()))
	return true
}

// running paths in switcher order (the ones that deployed)
func hsGood(t *Tunnel) []HSPath {
	var out []HSPath
	for _, p := range t.Paths {
		if p.Failed == "" {
			out = append(out, p)
		}
	}
	return out
}

// hsGoodNow is hsGood and the chosen path, read under the store lock (an apply rewrites
// Paths while the health monitor and the bot read them).
func (a *App) hsGoodNow(t *Tunnel) (good []HSPath, pin string) {
	a.store.View(func(*State) { good, pin = hsGood(t), t.HSPin })
	return
}

// hsView is the switcher's state as the panel last read it.
type hsView struct {
	Active int       `json:"active"`
	Since  int64     `json:"since"`
	Paths  []string  `json:"paths"` // label of each running path, switcher order
	OK     []bool    `json:"ok"`
	Read   int64     `json:"read"`
	Auto   bool      `json:"auto"`
	RTT    []int     `json:"rtt"`  // ms, smoothed (-1 = not measured yet)
	Loss   []float64 `json:"loss"` // %, smoothed (-1 = unknown: ICMP filtered or manual mode)
	Kbps   []int     `json:"kbps"` // last download measurement (-1 = none yet)
	Keys   []string  `json:"keys"` // "method|family" of each path
	Pin    int       `json:"pin"`  // the chosen path's index (-1 = the tunnel's own)
}

// hsRead reads the switcher's state and the events since `after` from the Iran server.
func (a *App) hsRead(ctx context.Context, h Host, t *Tunnel, after int64) (*hsView, []string, error) {
	dir := hsDir(t)
	out, err := h.Run(ctx, fmt.Sprintf(`cd %s 2>/dev/null || exit 3
echo "A $(cat active 2>/dev/null)"
echo "M $(cat mode 2>/dev/null || echo manual)"
sed 's/^/S /' status 2>/dev/null
awk -v s=%d '$1 > s' events.log 2>/dev/null | sed 's/^/E /' | tail -n 50
systemctl is-active %s >/dev/null 2>&1 && echo "U active" || echo "U down"`, dir, after, unitName(hsUnitTunnel(t))), nil)
	if err != nil && !strings.Contains(out, "A ") {
		return nil, nil, fmt.Errorf("switcher state unreadable: %v", err)
	}
	v := &hsView{Active: -1, Read: time.Now().Unix()}
	good, pin := a.hsGoodNow(t)
	for _, p := range good {
		v.Paths = append(v.Paths, p.label())
	}
	v.OK = make([]bool, len(v.Paths))
	v.Pin = -1
	for k, p := range good {
		v.Keys = append(v.Keys, p.Method+"|"+p.Family)
		if pin == p.Method+"|"+p.Family {
			v.Pin = k
		}
	}
	v.RTT, v.Loss, v.Kbps = make([]int, len(v.Paths)), make([]float64, len(v.Paths)), make([]int, len(v.Paths))
	for k := range v.Paths {
		v.RTT[k], v.Loss[k], v.Kbps[k] = -1, -1, -1
	}
	num := func(f []string, i int) (int, bool) {
		if i >= len(f) {
			return 0, false
		}
		n, err := strconv.Atoi(f[i])
		return n, err == nil
	}
	var events []string
	unit := ""
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "A":
			v.Active, _ = strconv.Atoi(f[1])
			if len(f) > 2 {
				v.Since, _ = strconv.ParseInt(f[2], 10, 64)
			}
		case "S":
			if k, err := strconv.Atoi(f[1]); err == nil && k < len(v.OK) && len(f) > 2 {
				v.OK[k] = f[2] == "ok"
				if n, ok := num(f, 4); ok {
					v.RTT[k] = n
				}
				if n, ok := num(f, 5); ok {
					v.Loss[k] = float64(n) / 10
				}
				if n, ok := num(f, 6); ok {
					v.Kbps[k] = n
				}
			}
		case "M":
			v.Auto = f[1] == "auto"
		case "E":
			events = append(events, strings.Join(f[1:], " "))
		case "U":
			unit = f[1]
		}
	}
	if unit != "active" {
		return v, events, fmt.Errorf("the switcher isn't running on the Iran server")
	}
	return v, events, nil
}

// hsEventText turns "epoch switch from to reason…" into a message line.
func hsEventText(t *Tunnel, good []HSPath, e string) (int64, string) {
	f := strings.Fields(e)
	if len(f) < 4 {
		return 0, ""
	}
	at, _ := strconv.ParseInt(f[0], 10, 64)
	name := func(s string) string {
		if k, err := strconv.Atoi(s); err == nil && k >= 0 && k < len(good) {
			return good[k].label()
		}
		return "—"
	}
	reason := strings.Join(f[4:], " ")
	switch f[1] {
	case "switch":
		if f[2] == "-1" {
			return at, ""
		}
		if strings.HasPrefix(reason, "auto: ") {
			return at, fmt.Sprintf("⚡ %s: auto mode moved the users to %s — better than %s (%s), %s (Tehran)", t.Name, name(f[3]), name(f[2]), strings.TrimPrefix(reason, "auto: "), clock(time.Unix(at, 0)))
		}
		if i := strings.Index(reason, "worked for "); i >= 0 {
			return at, fmt.Sprintf("↩ %s back on %s (it was stable for %s) — from %s, %s (Tehran)", t.Name, name(f[3]), reason[i+len("worked for "):], name(f[2]), clock(time.Unix(at, 0)))
		}
		return at, fmt.Sprintf("🔀 %s switched to %s — %s (%s), %s (Tehran)", t.Name, name(f[3]), name(f[2]), strings.ReplaceAll(reason, "path "+f[2]+" ", ""), clock(time.Unix(at, 0)))
	case "kernel":
		return at, fmt.Sprintf("⚙ %s (Iran server): %s", t.Name, reason)
	}
	return at, ""
}

// hsAcct counts users' traffic by the connections' original port (the same whichever path
// carries it, DNAT or REDIRECT), in mangle so nothing else is affected.
func hsAcct(t *Tunnel) string {
	in, out := "TPHA_"+t.ID, "TPHB_"+t.ID
	var rules strings.Builder
	for _, s := range splitPorts(t.Ports) {
		p := strings.ReplaceAll(s.listen, "-", ":")
		for _, proto := range []string{"tcp", "udp"} {
			fmt.Fprintf(&rules, "    iptables -w -t mangle -A %s -p %s -m conntrack --ctdir ORIGINAL --ctorigdstport %s\n", in, proto, p)
			fmt.Fprintf(&rules, "    iptables -w -t mangle -A %s -p %s -m conntrack --ctdir REPLY --ctorigdstport %s\n", out, proto, p)
		}
	}
	return fmt.Sprintf(`if ! iptables -w -t mangle -nL %[1]s >/dev/null 2>&1; then
    iptables -w -t mangle -N %[1]s; iptables -w -t mangle -N %[2]s
%[4]s    iptables -w -t mangle -I PREROUTING -j %[1]s; iptables -w -t mangle -I POSTROUTING -j %[2]s
fi
d=$(iptables -w -t mangle -nvxL %[2]s 2>/dev/null | awk 'NR>2{s+=$2}END{printf "%%d", s+0}')
u=$(iptables -w -t mangle -nvxL %[1]s 2>/dev/null | awk 'NR>2{s+=$2}END{printf "%%d", s+0}')
echo "T %[3]s $d $u"
`, in, out, t.ID, rules.String())
}

func hsAcctDown(t *Tunnel) string {
	in, out := "TPHA_"+t.ID, "TPHB_"+t.ID
	return fmt.Sprintf(`while iptables -w -t mangle -D PREROUTING -j %[1]s 2>/dev/null; do :; done
while iptables -w -t mangle -D POSTROUTING -j %[2]s 2>/dev/null; do :; done
iptables -w -t mangle -F %[1]s 2>/dev/null; iptables -w -t mangle -X %[1]s 2>/dev/null
iptables -w -t mangle -F %[2]s 2>/dev/null; iptables -w -t mangle -X %[2]s 2>/dev/null
true
`, in, out)
}

// hsReport keeps the switcher's view for the UI and sends its new events to Telegram.
func (a *App) hsReport(t *Tunnel, v *hsView, events []string) {
	if v != nil {
		a.healthMu.Lock()
		if a.hsViews == nil {
			a.hsViews = map[string]*hsView{}
		}
		a.hsViews[t.ID] = v
		a.healthMu.Unlock()
	}
	good, _ := a.hsGoodNow(t)
	var seen int64
	a.store.View(func(*State) { seen = t.HSSeen })
	newest := seen
	for _, e := range events {
		at, msg := hsEventText(t, good, e)
		if at > newest {
			newest = at
		}
		if msg != "" && at > seen {
			a.push(msg)
		}
	}
	if newest > seen {
		_ = a.store.Update(func(*State) error {
			if newest > t.HSSeen {
				t.HSSeen = newest
			}
			return nil
		})
	}
}

func (a *App) hsViewOf(id string) *hsView {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	return a.hsViews[id]
}

// hsIndex is path (method, family)'s switcher index among the running paths, or -1.
func hsIndex(t *Tunnel, mid, fam string) int {
	for k, p := range hsGood(t) {
		if p.Method == mid && p.Family == fam {
			return k
		}
	}
	return -1
}

// hsPinTo moves the users of a hot-standby tunnel to one of its running paths without a
// re-apply: the switcher swaps the selector (new connections there, open ones finish where
// they are), so nobody is cut. pin "" = back to the tunnel's own method.
func (a *App) hsPinTo(ctx context.Context, t *Tunnel, pin string) (string, error) {
	if pin == t.Active+"|"+t.Family {
		pin = ""
	}
	_ = a.store.Update(func(*State) error { t.HSPin = pin; return nil })
	idx := hsPinIndex(t, hsGood(t))
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return "", fmt.Errorf("Iran server not found")
	}
	h, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return "", fmt.Errorf("the Iran server can't be reached now: %v", err)
	}
	out, _ := h.Run(ctx, fmt.Sprintf("cd %s 2>/dev/null || { echo NODIR; exit 0; }; echo %s > pin; grep -q 'chosen in the panel' switch.sh && echo OK || echo OLD", hsDir(t), shq(idx)), nil)
	switch {
	case strings.Contains(out, "OLD"):
		return "", fmt.Errorf("this switcher is from an older panel version — press Re-apply once")
	case !strings.Contains(out, "OK"):
		return "", fmt.Errorf("hot standby isn't running on the Iran server — press Re-apply")
	}
	name := methodTitle(t.Active) + " (" + t.Family + ")"
	if pin != "" {
		f := strings.SplitN(pin, "|", 2)
		name = methodTitle(f[0]) + " (" + f[1] + ")"
	}
	return "users move to " + name + " within a few seconds — open connections finish where they are, nobody is cut", nil
}

// hsSwitchJob is Apply for a path that already runs: a short job around hsPinTo.
func (a *App) hsSwitchJob(t *Tunnel, mid, fam string) (*Job, error) {
	j, err := a.jobs.start(t.ID, "switch")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(time.Minute)
		defer cancel()
		j.log("%s %s is already running as a hot-standby path — switching the users over, no restart", methodTitle(mid), fam)
		msg, err := a.hsPinTo(ctx, t, mid+"|"+fam)
		if err != nil {
			j.log("ERROR: %v", err)
			j.finish("error")
			return
		}
		j.log("DONE — %s", msg)
		j.finish("ok")
	}()
	return j, nil
}
