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
	hsFails    = 2  // failed checks in a row before the active path is abandoned
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
			if !supportsFamily(m, f) || m.ID == "spoof" || (m.ID == mid && f == fam) || (hsOnly != nil && !contains(hsOnly, m.ID)) {
				continue
			}
			if !benchIsL3(m, t.Options[m.ID]) && !hsForwarderOK(t) {
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
		used := map[int]bool{}
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
	return t.Paths
}

// hsSelectUp makes path p the one users' ports lead to (the selector chain names are the
// same for every path, so hsSelectDown removes whichever is active).
func hsSelectUp(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) string {
	pt := pathTunnel(t, p)
	m := methodByID[p.Method]
	if m != nil && benchIsL3(m, pt.Options[m.ID]) {
		d := deriveFor(pt, srv, fsrv, set)
		return portForwardV4(t.Ports, d.KHv4, l3Iface(m, pt), hsTag(t))
	}
	nat := "TP_" + hsTag(t)
	var b strings.Builder
	fmt.Fprintf(&b, "iptables -t nat -N %[1]s 2>/dev/null || iptables -t nat -F %[1]s\n", nat)
	for j, s := range splitPorts(t.Ports) {
		for _, proto := range []string{"tcp", "udp"} {
			fmt.Fprintf(&b, "iptables -t nat -A %s -m addrtype --dst-type LOCAL -p %s --dport %s -j REDIRECT --to-ports %d\n", nat, proto, s.listen, hsInternal(p, j))
		}
	}
	fmt.Fprintf(&b, "iptables -t nat -C PREROUTING -j %[1]s 2>/dev/null || iptables -t nat -I PREROUTING -j %[1]s\n", nat)
	return b.String()
}

func hsSelectDown(t *Tunnel) string { return portForwardDownV4(hsTag(t)) }

// hsTarget is where the switcher checks path p end to end (through the tunnel).
func hsTarget(t *Tunnel, p HSPath, srv, fsrv *Server, set Settings) string {
	pt := pathTunnel(t, p)
	m := methodByID[p.Method]
	if m != nil && benchIsL3(m, pt.Options[m.ID]) {
		return fmt.Sprintf("%s:%d", deriveFor(pt, srv, fsrv, set).KHv4, hsProbePort(t))
	}
	return fmt.Sprintf("127.0.0.1:%d", hsInternal(p, 19))
}

// hsSwitcher is the switcher's loop (bash, on the Iran server).
func hsSwitcher(t *Tunnel, paths []HSPath) string {
	var ports []string
	for _, s := range splitPorts(t.Ports) {
		ports = append(ports, strings.ReplaceAll(s.listen, "-", ":"))
	}
	return fmt.Sprintf(`#!/bin/bash
# Hot-standby switcher for tunnel %[1]q: checks every path end to end and keeps the users'
# ports on the best working one. Events go to events.log (epoch kind from to reason).
D=%[2]s; P=%[3]s; N=%[4]d; EVERY=%[5]d; FAILS=%[6]d; BACK=%[7]d; PORTS=%[8]q
cd "$D" || exit 1
mapfile -t T < targets
ev() { echo "$(date +%%s) $*" >> events.log; tail -n 300 events.log > events.tmp && mv events.tmp events.log; }
tune() {
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
use() { # use <k> <reason>
  bash down.sh >/dev/null 2>&1; bash up-$1.sh >/dev/null 2>&1
  if command -v conntrack >/dev/null 2>&1; then for p in $PORTS; do conntrack -D -p tcp --orig-port-dst ${p%%%%:*} >/dev/null 2>&1; conntrack -D -p udp --orig-port-dst ${p%%%%:*} >/dev/null 2>&1; done; fi
  ev switch "$active" "$1" "$2"; active=$1; echo "$1 $(date +%%s)" > active
}
declare -a ok since fails
active=-1
if [ -f active ]; then read -r a _ < active; [ -n "$a" ] && [ "$a" -lt $N ] && { bash down.sh >/dev/null 2>&1; bash up-$a.sh >/dev/null 2>&1; active=$a; }; fi
[ $active -ge 0 ] || use 0 "start"
tune; n=0
while true; do
  for ((k=0; k<N; k++)); do ( timeout 3 $P probe rtt -addr ${T[$k]} -n 2 >/dev/null 2>&1 && echo ok > c$k || echo down > c$k ) & done
  wait
  now=$(date +%%s); : > status.tmp
  for ((k=0; k<N; k++)); do
    r=$(cat c$k 2>/dev/null)
    if [ "$r" = ok ]; then [ "${ok[$k]}" = 1 ] || since[$k]=$now; ok[$k]=1; fails[$k]=0
    else [ "${ok[$k]}" = 0 ] || since[$k]=$now; ok[$k]=0; fails[$k]=$(( ${fails[$k]:-0} + 1 )); fi
    echo "$k ${r:-down} ${since[$k]:-$now}" >> status.tmp
  done
  mv status.tmp status
  if [ "${ok[$active]}" != 1 ] && [ "${fails[$active]:-0}" -ge $FAILS ]; then
    for ((k=0; k<N; k++)); do if [ "${ok[$k]}" = 1 ]; then use $k "path $active failed $FAILS checks in a row"; break; fi; done
  elif [ "${ok[$active]}" = 1 ]; then
    for ((k=0; k<active; k++)); do
      if [ "${ok[$k]}" = 1 ] && [ $((now - ${since[$k]:-$now})) -ge $BACK ]; then use $k "path $k worked for ${BACK}s"; break; fi
    done
  fi
  n=$((n + 1)); [ $((n %% 20)) = 0 ] && tune
  sleep $EVERY
done
`, t.Name, hsDir(t), probeBin, len(paths), hsEvery, hsFails, hsFailback, strings.Join(ports, " "))
}

// hsSwitcherPlan is the Iran side's switcher unit with its files.
func (a *App) hsSwitcherPlan(t *Tunnel, paths []HSPath) SidePlan {
	srv, fsrv, set := a.store.Server(t.ServerID), a.store.Server(t.ForeignID), a.settings()
	dir := hsDir(t)
	files := map[string]FileSpec{
		dir + "/switch.sh": {Content: []byte(hsSwitcher(t, paths)), Mode: 0o755},
		dir + "/down.sh":   {Content: []byte("#!/bin/bash\n" + hsSelectDown(t)), Mode: 0o755},
	}
	var targets []string
	for k, p := range paths {
		files[fmt.Sprintf("%s/up-%d.sh", dir, k)] = FileSpec{Content: []byte("#!/bin/bash\n" + hsSelectUp(t, p, srv, fsrv, set) + "exit 0\n"), Mode: 0o755}
		targets = append(targets, hsTarget(t, p, srv, fsrv, set))
	}
	files[dir+"/targets"] = FileSpec{Content: []byte(strings.Join(targets, "\n") + "\n"), Mode: 0o644}
	return SidePlan{Files: files, Artifacts: []Artifact{probeArt}, Unit: Unit{
		Desc: "Hot standby switcher " + t.Name, ExecStart: "/bin/bash " + dir + "/switch.sh", ExecStopPost: dir + "/down.sh"}}
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

// hsView is the switcher's state as the panel last read it.
type hsView struct {
	Active int      `json:"active"`
	Since  int64    `json:"since"`
	Paths  []string `json:"paths"` // label of each running path, switcher order
	OK     []bool   `json:"ok"`
	Read   int64    `json:"read"`
}

// hsRead reads the switcher's state and the events since `after` from the Iran server.
func (a *App) hsRead(ctx context.Context, h Host, t *Tunnel, after int64) (*hsView, []string, error) {
	dir := hsDir(t)
	out, err := h.Run(ctx, fmt.Sprintf(`cd %s 2>/dev/null || exit 3
echo "A $(cat active 2>/dev/null)"
sed 's/^/S /' status 2>/dev/null
awk -v s=%d '$1 > s' events.log 2>/dev/null | sed 's/^/E /' | tail -n 50
systemctl is-active %s >/dev/null 2>&1 && echo "U active" || echo "U down"`, dir, after, unitName(hsUnitTunnel(t))), nil)
	if err != nil && !strings.Contains(out, "A ") {
		return nil, nil, fmt.Errorf("switcher state unreadable: %v", err)
	}
	v := &hsView{Active: -1, Read: time.Now().Unix()}
	for _, p := range hsGood(t) {
		v.Paths = append(v.Paths, p.label())
	}
	v.OK = make([]bool, len(v.Paths))
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
			}
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
func hsEventText(t *Tunnel, e string) (int64, string) {
	f := strings.Fields(e)
	if len(f) < 4 {
		return 0, ""
	}
	at, _ := strconv.ParseInt(f[0], 10, 64)
	good := hsGood(t)
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
		if strings.Contains(reason, "worked for") {
			return at, fmt.Sprintf("↩ %s back on %s (it was stable for %ds) — from %s, %s (Tehran)", t.Name, name(f[3]), hsFailback, name(f[2]), clock(time.Unix(at, 0)))
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
	newest := t.HSSeen
	for _, e := range events {
		at, msg := hsEventText(t, e)
		if at > newest {
			newest = at
		}
		if msg != "" && at > t.HSSeen {
			a.push(msg)
		}
	}
	if newest > t.HSSeen {
		_ = a.store.Update(func(*State) error { t.HSSeen = newest; return nil })
	}
}

func (a *App) hsViewOf(id string) *hsView {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	return a.hsViews[id]
}
