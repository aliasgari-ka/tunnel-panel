package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-path kernel settings, edited in the tunnel card's hot-standby list (⋯ → ⚙ Settings).
//
// A path with a network interface of its own (GRE, IPsec, WireGuard, Premium ipx… — l3Iface)
// can have its interface's MTU, transmit queue length and queueing discipline set, and the
// TCP MSS the Iran side clamps the users' connections to on it. All of them change live, on
// both servers, without restarting anything: nobody is cut. They are also written next to
// the path's unit (net.sh, run by a drop-in after each start) so a restart, a reboot or a
// rebuild keeps them, and the switcher's MSS rule for the path follows them (hsBase).
//
// A path that forwards ports in user space (FRP, Backhaul tcp, BackPack…) has no interface
// of its own: the kernel settings that affect it are the servers' (Servers → Optimize), shown
// read-only in the panel.
//
// Values set here are the user's: kept whatever happens (a path that stops answering with
// them is reported failing, with the reason, and the users stay on a working path);
// ↺ Defaults puts the interface back as the method made it.

// PathNet is one path's kernel settings; zero = the method's/kernel's own.
type PathNet struct {
	MTU    int    `json:"mtu,omitempty"`    // interface MTU
	MSS    int    `json:"mss,omitempty"`    // fixed TCP MSS for the users' connections (0 = follow the path MTU)
	TxQLen int    `json:"txqlen,omitempty"` // transmit queue length
	Qdisc  string `json:"qdisc,omitempty"`  // root queueing discipline ("" = kernel default)
}

func (n PathNet) zero() bool { return n == PathNet{} }

// pathNetQdiscs are the queueing disciplines offered ("" = leave the kernel's).
var pathNetQdiscs = []string{"", "fq", "fq_codel", "cake", "pfifo_fast"}

// latinNum is s with Persian/Arabic digits made ASCII and spaces trimmed ("۱۴۰۰" → "1400").
func latinNum(s string) string { return strings.TrimSpace(igDigits(s)) }

// parsePathNet reads the form's values (strings, Persian digits accepted) and checks them.
// fam is the path's family (an IPv6 interface needs MTU ≥ 1280); ownMTU: the method has an
// MTU option of its own, which is where the MTU is set then.
func parsePathNet(in map[string]string, fam string, ownMTU bool) (PathNet, error) {
	var n PathNet
	num := func(key, label string, lo, hi int) (int, error) {
		v := latinNum(in[key])
		if v == "" || v == "0" {
			return 0, nil
		}
		x, err := strconv.Atoi(v)
		if err != nil || x < lo || x > hi {
			return 0, fmt.Errorf("%s must be a number between %d and %d (blank = default)", label, lo, hi)
		}
		return x, nil
	}
	var err error
	lo := 576
	if fam == "v6" {
		lo = 1280
	}
	if n.MTU, err = num("mtu", "MTU", lo, 9000); err != nil {
		return n, err
	}
	if n.MTU > 0 && ownMTU {
		return n, fmt.Errorf("this method sets its MTU itself — change it in the method's options above")
	}
	if n.MSS, err = num("mss", "TCP MSS", 536, 8960); err != nil {
		return n, err
	}
	if n.MSS > 0 && n.MTU > 0 && n.MSS > n.MTU-40 {
		return n, fmt.Errorf("TCP MSS %d doesn't fit in MTU %d — at most %d", n.MSS, n.MTU, n.MTU-40)
	}
	if n.TxQLen, err = num("txqlen", "Queue length", 10, 100000); err != nil {
		return n, err
	}
	n.Qdisc = strings.TrimSpace(in["qdisc"])
	if !contains(pathNetQdiscs, n.Qdisc) {
		return n, fmt.Errorf("queueing discipline must be one of %s", strings.Join(pathNetQdiscs[1:], ", "))
	}
	return n, nil
}

// pathNetDropIn is the unit drop-in that runs net.sh after each start of the path's unit.
func pathNetDropIn(pt *Tunnel) string {
	return "/etc/systemd/system/" + unitName(pt) + ".d/50-tp-net.conf"
}

func pathNetSh(pt *Tunnel) string { return tunnelDir(pt) + "/net.sh" }

// pathNetScript is net.sh: wait for the interface, note what the method made it (net.orig,
// for ↺ Defaults), then set what the user chose. "start" (after a unit start) always notes
// the method's values; "live" only when none are noted yet.
func pathNetScript(pt *Tunnel, ifc string, n PathNet) string {
	d := tunnelDir(pt)
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/bash
# Tunnel Panel — kernel settings of this path's interface (the card's path ⚙ Settings)
IF=%[1]s; D=%[2]s
for i in $(seq 1 40); do [ -e /sys/class/net/$IF ] && break; sleep 0.25; done
[ -e /sys/class/net/$IF ] || { echo "net: $IF is not up yet — set when it starts"; exit 0; }
if [ "$1" = start ] || [ ! -s $D/net.orig ]; then echo "$(cat /sys/class/net/$IF/mtu) $(cat /sys/class/net/$IF/tx_queue_len)" >$D/net.orig; fi
`, ifc, d)
	if n.MTU > 0 {
		fmt.Fprintf(&b, "ip link set dev $IF mtu %d || echo \"net: MTU %d refused on $IF\"\n", n.MTU, n.MTU)
	}
	if n.TxQLen > 0 {
		fmt.Fprintf(&b, "ip link set dev $IF txqueuelen %d || echo \"net: queue length refused on $IF\"\n", n.TxQLen)
	}
	if n.Qdisc != "" {
		fmt.Fprintf(&b, "tc qdisc replace dev $IF root %[1]s 2>/dev/null || echo \"net: %[1]s is not available on this kernel — $IF keeps its own\"\n", n.Qdisc)
	}
	b.WriteString(pathNetShow)
	return b.String()
}

// pathNetShow prints what the interface runs with now.
const pathNetShow = `echo "net $IF: mtu $(cat /sys/class/net/$IF/mtu) · txqueuelen $(cat /sys/class/net/$IF/tx_queue_len) · qdisc $(tc qdisc show dev $IF 2>/dev/null | awk 'NR==1{print $2}')"
`

// pathNetFiles are net.sh and its drop-in (n non-zero).
func pathNetFiles(pt *Tunnel, ifc string, n PathNet) map[string]FileSpec {
	return map[string]FileSpec{
		pathNetSh(pt):     {Content: []byte(pathNetScript(pt, ifc, n)), Mode: 0o755},
		pathNetDropIn(pt): {Content: []byte("[Service]\nExecStartPost=-" + pathNetSh(pt) + " start\n"), Mode: 0o644},
	}
}

// addPathNet puts a path's kernel settings into its plans (both sides): a rebuild, Repair or
// a fresh server keep them.
func addPathNet(m *Method, pt *Tunnel, plans ...*SidePlan) {
	if pt.Net == nil || pt.Net.zero() {
		return
	}
	ifc := l3Iface(m, pt)
	if ifc == "" {
		return
	}
	for _, p := range plans {
		if p.Files == nil {
			p.Files = map[string]FileSpec{}
		}
		for k, v := range pathNetFiles(pt, ifc, *pt.Net) {
			p.Files[k] = v
		}
	}
}

// pathNetLive is the script that changes a running path's interface from old to n in place:
// what is no longer set goes back to the method's values (net.orig) or the kernel's qdisc,
// then net.sh sets the rest. Nothing restarts.
func pathNetLive(pt *Tunnel, ifc string, old, n PathNet) string {
	d := tunnelDir(pt)
	var b strings.Builder
	fmt.Fprintf(&b, "IF=%s; D=%s\n", ifc, d)
	if (old.MTU > 0 && n.MTU == 0) || (old.TxQLen > 0 && n.TxQLen == 0) {
		b.WriteString("if [ -e /sys/class/net/$IF ] && [ -s $D/net.orig ]; then read om oq <$D/net.orig\n")
		if old.MTU > 0 && n.MTU == 0 {
			b.WriteString("  [ -n \"$om\" ] && ip link set dev $IF mtu $om\n")
		}
		if old.TxQLen > 0 && n.TxQLen == 0 {
			b.WriteString("  [ -n \"$oq\" ] && ip link set dev $IF txqueuelen $oq\n")
		}
		b.WriteString("fi\n")
	}
	if old.Qdisc != "" && n.Qdisc == "" {
		b.WriteString("tc qdisc del dev $IF root 2>/dev/null\n")
	}
	if n.zero() {
		fmt.Fprintf(&b, "rm -f %s $D/net.sh $D/net.orig\nsystemctl daemon-reload\n[ -e /sys/class/net/$IF ] && %s", pathNetDropIn(pt), pathNetShow)
	} else {
		b.WriteString("systemctl daemon-reload\n$D/net.sh live\n")
	}
	b.WriteString("echo TP-NET-DONE\n")
	return b.String()
}

// pathNetMSSRule is the Iran side's MSS rule for a path's interface in the switcher's chain.
func pathNetMSSRule(chain, ifc string, mss int) string {
	tgt := "--clamp-mss-to-pmtu"
	if mss > 0 {
		tgt = "--set-mss " + strconv.Itoa(mss)
	}
	return fmt.Sprintf("iptables -w -t mangle -A %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS %s\n", chain, ifc, tgt)
}

// pathNetMSSLive swaps the path's MSS rule in the running switcher's chain (when it runs).
func pathNetMSSLive(t *Tunnel, ifc string, mss int) string {
	ch := "TPM_" + hsTag(t)
	return fmt.Sprintf(`if iptables -w -t mangle -S %[1]s >/dev/null 2>&1; then
iptables -w -t mangle -S %[1]s | grep -E -- "-o %[2]s( |$)" | grep TCPMSS | sed 's/^-A /-D /' | while read -r r; do eval iptables -w -t mangle $r; done
%[3]secho "mss %[2]s: $(iptables -w -t mangle -S %[1]s | grep -E -- "-o %[2]s( |$)" | grep -o 'set-mss [0-9]*\|clamp-mss-to-pmtu' | head -1)"
fi
`, ch, ifc, pathNetMSSRule(ch, ifc, mss))
}

// setPathNet stores key's settings copy-on-write (zero removes them); inside store.Update.
func (t *Tunnel) setPathNet(key string, n PathNet) {
	nm := make(map[string]PathNet, len(t.PathNet)+1)
	for k, v := range t.PathNet {
		nm[k] = v
	}
	if n.zero() {
		delete(nm, key)
	} else {
		nm[key] = n
	}
	if len(nm) == 0 {
		nm = nil
	}
	t.PathNet = nm
}

// pathOf is t's path (method|family), stored as now.
func (a *App) pathOf(t *Tunnel, key string) (HSPath, bool) {
	var out HSPath
	found := false
	a.store.View(func(*State) {
		for _, p := range t.Paths {
			if p.Method+"|"+p.Family == key {
				out, found = p, true
			}
		}
	})
	return out, found
}

// SavePathNet validates, stores and applies a path's kernel settings. Result: "job" when the
// servers are changed now, "note" otherwise.
func (a *App) SavePathNet(t *Tunnel, key string, in map[string]string, reset bool) (map[string]string, int, error) {
	mid, fam, ok := hsPathArg(key)
	if !ok {
		return nil, 400, fmt.Errorf("bad path")
	}
	p, found := a.pathOf(t, key)
	if !found {
		return nil, 404, fmt.Errorf("this tunnel has no %s (%s) path", methodTitle(mid), fam)
	}
	m := methodByID[mid]
	var pt *Tunnel
	var old PathNet
	a.store.View(func(*State) { pt, old = pathTunnel(t, p), t.PathNet[key] })
	ifc := l3Iface(m, pt)
	if ifc == "" {
		return nil, 400, fmt.Errorf("%s forwards ports in user space — it has no network interface of its own; the kernel settings that affect it are the servers' (Servers → ⚡ Optimize)", p.label())
	}
	var n PathNet
	if !reset {
		var err error
		if n, err = parsePathNet(in, fam, methodField(m, "mtu") != nil); err != nil {
			return nil, 400, err
		}
	}
	if n == old {
		return map[string]string{"ok": "1", "note": "Saved — nothing changed."}, 200, nil
	}
	if id := a.jobs.running(t.ID); id != "" {
		return nil, 409, fmt.Errorf("A job is still running on this tunnel — wait for it to end (or cancel it), then save again. Nothing was changed.")
	}
	var active string
	_ = a.store.Update(func(*State) error {
		t.setPathNet(key, n)
		t.Updated = time.Now().Unix()
		active = t.Active
		return nil
	})
	out := map[string]string{"ok": "1"}
	if active == "" || !t.HotStandby || p.Failed != "" {
		out["note"] = "Saved — used when this path starts next."
		return out, 200, nil
	}
	j, err := a.jobs.start(t.ID, "pathnet:"+key)
	if err != nil {
		out["note"] = "Saved, but not applied: " + err.Error()
		return out, 200, nil
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(5 * time.Minute)
		defer cancel()
		a.pathNetApply(ctx, j, t, p, ifc, old, n)
	}()
	out["job"] = j.ID
	return out, 200, nil
}

// hsBestOther is the working path, other than those in skip, the users would go to: the
// lowest latency among the ones that answer ("" = none).
func hsBestOther(v *hsView, skip map[string]bool) string {
	if v == nil {
		return ""
	}
	best, bestRTT := "", 1<<30
	for k, key := range v.Keys {
		if skip[key] || k >= len(v.OK) || !v.OK[k] {
			continue
		}
		r := 1 << 29 // answers, latency not measured: after the measured ones
		if k < len(v.RTT) && v.RTT[k] >= 0 {
			r = v.RTT[k]
		}
		if r < bestRTT {
			best, bestRTT = key, r
		}
	}
	return best
}

// hsStepAside moves the users off the paths in mine (to the best other working path) when
// they are on one of them; the returned func puts them back as they were (their choice, or
// auto's pick). moved=false: they weren't on mine, or no other path answers.
func (a *App) hsStepAside(ctx context.Context, j *Job, ir Host, t *Tunnel, mine map[string]bool, why string) (restore func(), users string, moved bool) {
	var oldPin, own string
	var auto bool
	a.store.View(func(*State) { oldPin, own, auto = t.HSPin, t.Active+"|"+t.Family, t.HSAuto })
	users, _, v := a.optPathsState(ctx, ir, t)
	if v == nil {
		v = a.hsViewOf(t.ID)
	}
	restore = func() {}
	if !mine[users] {
		return restore, users, false
	}
	other := hsBestOther(v, mine)
	if other == "" {
		j.log("the users are on %s and no other path answers now — %s", users, why)
		return restore, users, false
	}
	j.log("the users are on %s — moving them to %s (the best other working path) meanwhile", users, other)
	if msg, err := a.hsPinTo(ctx, t, other); err != nil {
		j.log("  WARN: %v — going on with the users on it", err)
		return restore, users, false
	} else {
		j.log("  %s", msg)
	}
	restore = func() {
		back := oldPin
		if auto && users != oldPin && !(oldPin == "" && users == own) {
			back = users
		}
		j.log("moving the users back to %s", users)
		if msg, err := a.hsPinTo(ctx, t, back); err != nil {
			j.log("  WARN: %v", err)
		} else {
			j.log("  %s", msg)
		}
		if back != oldPin {
			_ = a.store.Update(func(*State) error { t.HSPin = oldPin; return nil })
		}
	}
	return restore, users, true
}

// pathNetApply changes a running path's interface on both servers in place.
func (a *App) pathNetApply(ctx context.Context, j *Job, t *Tunnel, p HSPath, ifc string, old, n PathNet) {
	key := p.Method + "|" + p.Family
	j.log("%s: kernel settings %s → %s — changed live on both servers, nothing restarts; the other paths are not touched", p.label(), pathNetDesc(old), pathNetDesc(n))
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		j.log("ERROR: Iran server not found")
		j.finish("error")
		return
	}
	ir, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		j.log("ERROR: the Iran server can't be reached now (%v) — saved; it is set when the path starts next", err)
		j.finish("error")
		return
	}
	kh, _, err := a.foreignHost(ctx, t, nil)
	if err != nil {
		j.log("ERROR: the foreign server can't be reached now (%v) — saved; it is set when the path starts next", err)
		j.finish("error")
		return
	}
	restore, _, _ := a.hsStepAside(ctx, j, ir, t, map[string]bool{key: true}, "changed in place (no restart, open connections stay)")
	var pt *Tunnel
	a.store.View(func(*State) { pt = pathTunnel(t, p) })
	files := map[string]FileSpec{}
	if !n.zero() {
		files = pathNetFiles(pt, ifc, n)
	}
	var errs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range []struct {
		label string
		h     Host
	}{{"KH", kh}, {"IR", ir}} {
		wg.Add(1)
		go func(label string, h Host) {
			defer wg.Done()
			script := pathNetLive(pt, ifc, old, n)
			if label == "IR" && old.MSS != n.MSS {
				script = pathNetMSSLive(t, ifc, n.MSS) + script
			}
			out, err := runWithFiles(ctx, h, files, script, quietFiles(func(l string) {
				if l = strings.TrimSpace(l); l != "" && l != "TP-NET-DONE" {
					j.log("[%s] %s", label, l)
				}
			}))
			mu.Lock()
			defer mu.Unlock()
			if err != nil || !strings.Contains(out, "TP-NET-DONE") {
				errs = append(errs, fmt.Sprintf("%s: %v", label, pnErr(err)))
			}
		}(s.label, s.h)
	}
	wg.Wait()
	sort.Strings(errs)
	okNow, v := a.optWait(ctx, ir, t, []string{key})
	restore()
	switch {
	case len(errs) > 0:
		j.log("✕ not set everywhere: %s — saved as you set it; Re-apply sets it again", strings.Join(errs, "; "))
		j.finish("error")
	case okNow[key]:
		j.log("  ✓ %s answers with these settings (%s)", key, optPathStat(v, key))
		j.log("DONE — %s runs with %s", p.label(), pathNetDesc(n))
		j.finish("ok")
	default:
		j.log("  ✕ %s doesn't answer with these settings: %s — kept as you set them; ↺ Defaults puts the interface back", key, optWhy(v, key, ""))
		j.log("FAILING — the users stay on a working path")
		a.pushTInfo(t, fmt.Sprintf("⚠ %s: %s doesn't answer with the kernel settings you set (%s) — kept as you set them; users stay on a working path", t.Name, p.label(), pathNetDesc(n)))
		j.finish("error")
	}
}

func pnErr(err error) string {
	if err != nil {
		return err.Error()
	}
	return "didn't finish"
}

// pathNetDesc is "MTU 1400, MSS 1360, queue 1000, qdisc fq" ("defaults" when nothing is set).
func pathNetDesc(n PathNet) string {
	var s []string
	if n.MTU > 0 {
		s = append(s, fmt.Sprintf("MTU %d", n.MTU))
	}
	if n.MSS > 0 {
		s = append(s, fmt.Sprintf("MSS %d", n.MSS))
	}
	if n.TxQLen > 0 {
		s = append(s, fmt.Sprintf("queue %d", n.TxQLen))
	}
	if n.Qdisc != "" {
		s = append(s, "qdisc "+n.Qdisc)
	}
	if len(s) == 0 {
		return "defaults"
	}
	return strings.Join(s, ", ")
}

// PathNetSide is what one server runs with now, for the panel.
type PathNetSide struct {
	Side    string `json:"side"` // ir | kh
	Name    string `json:"name"`
	Err     string `json:"err,omitempty"`
	IfUp    bool   `json:"ifUp"`
	MTU     string `json:"mtu,omitempty"`
	TxQLen  string `json:"txqlen,omitempty"`
	Qdisc   string `json:"qdisc,omitempty"`
	MSS     string `json:"mss,omitempty"` // the switcher's rule for the path (Iran)
	CC      string `json:"cc,omitempty"`
	DefQd   string `json:"defQdisc,omitempty"`
	RMem    string `json:"rmem,omitempty"`
	WMem    string `json:"wmem,omitempty"`
	CTCount string `json:"ctCount,omitempty"`
	CTMax   string `json:"ctMax,omitempty"`
}

// pathNetInfoScript reads the interface (ifc "" = none) and the server-wide settings.
func pathNetInfoScript(t *Tunnel, ifc string, iran bool) string {
	var b strings.Builder
	if ifc != "" {
		fmt.Fprintf(&b, `IF=%s
if [ -e /sys/class/net/$IF ]; then echo "IF 1 $(cat /sys/class/net/$IF/mtu) $(cat /sys/class/net/$IF/tx_queue_len) $(tc qdisc show dev $IF 2>/dev/null | awk 'NR==1{print $2}')"; else echo "IF 0"; fi
`, ifc)
		if iran {
			fmt.Fprintf(&b, "echo \"MSS $(iptables -w -t mangle -S TPM_%s 2>/dev/null | grep -E -- \"-o $IF( |$)\" | grep -o 'set-mss [0-9]*\\|clamp-mss-to-pmtu' | head -1)\"\n", hsTag(t))
		}
	}
	b.WriteString(`echo "CC $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
echo "QD $(sysctl -n net.core.default_qdisc 2>/dev/null)"
echo "RM $(sysctl -n net.core.rmem_max 2>/dev/null) $(sysctl -n net.core.wmem_max 2>/dev/null)"
echo "CT $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -) $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo -)"
`)
	return b.String()
}

func parsePathNetInfo(out string, s *PathNetSide) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		at := func(i int) string {
			if i < len(f) {
				return f[i]
			}
			return ""
		}
		switch f[0] {
		case "IF":
			s.IfUp = at(1) == "1"
			s.MTU, s.TxQLen, s.Qdisc = at(2), at(3), at(4)
		case "MSS":
			s.MSS = strings.Join(f[1:], " ")
		case "CC":
			s.CC = at(1)
		case "QD":
			s.DefQd = at(1)
		case "RM":
			s.RMem, s.WMem = at(1), at(2)
		case "CT":
			s.CTCount, s.CTMax = at(1), at(2)
		}
	}
}

// PathNetInfo: the path's interface name ("" = it has none) and what both servers run with.
func (a *App) PathNetInfo(ctx context.Context, t *Tunnel, key string) (map[string]any, int, error) {
	mid, _, ok := hsPathArg(key)
	if !ok {
		return nil, 400, fmt.Errorf("bad path")
	}
	p, found := a.pathOf(t, key)
	if !found {
		return nil, 404, fmt.Errorf("this tunnel has no such path")
	}
	var pt *Tunnel
	a.store.View(func(*State) { pt = pathTunnel(t, p) })
	ifc := l3Iface(methodByID[mid], pt)
	sides := []PathNetSide{{Side: "ir"}, {Side: "kh"}}
	var wg sync.WaitGroup
	for i := range sides {
		wg.Add(1)
		go func(s *PathNetSide) {
			defer wg.Done()
			var h Host
			var err error
			if s.Side == "ir" {
				srv := a.store.Server(t.ServerID)
				if srv == nil {
					s.Err = "server not found"
					return
				}
				s.Name = srv.Name
				h, _, err = a.reach(ctx, srv, nil)
			} else {
				if f := a.store.Server(t.ForeignID); f != nil {
					s.Name = f.Name
				}
				h, _, err = a.foreignHost(ctx, t, nil)
			}
			if err != nil {
				s.Err = err.Error()
				return
			}
			out, err := h.Run(ctx, pathNetInfoScript(t, ifc, s.Side == "ir"), nil)
			if err != nil && out == "" {
				s.Err = err.Error()
				return
			}
			parsePathNetInfo(out, s)
		}(&sides[i])
	}
	wg.Wait()
	return map[string]any{"iface": ifc, "sides": sides}, 200, nil
}

// tunnelPathNet: POST {ID, Path, Net{mtu,mss,txqlen,qdisc}, Reset} → {job} | {note}.
func (s *Server2) tunnelPathNet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID, Path string
		Net      map[string]string
		Reset    bool
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	t := s.ownTunnel(r, in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	res, code, err := s.app.SavePathNet(t, in.Path, in.Net, in.Reset)
	if err != nil {
		httpErr(w, code, err.Error())
		return
	}
	writeJSON(w, res)
}

// tunnelPathNetInfo: POST {ID, Path} → {iface, sides}.
func (s *Server2) tunnelPathNetInfo(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Path string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	t := s.ownTunnel(r, in.ID)
	if t == nil {
		httpErr(w, 404, "tunnel not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	res, code, err := s.app.PathNetInfo(ctx, t, in.Path)
	if err != nil {
		httpErr(w, code, err.Error())
		return
	}
	writeJSON(w, res)
}

// ownTunnel is tunnel id when the signed-in account may see it (the guard checked too).
func (s *Server2) ownTunnel(r *http.Request, id string) *Tunnel {
	t := s.app.store.Tunnel(id)
	if t == nil {
		return nil
	}
	user, admin := s.who(r)
	owner := ""
	s.app.store.View(func(*State) { owner = t.Owner })
	if !visible(user, admin, owner) {
		return nil
	}
	return t
}
