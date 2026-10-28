package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// diagnoseHot is Diagnose for a hot-standby tunnel. Its users never reach the tunnel's own
// unit: the switcher on the Iran server NATs their port into one of the paths (each its own
// unit on both servers) and checks every path against a probe server on the foreign side.
// The checks the single-path Diagnose runs (the tunnel's unit, a listener on the users'
// port, a local connect through it) all fail there by design, so they are not run; what is
// checked instead: both servers' boot time, the switcher and the probe server, every path's
// unit on both sides (running, enabled at boot, its log since boot), the users' NAT, and
// the switcher's own verdict per path.
func (a *App) diagnoseHot(ctx context.Context, j *Job, t *Tunnel, ir, kh Host) {
	problems := 0
	ok := func(f string, x ...any) { j.log("  ✓ "+f, x...) }
	bad := func(f string, x ...any) { problems++; j.log("  ✕ "+f, x...) }
	hint := func(f string, x ...any) { j.log("    → "+f, x...) }
	run := func(h Host, sh string) string { out, _ := h.Run(ctx, sh, nil); return strings.TrimSpace(out) }

	var paths []HSPath
	var name, ports string
	a.store.View(func(*State) { paths, name, ports = append([]HSPath(nil), t.Paths...), t.Name, t.Ports })
	j.log("Diagnosing %s — hot standby, %d paths", name, len(paths))
	sides := []struct {
		n string
		h Host
	}{{"Iran", ir}, {"foreign", kh}}

	// 1. a recent boot explains services that never came back
	j.log("1. servers")
	for _, s := range sides {
		if up, err := strconv.Atoi(run(s.h, "cut -d. -f1 /proc/uptime")); err == nil {
			if up < 3600 {
				j.log("  ! %s server booted %d min ago", s.n, up/60)
			} else {
				ok("%s server up for %s", s.n, shortDur(time.Duration(up)*time.Second))
			}
		}
	}

	// unitCheck reports one unit: running, started at boot, and why not (its log since boot)
	unitCheck := func(side string, h Host, unit, what string) {
		st := lastLine(run(h, "systemctl is-active "+unit+" 2>/dev/null || true"))
		en := lastLine(run(h, "systemctl is-enabled "+unit+" 2>/dev/null || true"))
		switch {
		case st == "active" && en == "enabled":
			ok("%s: %s running", side, what)
		case st == "active":
			bad("%s: %s running but not enabled (%s) — it won't start after a reboot", side, what, orStr(en, "unknown"))
		default:
			bad("%s: %s is %s (%s at boot)", side, what, orStr(st, "missing"), orStr(en, "not installed"))
			for _, l := range strings.Split(run(h, "journalctl -b -u "+unit+" -n 6 --no-pager -o cat 2>/dev/null | sed 's/\\x1b\\[[0-9;]*m//g'"), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					hint("%s", l)
				}
			}
		}
	}

	// 2. the switcher (Iran) and the probe server the checks go to (foreign)
	j.log("2. switcher and probe server")
	hsUnit := unitName(hsUnitTunnel(t))
	unitCheck("Iran", ir, hsUnit, "switcher")
	unitCheck("foreign", kh, hsUnit, "probe server")

	// 3. every path's unit on both servers
	j.log("3. paths")
	for _, p := range paths {
		if p.Failed != "" {
			j.log("  · %s: left out at the last apply — %s", p.label(), firstLine(p.Failed))
			continue
		}
		unit := unitName(pathTunnel(t, p))
		for _, s := range sides {
			unitCheck(s.n, s.h, unit, p.label())
		}
	}

	// 4. the users' port goes into the switcher's selector chain
	j.log("4. users' port %s", ports)
	chain := "TP_" + hsTag(t)
	nat := run(ir, fmt.Sprintf("iptables -w -t nat -S %[1]s 2>/dev/null | grep -c -- '^-A'; iptables -w -t nat -S PREROUTING 2>/dev/null | grep -c -- '-j %[1]s'", chain))
	if f := strings.Fields(nat); len(f) == 2 && f[0] != "0" && f[1] != "0" {
		ok("the users' port is sent to the path the switcher picked (%s rules)", f[0])
	} else {
		bad("the users' port isn't wired to the switcher (no %s rules in nat PREROUTING) — users can't get in", chain)
	}

	// 5. the switcher's own end-to-end verdict on each path (through the tunnel to the probe)
	j.log("5. switcher's checks")
	v, _, err := a.hsRead(ctx, ir, t, 0)
	switch {
	case err != nil:
		bad("can't read the switcher: %v", err)
	default:
		up := 0
		for i, label := range v.Paths {
			state := "✕ fails"
			if i < len(v.OK) && v.OK[i] {
				state, up = "✓ passes", up+1
			}
			on := ""
			if i == v.Active {
				on = "  ← users"
			}
			j.log("  %s %s%s", state, label, on)
		}
		switch {
		case up == 0:
			bad("no path passes: users are cut off")
		case v.Active < 0 || v.Active >= len(v.OK) || !v.OK[v.Active]:
			bad("the users' path fails (the switcher moves them within its grace time)")
		default:
			ok("users are on a working path (%d of %d pass)", up, len(v.Paths))
		}
		// a standby path that fails leaves the users fewer places to go when theirs dies: not
		// a problem today (Repair leaves it alone so as not to cut them), but worth a warning
		if down := len(v.Paths) - up; up > 0 && down > 0 {
			j.log("  ! %d standby path(s) fail the switcher's check — users have fewer paths to fall back on", down)
			hint("applying the tunnel again rebuilds them (users are cut briefly); a method that never passes on this route can be left out of the route's methods")
		}
	}

	// 6. what the counters say right now
	if st := a.Traffic().Tunnels[t.ID]; st != nil && st.Error == "" {
		j.log("6. traffic: ↓ %s ↑ %s now, total ↓ %s ↑ %s", fmtRate(st.Down), fmtRate(st.Up), fmtBytes(st.TotalDown), fmtBytes(st.TotalUp))
	}
	if problems == 0 {
		j.log("DONE — no problem found. If clients still fail, check the client config points at the Iran IP and port %s.", firstPort(ports))
	} else {
		j.log("DONE — %d problem(s) found, see ✕ above", problems)
	}
	j.finish("ok")
}
