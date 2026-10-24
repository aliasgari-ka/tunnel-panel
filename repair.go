package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Repair goes over every running tunnel and fixes what can be fixed without asking: a tunnel
// that doesn't work is applied again; a hot-standby tunnel with dead paths is rebuilt (with
// the carriers the benchmark found), one that only runs an older switcher gets the new one in
// place; a Golden-GRE tunnel still running an older relay gets the current one. Tunnels whose
// server is down are left alone — that is the server, not the tunnel. It runs once on its own
// after an update (when the servers have been checked), and from the panel or the bot.

const repairJobKey = "repair"

// hsSwitcherVersion marks the switcher script; an older one on a server is replaced.
const hsSwitcherVersion = "tp-switcher 7"

// Repair starts the repair job.
func (a *App) Repair(why string) (*Job, error) {
	j, err := a.jobs.start(repairJobKey, "repair")
	if err != nil {
		return nil, fmt.Errorf("a repair is already running")
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(90 * time.Minute)
		defer cancel()
		var ts []*Tunnel
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.Active != "" {
					ts = append(ts, t)
				}
			}
		})
		j.log("%s: checking %d running tunnels", why, len(ts))
		var fixed, skipped, failed []string
		for _, t := range ts {
			if ctx.Err() != nil {
				break
			}
			res, what := a.repairOne(ctx, j, t)
			switch res {
			case "fixed":
				fixed = append(fixed, t.Name+" ("+what+")")
			case "failed":
				failed = append(failed, t.Name+" ("+what+")")
			case "skipped":
				skipped = append(skipped, t.Name+" ("+what+")")
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "🛠 Repair (%s): %d tunnels checked", why, len(ts))
		if len(fixed)+len(failed)+len(skipped) == 0 {
			b.WriteString(" — all fine, nothing to do")
		}
		for _, x := range fixed {
			b.WriteString("\n✅ " + x)
		}
		for _, x := range failed {
			b.WriteString("\n❌ " + x)
		}
		for _, x := range skipped {
			b.WriteString("\n⏭ " + x)
		}
		j.log("DONE — %d repaired, %d failed, %d skipped", len(fixed), len(failed), len(skipped))
		j.finish("ok")
		a.push(b.String())
	}()
	return j, nil
}

// repairOne decides about one tunnel: "" (fine), "fixed", "failed" or "skipped", and why.
func (a *App) repairOne(ctx context.Context, j *Job, t *Tunnel) (string, string) {
	var name, active, fam string
	var hot bool
	var npaths int
	a.store.View(func(*State) { name, active, fam, hot, npaths = t.Name, t.Active, t.Family, t.HotStandby, len(t.Paths) })
	if active == "" {
		return "", ""
	}
	if a.jobs.running(t.ID) != "" {
		j.log("· %s: a job is running on it — left alone", name)
		return "skipped", "busy"
	}
	if !a.serverReachable(t.ServerID) || (t.ForeignID != "" && !a.serverReachable(t.ForeignID)) {
		j.log("· %s: a server of it is down — that's the server, not the tunnel; left alone", name)
		return "skipped", "server down"
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return "", ""
	}
	ir, _, err := a.reach(cctx, srv, nil)
	if err != nil {
		j.log("· %s: Iran server unreachable (%v) — left alone", name, err)
		return "skipped", "Iran unreachable"
	}
	kh, _, err := a.foreignHost(cctx, t, nil)
	if err != nil {
		j.log("· %s: foreign server unreachable (%v) — left alone", name, err)
		return "skipped", "foreign unreachable"
	}

	if hot && npaths > 0 {
		// methods left out (or put back) on the route since the last apply
		if drop, add := a.hsPathDiff(t); len(drop)+len(add) > 0 {
			j.log("· %s: paths differ from the route's choices (%d left out, %d put back) — updating them", name, len(drop), len(add))
			pj, err := a.hsUpdatePaths(t)
			if err != nil {
				return "failed", "path update: " + err.Error()
			}
			for pj != nil && pj.snapshot().Status == "running" && ctx.Err() == nil {
				time.Sleep(2 * time.Second)
			}
			if pj != nil && pj.snapshot().Status != "ok" {
				return "failed", "path update " + pj.snapshot().Status
			}
			return "fixed", "paths updated to the route's choices"
		}
	}

	why := ""
	switcherOnly := false
	if hot && npaths > 0 {
		v, _, err := a.hsRead(cctx, ir, t, 0)
		bad := 0
		if v != nil {
			for _, ok := range v.OK {
				if !ok {
					bad++
				}
			}
		}
		failedPaths := 0
		a.store.View(func(*State) {
			for _, p := range t.Paths {
				if p.Failed != "" {
					failedPaths++
				}
			}
		})
		out, _ := ir.Run(cctx, "grep -q "+shq(hsSwitcherVersion)+" "+shq(hsDir(t)+"/switch.sh")+" 2>/dev/null && echo NEW || echo OLD", nil)
		switch {
		case err != nil:
			why = "switcher not running: " + err.Error()
		// only paths that ran and died count: a path whose method never came up on this
		// route (Failed at deploy) rebuilt the tunnel — and cut its users — after every
		// update, without ever coming up either
		case bad > 0 && bad < len(v.OK) && v.Active >= 0 && v.Active < len(v.OK) && v.OK[v.Active]:
			// users are on a working path and the switcher moves them if it dies: rebuilding
			// the whole tunnel for a dead standby path would cut them for nothing (seen live:
			// xe108 rebuilt after every update because one path never passes data there).
			// An older switcher is still renewed — in place, nobody is cut (these tunnels kept
			// the old one through every update, seen live: America, xe108)
			if !strings.Contains(out, "OLD") {
				j.log("· %s: %d of %d standby paths down — users are on a working one; left alone", name, bad, len(v.OK))
				return "", ""
			}
			j.log("· %s: %d of %d standby paths down — users are on a working one; no rebuild", name, bad, len(v.OK))
			why, switcherOnly = "older switcher", true
		case bad > 0:
			why = fmt.Sprintf("%d of %d paths down", bad, len(v.OK)+failedPaths)
		case strings.Contains(out, "OLD"):
			why, switcherOnly = "older switcher", true
		}
	} else {
		if r := healthReason(a.Health(cctx, t)); r != "" {
			why = r
		}
	}
	if why == "" && active == "golden" {
		for _, side := range []struct {
			label string
			h     Host
		}{{"Iran", ir}, {"foreign", kh}} {
			if got := a.relaySrcOutdated(cctx, side.h); got != "" {
				j.log("· %s: the Golden-GRE relay on the %s server is from source %s, this panel's is %s", name, side.label, got, goldenRelaySrc)
				why = "older Golden-GRE relay"
				break
			}
		}
	}
	if why == "" {
		j.log("· %s: fine", name)
		return "", ""
	}

	if switcherOnly {
		// the paths work: only the switcher (Iran) and the probe server (foreign) are renewed,
		// in place — new connections pause for about a second, open ones go on
		j.log("· %s: %s — updating the switcher in place", name, why)
		if err := a.deploy(cctx, j, "KH", kh, hsUnitTunnel(t), hsProbePlan(t)); err != nil {
			j.log("  ✕ probe server: %v", err)
			return "failed", "switcher update: " + err.Error()
		}
		if err := a.deploy(cctx, j, "IR", ir, hsUnitTunnel(t), a.hsSwitcherPlan(t, hsGood(t))); err != nil {
			j.log("  ✕ switcher: %v", err)
			return "failed", "switcher update: " + err.Error()
		}
		j.log("  ✓ switcher updated")
		return "fixed", "switcher updated"
	}

	j.log("· %s: %s — applying %s (%s) again", name, why, methodTitle(active), famName(fam))
	rj, err := a.ApplyRoute(t, active, fam)
	if err != nil {
		j.log("  ✕ %v", err)
		return "failed", err.Error()
	}
	for rj.snapshot().Status == "running" && ctx.Err() == nil {
		time.Sleep(2 * time.Second)
	}
	if s := rj.snapshot(); s.Status != "ok" {
		last := ""
		for i := len(s.Lines) - 1; i >= 0; i-- {
			if strings.Contains(s.Lines[i], "ERROR") {
				last = s.Lines[i][strings.Index(s.Lines[i], "ERROR"):]
				break
			}
		}
		j.log("  ✕ re-apply %s: %s", s.Status, last)
		return "failed", why + " → " + orStr(last, s.Status)
	}
	j.log("  ✓ applied again")
	return "fixed", why
}

// relaySrcOutdated returns the source hash of the relay installed on h when it differs from
// this panel's ("" = current, not installed, or unknown).
func (a *App) relaySrcOutdated(ctx context.Context, h Host) string {
	arch, err := hostArch(ctx, h)
	if err != nil {
		return ""
	}
	if want, err := helperBytes("golden-gre-relay", arch); err != nil || len(want) == 0 {
		return "" // nothing to renew it with
	}
	// the relay's source, not its bytes (golden_src.go). A relay installed before the
	// source was recorded counts as current: the source hasn't changed since then. Only an
	// explicit "SRC <hash>" line counts, so nothing else the shell prints can trip it.
	out, _ := h.Run(ctx, "if [ -x /usr/local/sbin/golden-gre-relay ] && [ -s /usr/local/sbin/golden-gre-relay.src ]; then echo \"SRC $(head -c 64 /usr/local/sbin/golden-gre-relay.src)\"; fi; true", nil)
	for _, l := range strings.Split(out, "\n") {
		if got, ok := strings.CutPrefix(strings.TrimSpace(l), "SRC "); ok {
			if got = strings.TrimSpace(got); got != "" && got != goldenRelaySrc {
				return got
			}
		}
	}
	return ""
}

// resumeInterrupted brings back tunnels an apply had taken down when the panel stopped in
// the middle of it (a restart or an update): they would otherwise stay down, and Repair only
// looks at running tunnels. It waits a little so the servers have been checked first.
func (a *App) resumeInterrupted() {
	type todo struct {
		t        *Tunnel
		mid, fam string
	}
	var ts []todo
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if t.Applying != "" && t.Active == "" {
				ts = append(ts, todo{t, t.Applying, t.Family})
			}
		}
	})
	if len(ts) == 0 {
		return
	}
	time.Sleep(45 * time.Second)
	for _, x := range ts {
		if methodByID[x.mid] == nil || a.jobs.running(x.t.ID) != "" {
			continue
		}
		var still bool
		a.store.View(func(*State) { still = x.t.Applying != "" && x.t.Active == "" })
		if !still {
			continue // started or stopped from the panel meanwhile
		}
		a.pushT(x.t, fmt.Sprintf("🔄 %s was left down by a panel restart in the middle of applying %s — bringing it back", x.t.Name, methodTitle(x.mid)))
		j, err := a.ApplyRoute(x.t, x.mid, x.fam)
		if err != nil {
			a.pushT(x.t, fmt.Sprintf("❌ %s: could not resume %s — %v", x.t.Name, methodTitle(x.mid), err))
			continue
		}
		for j.snapshot().Status == "running" {
			time.Sleep(2 * time.Second) // one at a time
		}
	}
}

// repairAfterUpdate runs Repair once when this version starts for the first time, after
// the server monitor and the health checks had a few minutes to see the servers.
func (a *App) repairAfterUpdate() {
	if version == "dev" {
		return
	}
	last, running := "", 0
	a.store.View(func(st *State) {
		last = st.LastVersion
		for _, t := range st.Tunnels {
			if t.Active != "" {
				running++
			}
		}
	})
	if last == version {
		return
	}
	time.Sleep(4 * time.Minute)
	_ = a.store.Update(func(st *State) error { st.LastVersion = version; return nil })
	if running == 0 {
		return // a fresh panel, or nothing running: nothing to repair
	}
	if _, err := a.Repair("after the update to " + version); err != nil {
		a.push("🛠 the repair after the update could not start: " + err.Error())
	}
}
