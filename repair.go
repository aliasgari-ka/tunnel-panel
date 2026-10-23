package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
const hsSwitcherVersion = "tp-switcher 3"

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
		case bad > 0 || failedPaths > 0:
			why = fmt.Sprintf("%d of %d paths down", bad+failedPaths, len(v.OK)+failedPaths)
		case strings.Contains(out, "OLD"):
			why, switcherOnly = "older switcher", true
		}
	} else {
		if r := healthReason(a.Health(cctx, t)); r != "" {
			why = r
		}
	}
	if why == "" && active == "golden" {
		if old := a.relayOutdated(cctx, ir) || a.relayOutdated(cctx, kh); old {
			why = "older Golden-GRE relay"
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

// relayOutdated: the Golden-GRE relay on h is not the panel's current build.
func (a *App) relayOutdated(ctx context.Context, h Host) bool {
	arch, err := hostArch(ctx, h)
	if err != nil {
		return false
	}
	want, err := helperBytes("golden-gre-relay", arch)
	if err != nil || len(want) == 0 {
		return false
	}
	sum := sha256.Sum256(want)
	out, _ := h.Run(ctx, "sha256sum /usr/local/sbin/golden-gre-relay 2>/dev/null | cut -c1-64", nil)
	got := strings.TrimSpace(lastLine(out))
	return got != "" && got != hex.EncodeToString(sum[:])
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
