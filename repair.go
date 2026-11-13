package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Repair works in two steps. The check (repairCheck) only reads: for every running tunnel it
// says what is wrong and what Repair would change — each change with its impact (none, a
// brief blip of new connections, or users moved because the tunnel is applied again) and the
// side it touches. The apply (repairRunJob) then does only the items that were chosen,
// checking each tunnel again first: a tunnel that got well meanwhile is left alone, and an
// item that would move users runs only when that was confirmed.
//
// What it fixes: a tunnel that doesn't work is applied again; a hot-standby tunnel with dead
// paths is rebuilt (with the carriers the benchmark found), one that only runs an older
// switcher gets the new one in place; a Golden-GRE tunnel still running an older relay gets
// the current one; units without the Go memory settings get them. Tunnels whose server is
// down are left alone — that is the server, not the tunnel. After an update it runs on its
// own (RepairAuto: by default only the fixes nobody notices; the rest is reported).

const repairJobKey = "repair"

// the kinds of fix
const (
	rkPaths    = "paths"    // paths brought in line with the route's choices
	rkReapply  = "reapply"  // the tunnel is applied again
	rkSwitcher = "switcher" // the switcher (Iran) and probe server (foreign) renewed in place
	rkMemory   = "memory"   // Go memory drop-ins on the units (memtune.go)
)

// impacts on the users
const (
	impNone  = "none"  // nobody notices
	impBlip  = "blip"  // new connections pause about a second, open ones go on
	impUsers = "users" // users are cut or moved while it runs
)

// hsSwitcherVersion marks the switcher script ("# tp-switcher N" line); an older one on a
// server is replaced. Read from the script itself: a copy kept here by hand fell behind
// once, and Repair then left every running switcher on the old logic.
var hsSwitcherVersion = func() string {
	for _, l := range strings.Split(hsSwitcher, "\n") {
		if strings.HasPrefix(l, "# tp-switcher ") {
			return l
		}
	}
	panic("hsSwitcher has no '# tp-switcher N' line")
}()

// RepairItem is one thing Repair would change on a tunnel.
type RepairItem struct {
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	Impact string `json:"impact"` // none | blip | users
	Side   string `json:"side"`   // iran | foreign | both
	Detail string `json:"detail,omitempty"`
	// Ask: why this one waits for the user (only impact users): the panel does the others itself
	Ask string `json:"ask,omitempty"`
	// in a run: done | failed | left, and the error or why it was left
	Status string `json:"status,omitempty"`
	Why    string `json:"why,omitempty"`
}

// RepairTunnel is the check of one tunnel and, in a run, what became of it.
type RepairTunnel struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Owner string       `json:"owner,omitempty"`
	State string       `json:"state"` // ok | fix | skip
	Note  string       `json:"note,omitempty"`
	Items []RepairItem `json:"items,omitempty"`
	// in a run
	Picked []string `json:"picked,omitempty"`
	Result string   `json:"result,omitempty"` // waiting | running | fixed | failed | skipped | fine
	Done   string   `json:"done,omitempty"`   // what was done, or why not
	// the items as the run found them, each with its Status
	Results []RepairItem `json:"results,omitempty"`
}

// RepairRun is one Repair job: the tunnels it covered and how each went.
type RepairRun struct {
	Job     string          `json:"job"`
	Why     string          `json:"why"`
	Auto    bool            `json:"auto,omitempty"`
	By      string          `json:"by,omitempty"`
	Started int64           `json:"started"`
	Ended   int64           `json:"ended,omitempty"`
	Tunnels []*RepairTunnel `json:"tunnels"`
}

// repairState is the run in progress (the page follows it).
type repairState struct {
	mu  sync.Mutex
	cur *RepairRun
	bg  repairBgState // the background run (repair_bg.go)
}

// why an item waits for the admin (RepairItem.Ask): each one cuts or moves users
const (
	askRebuild    = "the whole tunnel is rebuilt: all its paths restart at once and users drop for a moment"
	askSingle     = "this tunnel has a single path: applying it again cuts its users for a moment"
	askRelay      = "the relay is replaced under the running tunnel: users drop for a moment"
	askPathsUsers = "the path the users are on is left out on the route: they are moved to another one"
)

func (rs *repairState) snapshot() *RepairRun {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return copyRun(rs.cur)
}

func copyRun(r *RepairRun) *RepairRun {
	if r == nil {
		return nil
	}
	c := *r
	c.Tunnels = make([]*RepairTunnel, len(r.Tunnels))
	for i, t := range r.Tunnels {
		x := *t
		x.Items = append([]RepairItem(nil), t.Items...)
		x.Picked = append([]string(nil), t.Picked...)
		x.Results = append([]RepairItem(nil), t.Results...)
		c.Tunnels[i] = &x
	}
	return &c
}

// repairEnv is what the apply step needs from the check.
type repairEnv struct {
	ir, kh Host
}

// repairCheck looks at one tunnel and says what Repair would change. It only reads: no job,
// no state change, nothing written on a server.
func (a *App) repairCheck(ctx context.Context, t *Tunnel) (*RepairTunnel, *repairEnv) {
	var name, active, owner string
	var hot bool
	var npaths int
	a.store.View(func(*State) { name, active, owner, hot, npaths = t.Name, t.Active, t.Owner, t.HotStandby, len(t.Paths) })
	rt := &RepairTunnel{ID: t.ID, Name: name, Owner: owner, State: "ok"}
	skip := func(note string) (*RepairTunnel, *repairEnv) {
		rt.State, rt.Note = "skip", note
		return rt, nil
	}
	if active == "" {
		return skip("stopped")
	}
	if a.jobs.running(t.ID) != "" {
		return skip("a job is running on it")
	}
	if !a.serverReachable(t.ServerID) || (t.ForeignID != "" && !a.serverReachable(t.ForeignID)) {
		return skip("a server of it is down — that's the server, not the tunnel")
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return skip("Iran server not found")
	}
	ir, _, err := a.reach(cctx, srv, nil)
	if err != nil {
		return skip("Iran server unreachable: " + err.Error())
	}
	kh, _, err := a.foreignHost(cctx, t, nil)
	if err != nil {
		return skip("foreign server unreachable: " + err.Error())
	}
	env := &repairEnv{ir: ir, kh: kh}
	add := func(kind, text, impact, side string) {
		rt.Items = append(rt.Items, RepairItem{Kind: kind, Text: text, Impact: impact, Side: side})
	}
	ask := func(why string) { rt.Items[len(rt.Items)-1].Ask = why }
	done := func() (*RepairTunnel, *repairEnv) {
		if len(rt.Items) > 0 {
			rt.State = "fix"
		}
		return rt, env
	}

	if hot && npaths > 0 {
		// methods left out (or put back) on the route since the last apply
		if drop, put := a.hsPathDiff(t); len(drop)+len(put) > 0 {
			usersOn := ""
			if v := a.hsViewOf(t.ID); v != nil && v.Active >= 0 && v.Active < len(v.Keys) {
				usersOn = v.Keys[v.Active]
			}
			impact := impBlip // the switcher is renewed; users stay on their path
			var parts []string
			for _, p := range drop {
				parts = append(parts, "− "+p.label())
				if usersOn == "" || p.Method+"|"+p.Family == usersOn {
					impact = impUsers // the users' own path goes (or which one is not known)
				}
			}
			for _, p := range put {
				parts = append(parts, "+ "+p.label())
			}
			add(rkPaths, fmt.Sprintf("paths differ from the route's choices: %d to add, %d to remove", len(put), len(drop)), impact, "both")
			rt.Items[len(rt.Items)-1].Detail = strings.Join(parts, " · ")
			if impact == impUsers {
				ask(askPathsUsers)
			}
			return done() // the rest is looked at again once the paths are in line
		}
	}

	reapply := false
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
		out, rerr := ir.Run(cctx, "echo \"V $(grep -m1 '^# tp-switcher ' "+shq(hsDir(t)+"/switch.sh")+" 2>/dev/null)\"", nil)
		cur, read := "", false
		for _, l := range strings.Split(out, "\n") {
			if x, ok := strings.CutPrefix(strings.TrimRight(l, "\r"), "V"); ok {
				cur, read = strings.TrimSpace(x), true
			}
		}
		old := rerr == nil && read && cur != hsSwitcherVersion
		switcherText := fmt.Sprintf("switcher %s → %s (renewed in place)", switcherVer(cur), switcherVer(hsSwitcherVersion))
		switch {
		case err != nil:
			add(rkReapply, "switcher not running: "+err.Error(), impUsers, "both")
			ask(askRebuild)
			reapply = true
		// only paths that ran and died count: a path whose method never came up on this
		// route (Failed at deploy) rebuilt the tunnel — and cut its users — after every
		// update, without ever coming up either
		case bad > 0 && bad < len(v.OK) && v.Active >= 0 && v.Active < len(v.OK) && v.OK[v.Active]:
			// users are on a working path and the switcher moves them if it dies: rebuilding
			// the whole tunnel for a dead standby path would cut them for nothing (seen live:
			// xe108 rebuilt after every update because one path never passes data there).
			// An older switcher is still renewed — in place, nobody is cut
			rt.Note = fmt.Sprintf("%d of %d standby paths down — users are on a working one; no rebuild", bad, len(v.OK))
			if old {
				add(rkSwitcher, switcherText, impBlip, "both")
			}
		case bad > 0:
			add(rkReapply, fmt.Sprintf("%d of %d paths down — the tunnel is applied again", bad, len(v.OK)+failedPaths), impUsers, "both")
			ask(askRebuild)
			reapply = true
		case old:
			add(rkSwitcher, switcherText, impBlip, "both")
		}
	} else {
		irs, khs, link := a.Health(cctx, t)
		if text, side := healthItem(irs, khs, link, unitName(t)); text != "" {
			add(rkReapply, text+" — the tunnel is applied again", impUsers, side)
			ask(askSingle)
			reapply = true
		}
	}
	if !reapply && len(rt.Items) == 0 && (active == "golden" || active == "icmp") {
		for _, s := range []struct {
			label, side string
			h           Host
		}{{"Iran", "iran", ir}, {"foreign", "foreign", kh}} {
			if got := a.relaySrcOutdated(cctx, s.h); got != "" {
				add(rkReapply, fmt.Sprintf("Golden-GRE relay outdated on the %s server (%s → %s) — the tunnel is applied again", s.label, short8(got), short8(goldenRelaySrc)), impUsers, s.side)
				ask(askRelay)
				reapply = true
				break
			}
		}
	}
	if !reapply {
		// a working tunnel whose units predate the Go memory settings gets them (memtune.go):
		// units users are on take them at their next restart, so nobody is cut
		if irN, khN := a.memTuneNeed(cctx, t, ir, kh); irN+khN > 0 {
			side := "both"
			if khN == 0 {
				side = "iran"
			} else if irN == 0 {
				side = "foreign"
			}
			add(rkMemory, fmt.Sprintf("Go memory settings missing on %d unit(s)", irN+khN), impNone, side)
		}
	}
	return done()
}

// healthItem turns a Health result into what is wrong and on which side ("" = healthy).
func healthItem(ir, kh, link, unit string) (string, string) {
	switch {
	case ir == "unreachable":
		return "Iran server unreachable", "iran"
	case ir != "active":
		return "unit " + unit + " " + ir + " on the Iran server", "iran"
	case kh == "unreachable":
		return "foreign server unreachable", "foreign"
	case kh != "active":
		return "unit " + unit + " " + kh + " on the foreign server", "foreign"
	case link == "down":
		return "tunnel link down (no traffic between the servers)", "both"
	}
	return "", ""
}

// switcherVer: "# tp-switcher 13" → "v13" ("v?" when there is none).
func switcherVer(line string) string {
	if v := strings.TrimSpace(strings.TrimPrefix(line, "# tp-switcher ")); v != "" && v != line {
		return "v" + v
	}
	return "v?"
}

func short8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// repairCheckAll checks these tunnels a few at a time (nil: every running one).
func (a *App) repairCheckAll(ctx context.Context, ts []*Tunnel) []*RepairTunnel {
	out := make([]*RepairTunnel, len(ts))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, t := range ts {
		wg.Add(1)
		go func(i int, t *Tunnel) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], _ = a.repairCheck(ctx, t)
		}(i, t)
	}
	wg.Wait()
	return out
}

// runningTunnels lists the running tunnels (ids nil) or those of ids that exist, in the
// panel's order.
func (a *App) runningTunnels(ids []string) []*Tunnel {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var ts []*Tunnel
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if (ids == nil && t.Active != "") || want[t.ID] {
				ts = append(ts, t)
			}
		}
	})
	return ts
}

// repairApplyOne checks t again and does the items allow lets through. It returns the
// result (fine, fixed, failed, skipped), what was done or why not, and each item's outcome.
func (a *App) repairApplyOne(ctx context.Context, j *Job, t *Tunnel, allow func(RepairItem) (bool, string)) (string, string, []RepairItem) {
	rt, env := a.repairCheck(ctx, t)
	switch {
	case rt.State == "skip":
		j.log("· %s: %s — left alone", rt.Name, rt.Note)
		return "skipped", rt.Note, nil
	case len(rt.Items) == 0:
		j.log("· %s: fine", rt.Name)
		return "fine", "nothing to fix any more", nil
	}
	var res []RepairItem
	mark := func(it RepairItem, status, why string) {
		it.Status, it.Why = status, why
		res = append(res, it)
	}
	var did, failed, left []string
	reapplied := false
	for _, it := range rt.Items {
		if ok, why := allow(it); !ok {
			j.log("· %s: %s — not done (%s)", rt.Name, it.Text, why)
			left = append(left, it.Text+" ("+why+")")
			mark(it, "left", why)
			continue
		}
		if reapplied && it.Kind != rkReapply {
			mark(it, "done", "applied again")
			continue // applied again: the rest is new anyway
		}
		j.log("· %s: %s", rt.Name, it.Text)
		var err error
		switch it.Kind {
		case rkPaths:
			err = a.repairPaths(ctx, t)
		case rkReapply:
			err = a.repairReapply(ctx, j, t)
			reapplied = err == nil
		case rkSwitcher:
			err = a.repairSwitcher(ctx, j, t, env)
		case rkMemory:
			cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			n := a.memTune(cctx, j, t, env.ir, env.kh)
			cancel()
			if n == 0 {
				err = fmt.Errorf("no unit took the memory settings")
			}
		}
		if err != nil {
			j.log("  ✕ %v", err)
			failed = append(failed, it.Text+": "+err.Error())
			mark(it, "failed", err.Error())
			continue
		}
		j.log("  ✓ done")
		did = append(did, it.Text)
		mark(it, "done", "")
	}
	switch {
	case len(failed) > 0:
		return "failed", strings.Join(append(failed, did...), "; "), res
	case len(did) > 0:
		s := strings.Join(did, "; ")
		if len(left) > 0 {
			s += " · left: " + strings.Join(left, "; ")
		}
		return "fixed", s, res
	}
	return "skipped", strings.Join(left, "; "), res
}

func (a *App) repairPaths(ctx context.Context, t *Tunnel) error {
	pj, err := a.hsUpdatePaths(t)
	if err != nil {
		return fmt.Errorf("path update: %w", err)
	}
	for pj != nil && pj.snapshot().Status == "running" && ctx.Err() == nil {
		time.Sleep(2 * time.Second)
	}
	if pj != nil && pj.snapshot().Status != "ok" {
		return fmt.Errorf("path update %s%s", pj.snapshot().Status, lastError(pj.snapshot().Lines))
	}
	return nil
}

func (a *App) repairReapply(ctx context.Context, j *Job, t *Tunnel) error {
	rj, err := a.rebuildMode(t) // not ApplyRoute: on hot standby that can be only a switch to a dead path
	if err != nil {
		return err
	}
	for rj.snapshot().Status == "running" && ctx.Err() == nil {
		time.Sleep(2 * time.Second)
	}
	if s := rj.snapshot(); s.Status != "ok" {
		return fmt.Errorf("re-apply %s%s", s.Status, lastError(s.Lines))
	}
	return nil
}

// repairSwitcher renews the switcher (Iran) and the probe server (foreign) in place — new
// connections pause for about a second, open ones go on — and the memory settings after it.
func (a *App) repairSwitcher(ctx context.Context, j *Job, t *Tunnel, env *repairEnv) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := a.deploy(cctx, j, "KH", env.kh, hsUnitTunnel(t), hsProbePlan(t)); err != nil {
		return fmt.Errorf("probe server: %w", err)
	}
	if err := a.deploy(cctx, j, "IR", env.ir, hsUnitTunnel(t), a.hsSwitcherPlan(t, hsGood(t))); err != nil {
		return fmt.Errorf("switcher: %w", err)
	}
	return nil
}

// lastError is ": <the last ERROR line of a job>" ("" when there is none).
func lastError(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if k := strings.Index(lines[i], "ERROR"); k >= 0 {
			return ": " + lines[i][k:]
		}
	}
	return ""
}

// repairRunJob starts a Repair job over ts. allow decides each item (and says why not); by is
// the account that started it ("" = the panel itself).
func (a *App) repairRunJob(why, by string, auto bool, ts []*Tunnel, picked map[string][]string, allow func(t *Tunnel, it RepairItem) (bool, string)) (*Job, error) {
	return a.repairRun(why, by, auto, ts, picked, allow, nil)
}

// repairRun is repairRunJob; a sink, when given, gets the finished run instead of the admin
// chat and LastRepair (the background run, repair_bg.go).
func (a *App) repairRun(why, by string, auto bool, ts []*Tunnel, picked map[string][]string, allow func(t *Tunnel, it RepairItem) (bool, string), sink func(*RepairRun)) (*Job, error) {
	j, err := a.jobs.start(repairJobKey, "repair")
	if err != nil {
		return nil, fmt.Errorf("a repair is already running")
	}
	j.mu.Lock()
	j.Owner = by
	j.mu.Unlock()
	run := &RepairRun{Job: j.ID, Why: why, Auto: auto, By: by, Started: time.Now().Unix()}
	for _, t := range ts {
		var name, owner string
		a.store.View(func(*State) { name, owner = t.Name, t.Owner })
		run.Tunnels = append(run.Tunnels, &RepairTunnel{ID: t.ID, Name: name, Owner: owner, Picked: picked[t.ID], Result: "waiting"})
	}
	a.repair.mu.Lock()
	a.repair.cur = run
	a.repair.mu.Unlock()
	set := func(i int, res, done string, items []RepairItem) {
		a.repair.mu.Lock()
		run.Tunnels[i].Result, run.Tunnels[i].Done, run.Tunnels[i].Results = res, done, items
		a.repair.mu.Unlock()
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(90 * time.Minute)
		defer cancel()
		j.log("%s: %d tunnel(s)", why, len(ts))
		for i, t := range ts {
			if ctx.Err() != nil {
				set(i, "skipped", "cancelled", nil)
				continue
			}
			set(i, "running", "", nil)
			res, done, items := a.repairApplyOne(ctx, j, t, func(it RepairItem) (bool, string) { return allow(t, it) })
			set(i, res, done, items)
		}
		a.repair.mu.Lock()
		run.Ended = time.Now().Unix()
		final := copyRun(run)
		a.repair.mu.Unlock()
		if sink != nil {
			j.log("DONE")
			j.finish("ok")
			sink(final)
			return
		}
		_ = a.store.Update(func(st *State) error { st.LastRepair = final; return nil })
		var fixed, failed, skipped, waiting int
		var b strings.Builder
		for _, x := range final.Tunnels {
			switch x.Result {
			case "fixed":
				fixed++
				b.WriteString("\n✅ " + x.Name + " — " + x.Done)
			case "failed":
				failed++
				b.WriteString("\n❌ " + x.Name + " — " + x.Done)
			case "skipped":
				skipped++
				if strings.Contains(x.Done, "needs your OK") {
					waiting++
					b.WriteString("\n✋ " + x.Name + " — " + x.Done)
				}
			}
		}
		j.log("DONE — %d fixed, %d failed, %d left alone", fixed, failed, skipped)
		j.finish("ok")
		head := fmt.Sprintf("🛠 Repair (%s): %d tunnel(s) checked", why, len(ts))
		if fixed+failed+waiting == 0 {
			head += " — nothing to do"
		}
		if waiting > 0 {
			b.WriteString("\n\nOpen Tunnels → 🛠 Repair in the panel to choose the ones marked ✋.")
		}
		if failed > 0 || waiting > 0 || (auto && updReport.Swap(false)) {
			// (after an automatic update the admin chat hears what was re-applied, even nothing)
			a.push(head + b.String())
		} else {
			a.pushInfo(head + b.String())
		}
	}()
	return j, nil
}

// Repair modes for the automatic run after an update (State.RepairAuto)
const (
	repairAutoSafe = ""    // every fix that cuts nobody (none, blip); the rest is reported as needing an OK
	repairAutoAll  = "all" // everything, as Repair did before it asked (users may be moved)
	repairAutoOff  = "off" // nothing; the admin opens Repair
)

// RepairAuto runs Repair over every running tunnel the way the automatic mode says (the
// update hook and the Telegram bot).
func (a *App) RepairAuto(why string) (*Job, error) {
	var mode string
	a.store.View(func(st *State) { mode = st.RepairAuto })
	if mode == repairAutoOff {
		return nil, fmt.Errorf("automatic repair is off")
	}
	return a.repairRunJob(why, "", true, a.runningTunnels(nil), nil, func(t *Tunnel, it RepairItem) (bool, string) {
		return repairAutoAllows(mode, it)
	})
}

// repairAutoAllows: by default the panel does every fix that cuts nobody — the ones nobody
// notices and the ones where only new connections pause about a second (a newer switcher,
// standby paths added or removed while the users stay on theirs). Only what cuts or moves
// users waits for the admin (2026-11-14: the admin found that most items Repair showed
// needed no one's choice).
func repairAutoAllows(mode string, it RepairItem) (bool, string) {
	if mode == repairAutoAll || it.Impact == impNone || it.Impact == impBlip {
		return true, ""
	}
	return false, "needs your OK: " + impactWords(it.Impact)
}

func impactWords(imp string) string {
	switch imp {
	case impBlip:
		return "new connections pause ~1 s"
	case impUsers:
		return "users are cut or moved"
	}
	return "no impact"
}

// RepairPicked runs Repair over the chosen items: picks maps a tunnel to the kinds chosen on
// it; an item that would move users runs only with allowUsers.
func (a *App) RepairPicked(why, by string, picks map[string][]string, allowUsers bool) (*Job, error) {
	var ids []string
	for id := range picks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ts := a.runningTunnels(ids)
	if len(ts) == 0 {
		return nil, fmt.Errorf("no tunnel chosen")
	}
	return a.repairRunJob(why, by, false, ts, picks, func(t *Tunnel, it RepairItem) (bool, string) {
		return repairPickAllows(picks[t.ID], allowUsers, it)
	})
}

func repairPickAllows(kinds []string, allowUsers bool, it RepairItem) (bool, string) {
	chosen := false
	for _, k := range kinds {
		chosen = chosen || k == it.Kind
	}
	switch {
	case !chosen:
		return false, "not chosen"
	case it.Impact == impUsers && !allowUsers:
		return false, "needs your OK: " + impactWords(it.Impact)
	}
	return true, ""
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
		a.pushTInfo(x.t, fmt.Sprintf("🔄 %s was left down by a panel restart in the middle of applying %s — bringing it back", x.t.Name, methodTitle(x.mid)))
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
	go a.repairBgLoop() // and from then on every few hours (repair_bg.go)
	last, running, mode := "", 0, ""
	a.store.View(func(st *State) {
		last, mode = st.LastVersion, st.RepairAuto
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
	if running == 0 || mode == repairAutoOff {
		return // a fresh panel, nothing running, or automatic repair is off
	}
	if _, err := a.RepairAuto("after the update to " + version); err != nil {
		a.push("🛠 the repair after the update could not start: " + err.Error())
	}
}
