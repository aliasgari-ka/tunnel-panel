package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A hot-standby path that started fine and then went down was left down for good: the
// hourly retry (hsretry.go) only takes paths that failed to start, the rebuild only runs
// when every path is down, and Repair leaves a dead standby path alone while the users are
// fine. Seen live 2026-11-11: every Backhaul Premium ipx path stopped (its carrier was
// redirected by another program's firewall rule) and its core kept running, passing
// nothing; once the cause was gone, only a restart of that core brought it back. So the
// monitor restarts the core of a path that has been down for hsKickAfter, on both
// servers. It is never the path the users are on, and nothing else is touched. A path that
// stays down after a restart waits twice as long each time, up to hsKickMax (a route that
// never passes it doesn't get its core restarted every hour forever).
const (
	hsKickAfter = 30 * time.Minute
	hsKickEvery = time.Hour
	hsKickMax   = 24 * time.Hour
)

// hsKick: when the panel last restarted a down path, and how many times in a row.
type hsKick struct {
	at time.Time
	n  int
}

// hsKickDue lists the paths of t to restart now: down for hsKickAfter by the switcher's
// clock, not the users' path, and past their back-off. A path that is up again forgets
// its restarts.
func (a *App) hsKickDue(t *Tunnel, v *hsView, now time.Time) []HSPath {
	if v == nil || len(v.Keys) != len(v.OK) || len(v.Keys) != len(v.Changed) {
		return nil
	}
	var running string
	var paths []HSPath
	a.store.View(func(*State) {
		if t.HotStandby && t.Active != "" {
			paths = hsGood(t)
		}
		running = t.Applying
	})
	if len(paths) == 0 || running != "" {
		return nil
	}
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	if a.hsKicks == nil {
		a.hsKicks = map[string]hsKick{}
	}
	var due []HSPath
	for k, key := range v.Keys {
		id := t.ID + "|" + key
		if v.OK[k] {
			delete(a.hsKicks, id)
			continue
		}
		if k == v.Active || v.Changed[k] <= 0 || now.Unix()-v.Changed[k] < int64(hsKickAfter/time.Second) {
			continue
		}
		if kk, ok := a.hsKicks[id]; ok && now.Before(kk.at.Add(hsKickGap(kk.n))) {
			continue
		}
		for _, p := range paths {
			if p.Method+"|"+p.Family == key {
				due = append(due, p)
			}
		}
	}
	return due
}

// hsKickGap is how long a path waits after its n-th restart in a row.
func hsKickGap(n int) time.Duration {
	g := hsKickEvery
	for i := 1; i < n && g < hsKickMax; i++ {
		g *= 2
	}
	if g > hsKickMax {
		g = hsKickMax
	}
	return g
}

// hsKickNoted records a restart of path key of t (by the monitor or an Apply) and says how
// many there were in a row.
func (a *App) hsKickNoted(t *Tunnel, key string, now time.Time) int {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	if a.hsKicks == nil {
		a.hsKicks = map[string]hsKick{}
	}
	kk := a.hsKicks[t.ID+"|"+key]
	kk.at, kk.n = now, kk.n+1
	a.hsKicks[t.ID+"|"+key] = kk
	return kk.n
}

// hsRestartScript restarts a path's unit when this server has one.
func hsRestartScript(t *Tunnel, p HSPath) string {
	u := unitName(&Tunnel{ID: t.ID + "x" + strconv.Itoa(p.Index)}) // as hsWhyScript names it
	return fmt.Sprintf("systemctl cat %[1]s >/dev/null 2>&1 || { echo TP-NO-UNIT; exit 0; }\nsystemctl restart %[1]s && echo TP-RESTARTED\n", u)
}

// hsRestartPath restarts only path p's cores on both servers (foreign first: the Iran side
// then meets a fresh peer). The switcher, the other paths and the users are left alone.
func (a *App) hsRestartPath(ctx context.Context, t *Tunnel, p HSPath) error {
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return fmt.Errorf("Iran server not found")
	}
	kh, _, kerr := a.foreignHost(ctx, t, nil)
	ir, _, ierr := a.reach(ctx, srv, nil)
	var errs []string
	for _, s := range []struct {
		side string
		h    Host
		err  error
	}{{"foreign server", kh, kerr}, {"Iran server", ir, ierr}} {
		if s.err != nil || s.h == nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s.side, s.err))
			continue
		}
		out, err := s.h.Run(ctx, hsRestartScript(t, p), nil)
		if !strings.Contains(out, "TP-RESTARTED") && !strings.Contains(out, "TP-NO-UNIT") {
			errs = append(errs, fmt.Sprintf("%s: restart failed: %v %s", s.side, err, strings.TrimSpace(lastLine(out))))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// hsKickPaths restarts the due paths of t (go'd by the monitor).
func (a *App) hsKickPaths(t *Tunnel, v *hsView, due []HSPath) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	users := "—"
	if v != nil && v.Active >= 0 && v.Active < len(v.Paths) {
		users = v.Paths[v.Active]
	}
	for _, p := range due {
		key := p.Method + "|" + p.Family
		var since int64
		for k, kk := range v.Keys {
			if kk == key && k < len(v.Changed) {
				since = v.Changed[k]
			}
		}
		n := a.hsKickNoted(t, key, time.Now())
		err := a.hsRestartPath(ctx, t, p)
		down := time.Since(time.Unix(since, 0)).Round(time.Minute)
		switch {
		case err != nil:
			a.pushTInfo(t, fmt.Sprintf("⚠ %s: %s has been down %s — restarting its core failed: %v", t.Name, p.label(), shortDur(down), err))
		case n == 1:
			// told once per run of restarts: a route that never passes the path stays quiet
			a.pushTInfo(t, fmt.Sprintf("🔁 %s: %s was down %s — restarted only its core on both servers; the users stay on %s", t.Name, p.label(), shortDur(down), users))
		}
	}
}

// hsOrderByKeys puts good in the switcher's order (keys, "method|family" each). A key that
// is no longer among the panel's paths (dropped while the old switcher still runs) keeps
// its place with a bare path; no keys (an old switcher) leaves good as it is.
func (a *App) hsOrderByKeys(t *Tunnel, good []HSPath, keys []string) []HSPath {
	if len(keys) == 0 {
		return good
	}
	same := len(keys) == len(good)
	for k := 0; same && k < len(keys); k++ {
		same = keys[k] == good[k].Method+"|"+good[k].Family
	}
	if same {
		return good
	}
	var all []HSPath
	a.store.View(func(*State) { all = append([]HSPath(nil), t.Paths...) })
	out := make([]HSPath, 0, len(keys))
	for _, key := range keys {
		f := strings.SplitN(key, "|", 2)
		p := HSPath{Method: f[0]}
		if len(f) == 2 {
			p.Family = f[1]
		}
		for _, q := range append(append([]HSPath(nil), good...), all...) {
			if q.Method+"|"+q.Family == key {
				p = q
				break
			}
		}
		out = append(out, p)
	}
	return out
}

var hsRefusedPinRe = regexp.MustCompile(`\bpath (\d+) chosen in the panel doesn't answer`)

// hsRefusedPin: the index of the chosen path a "keep" event says didn't answer, or -1.
func hsRefusedPin(e string) int {
	f := strings.Fields(e)
	if len(f) < 4 || f[1] != "keep" {
		return -1
	}
	m := hsRefusedPinRe.FindStringSubmatch(e)
	if m == nil {
		return -1
	}
	k, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return k
}

// hsPathDown: path (mid, fam) of t as the panel runs it, and whether the switcher last saw
// it down while the users were on another path.
func (a *App) hsPathDown(t *Tunnel, mid, fam string) (HSPath, bool) {
	var p HSPath
	found := false
	a.store.View(func(*State) {
		for _, q := range hsGood(t) {
			if q.Method == mid && q.Family == fam {
				p, found = q, true
			}
		}
	})
	v := a.hsViewOf(t.ID)
	if !found || v == nil {
		return p, false
	}
	for k, key := range v.Keys {
		if key == mid+"|"+fam && k < len(v.OK) {
			return p, !v.OK[k] && k != v.Active
		}
	}
	return p, false
}
