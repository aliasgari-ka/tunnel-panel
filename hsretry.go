package main

import (
	"fmt"
	"time"
)

// A hot-standby path the apply could not start stays out until the next apply — and an
// apply cuts the users. A reverse method refused because a filter on the way happened to
// drop the foreign server's connections that minute was "failed" for good (seen live:
// England and the outbound tunnel, both fine again the next day). So the monitor tries a
// failed path again every hsRetryEvery while the tunnel is healthy: only that path is
// deployed, the others and their users are left alone (hsUpdatePathsRun with retry).
const hsRetryEvery = time.Hour

// hsRetryDue lists the failed paths of t whose last try is older than hsRetryEvery (a path
// from before the stamp counts as old) and that the route still allows.
func (a *App) hsRetryDue(t *Tunnel, now time.Time) []HSPath {
	var old []HSPath
	a.store.View(func(*State) {
		if !t.HotStandby || t.Active == "" {
			return
		}
		for _, p := range t.Paths {
			if p.Failed != "" && now.Unix()-p.FailedAt >= int64(hsRetryEvery/time.Second) {
				old = append(old, p)
			}
		}
	})
	var due []HSPath
	for _, p := range old {
		if !a.routeSkipped(t.ServerID, t.ForeignID, p.Method, p.Family) {
			due = append(due, p)
		}
	}
	return due
}

// hsRetryFailed tries the failed paths of t again, as one "paths" job (nil: nothing due or
// the tunnel is busy).
func (a *App) hsRetryFailed(t *Tunnel) (*Job, error) {
	old := a.hsRetryDue(t, time.Now())
	if len(old) == 0 {
		return nil, nil
	}
	j, err := a.jobs.start(t.ID, "paths")
	if err != nil {
		return nil, err
	}
	var add []HSPath
	for _, p := range old {
		add = append(add, HSPath{Method: p.Method, Family: p.Family})
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := j.context(20 * time.Minute)
		defer cancel()
		for _, p := range old {
			j.log("%s was refused on this route %s ago (%s) — trying it again; the running paths and their users are left alone", p.label(), time.Since(time.Unix(p.FailedAt, 0)).Round(time.Minute), p.Failed)
		}
		if err := a.hsUpdatePathsRun(ctx, j, t, old, add, true); err != nil {
			j.log("ERROR: %v", err)
			j.finish("failed")
			return
		}
		j.finish("ok")
	}()
	return j, nil
}

func (p HSPath) String() string { return fmt.Sprintf("%s|%s", p.Method, p.Family) }
