package main

import (
	"strconv"
	"strings"
	"time"
)

// autoBench benchmarks every route that carries a running tunnel (Iran server → foreign
// server, per address family) every Settings.AutoBench hours, one at a time on the spare
// benchmark slot, so failover and hot standby always pick from fresh results. A route that
// was benchmarked recently (by hand or here) is left alone, and so is everything while a
// benchmark is already running.
func (a *App) autoBench() {
	time.Sleep(5 * time.Minute) // let the panel settle after a start
	for {
		a.autoBenchRound()
		time.Sleep(10 * time.Minute)
	}
}

func autoBenchEvery(set Settings) time.Duration {
	v := strings.TrimSpace(set.AutoBench)
	if v == "" {
		return 12 * time.Hour
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Hour
}

type benchRoute struct{ iran, foreign, family string }

// dueRoutes lists the routes in use whose newest benchmark is older than every.
func (a *App) dueRoutes(every time.Duration) []benchRoute {
	seen := map[benchRoute]bool{}
	var out []benchRoute
	var ts []*Tunnel
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if t.Active != "" {
				ts = append(ts, t)
			}
		}
	})
	for _, t := range ts {
		for _, f := range a.routeFamilies(t) {
			r := benchRoute{t.ServerID, t.ForeignID, f}
			if seen[r] {
				continue
			}
			seen[r] = true
			last := int64(0)
			a.store.View(func(st *State) {
				for _, h := range st.BenchHistory {
					if h.IranID == r.iran && h.ForeignID == r.foreign && h.Family == r.family && h.At > last {
						last = h.At
					}
				}
			})
			if time.Since(time.Unix(last, 0)) >= every {
				out = append(out, r)
			}
		}
	}
	return out
}

func (a *App) autoBenchRound() {
	every := autoBenchEvery(a.settings())
	if every == 0 {
		return
	}
	for _, r := range a.dueRoutes(every) {
		if a.jobs.running("bench") != "" {
			return // a benchmark (or failback check) is using the slot: next round
		}
		if !a.serverReachable(r.iran) || (r.foreign != "" && !a.serverReachable(r.foreign)) {
			continue // a server is down: nothing useful to measure now
		}
		j, err := a.Bench(BenchRequest{IranID: r.iran, ForeignID: r.foreign, Family: r.family, Seconds: 3})
		if err != nil {
			continue
		}
		for j.snapshot().Status == "running" {
			time.Sleep(10 * time.Second)
		}
	}
}
