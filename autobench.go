package main

import (
	"strconv"
	"strings"
	"time"
)

// autoBench benchmarks the methods running on every route that carries a running tunnel
// (Iran server → foreign server, per address family; see runningMethods — the others aren't
// built just to be measured) every Settings.AutoBench hours, one at a time on the spare
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

// autoBenchMB caps each automatic throughput test (per method, per direction), so the
// periodic benchmark costs the Iran server little traffic: about 2×autoBenchMB per method.
const autoBenchMB = 3

func autoBenchEvery(set Settings) time.Duration {
	v := strings.TrimSpace(set.AutoBench)
	if v == "" {
		return 24 * time.Hour // once a day: hot standby keeps watching the paths in between
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Hour
}

type benchRoute struct{ iran, foreign, family string }

// runningMethods lists the methods the route's tunnels run on the servers now over fam: a
// hot-standby tunnel's paths that came up, a plain tunnel's active method (its backup's while
// on failover). The benchmark measures only these — the ones users actually ride.
func (a *App) runningMethods(iran, foreign, fam string) []string {
	var out []string
	add := func(m string) {
		if m != "" && !contains(out, m) {
			out = append(out, m)
		}
	}
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if t.Active == "" || t.ServerID != iran || t.ForeignID != foreign {
				continue
			}
			if len(t.Paths) > 0 {
				for _, p := range t.Paths {
					if p.Failed == "" && p.Family == fam {
						add(p.Method)
					}
				}
				continue
			}
			if t.Family == fam {
				add(t.Active)
			}
		}
	})
	return out
}

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
			if seen[r] || len(a.runningMethods(r.iran, r.foreign, f)) == 0 {
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
		j, err := a.Bench(BenchRequest{IranID: r.iran, ForeignID: r.foreign, Family: r.family, Running: true, Seconds: 3, MaxMB: autoBenchMB})
		if err != nil {
			continue
		}
		for j.snapshot().Status == "running" {
			time.Sleep(10 * time.Second)
		}
	}
}
