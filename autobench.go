package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// autoBench benchmarks the methods running on every route that carries a running tunnel
// (Iran server → foreign server, per address family; see runningMethods) every
// Settings.AutoBench hours, one at a time on the spare benchmark slot. Every autoBenchFull
// such rounds it measures every method instead: failover and hot standby also choose from
// the methods that aren't running (a backup, a method that failed once), and those results
// would otherwise never be refreshed. A route that was benchmarked recently (by hand or
// here) is left alone, and so is everything while a benchmark is already running.
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

// autoBenchFull: a full run (every method) once per this many automatic intervals — weekly
// at the default 24 h. A family nothing runs on gets only these.
const autoBenchFull = 7

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

// dueRoute is a route to benchmark now; full = every method, not only the running ones.
type dueRoute struct {
	benchRoute
	full bool
}

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
				for _, p := range hsGood(t) {
					if p.Family == fam {
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

// routeInUse is a route that carries a running tunnel, with when it was last benchmarked.
type routeInUse struct {
	benchRoute
	last, lastFull int64 // newest run, newest full run (unix; 0 = never)
	running        []string
}

// routesInUse lists the routes the automatic benchmark looks after: every route (per address
// family) of a running tunnel.
func (a *App) routesInUse() []routeInUse {
	seen := map[benchRoute]bool{}
	var out []routeInUse
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
			u := routeInUse{benchRoute: r, running: a.runningMethods(r.iran, r.foreign, f)}
			a.store.View(func(st *State) {
				for _, h := range st.BenchHistory {
					if h.IranID == r.iran && h.ForeignID == r.foreign && h.Family == r.family {
						u.last = max(u.last, h.At)
						if h.Full {
							u.lastFull = max(u.lastFull, h.At)
						}
					}
				}
			})
			out = append(out, u)
		}
	}
	return out
}

// next says when the route is due: the running methods every `every`, every method each
// autoBenchFull×every (or only that, when nothing runs over this family).
func (u routeInUse) next(every time.Duration) (next int64, full bool) {
	nf := u.lastFull + int64((autoBenchFull * every).Seconds())
	if len(u.running) == 0 {
		return nf, true
	}
	nr := u.last + int64(every.Seconds())
	if nf <= nr {
		return nf, true
	}
	return nr, false
}

// dueRoutes lists the routes in use that are due: the running methods when the newest run
// is older than every, every method when the newest full run is older than
// autoBenchFull×every (or nothing runs over that family: there is nothing else to measure).
func (a *App) dueRoutes(every time.Duration) []dueRoute {
	var out []dueRoute
	now := time.Now().Unix()
	for _, u := range a.routesInUse() {
		switch {
		case u.lastFull+int64((autoBenchFull*every).Seconds()) <= now:
			out = append(out, dueRoute{u.benchRoute, true})
		case len(u.running) > 0 && u.last+int64(every.Seconds()) <= now:
			out = append(out, dueRoute{u.benchRoute, false})
		}
	}
	return out
}

// autoBenchTried: when each due route was last started here. A run that measures nothing (every
// method skipped) or cannot start writes no history, so without this the route would be due
// again every round — a probe installed and removed over SSH every 10 minutes.
var autoBenchTried = struct {
	sync.Mutex
	at map[dueRoute]time.Time
}{at: map[dueRoute]time.Time{}}

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
			// a server is down: nothing useful to measure now (said on the page: the route
			// otherwise just looked "due" for as long as the server stayed down)
			a.benchFailed(BenchRequest{IranID: r.iran, ForeignID: r.foreign, Family: r.family, Auto: true}, "skipped by the automatic benchmark: a server of this route is unreachable")
			continue
		}
		autoBenchTried.Lock()
		recent := time.Since(autoBenchTried.at[r]) < every
		if !recent {
			autoBenchTried.at[r] = time.Now()
		}
		autoBenchTried.Unlock()
		if recent {
			continue // started within the interval and still due: it measured nothing
		}
		j, err := a.Bench(BenchRequest{IranID: r.iran, ForeignID: r.foreign, Family: r.family, Running: !r.full, Seconds: 3, MaxMB: autoBenchMB, Auto: true})
		if err != nil {
			continue
		}
		for j.snapshot().Status == "running" {
			time.Sleep(10 * time.Second)
		}
	}
}
