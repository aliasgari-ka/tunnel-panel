package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Repair in the background: every repairBgEvery the panel runs Repair itself over the running
// tunnels, one tunnel at a time, and does every fix that cuts nobody (repairAutoAllows: the
// ones nobody notices and the ~1 s blip of new connections). What would cut or move users
// stays for the admin in Tunnels → 🛠 Repair. Nothing is said per item: once a day
// (repairSummaryHour, Tehran) the admin chat gets one summary of what was done, what failed
// and what waits — and nothing on a day with none of those.
//
// An item the background run fixed that is back on the same tunnel within repairBgAgain is
// not done again: something keeps undoing it, and doing it over and over would only hide that
// (it waits for the admin with that reason). The automatic mode (RepairAuto) applies here too:
// "off" stops the background run, "all" lets it move users as well.

const (
	repairBgEvery     = 3 * time.Hour
	repairBgFirst     = 20 * time.Minute // after a start: the update's own run (repairAfterUpdate) goes first
	repairBgRetry     = 15 * time.Minute // a repair or update was running: try again then
	repairBgAgain     = 24 * time.Hour
	repairSummaryHour = 9
	repairCameBack    = "came back within a day after the panel fixed it — something undoes it; needs a look"
)

// repairBgState is what the background run remembers (in memory; a restart starts afresh).
type repairBgState struct {
	mu      sync.Mutex
	did     map[string]time.Time // tunnel id|kind → when the background run last did it
	fixed   map[string][]string  // tunnel name → what was done, since the last summary
	failed  map[string][]string
	waiting map[string][]string // tunnel name → what waits for the admin, and why
	sent    string              // the day the summary was last sent (Tehran)
}

func (b *repairBgState) init() {
	if b.did == nil {
		b.did, b.fixed, b.failed, b.waiting = map[string]time.Time{}, map[string][]string{}, map[string][]string{}, map[string][]string{}
	}
}

// repairBgLoop runs the background Repair and sends the daily summary.
func (a *App) repairBgLoop() {
	if version == "dev" {
		return
	}
	time.Sleep(repairBgFirst)
	next := time.Now()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for ; ; <-tick.C {
		now := time.Now()
		if !now.Before(next) {
			if a.repairBgOnce() {
				next = now.Add(repairBgEvery)
			} else {
				next = now.Add(repairBgRetry)
			}
		}
		if msg := a.repair.bg.summary(now); msg != "" {
			a.push(msg)
		}
	}
}

// repairBgOnce starts one background run; false when it couldn't start now (a repair, or an
// update of the panel, is running).
func (a *App) repairBgOnce() bool {
	var mode string
	a.store.View(func(st *State) { mode = st.RepairAuto })
	if mode == repairAutoOff {
		return true
	}
	if a.jobs.running(repairJobKey) != "" {
		return false
	}
	ts := a.runningTunnels(nil)
	if len(ts) == 0 {
		return true
	}
	bg := &a.repair.bg
	_, err := a.repairRun("in the background", "", true, ts, nil, func(t *Tunnel, it RepairItem) (bool, string) {
		return bg.allow(mode, t.ID, it, time.Now())
	}, func(r *RepairRun) {
		if bg.record(r, time.Now()) {
			// the page's "Last run" shows a background run only when it did or found something
			_ = a.store.Update(func(st *State) error { st.LastRepair = r; return nil })
		}
	})
	return err == nil
}

// allow is repairAutoAllows, except an item it already fixed on this tunnel within
// repairBgAgain.
func (b *repairBgState) allow(mode, id string, it RepairItem, now time.Time) (bool, string) {
	if mode == repairAutoOff {
		return false, "automatic repair is off"
	}
	if ok, why := repairAutoAllows(mode, it); !ok {
		return false, why
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	if at, ok := b.did[id+"|"+it.Kind]; ok && now.Sub(at) < repairBgAgain {
		return false, "needs your OK: " + repairCameBack
	}
	return true, ""
}

// record keeps what a finished background run did for the summary; true when it did or found
// anything (a fix, a failure, an item that waits).
func (b *repairBgState) record(r *RepairRun, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	any := false
	for _, t := range r.Tunnels {
		for _, it := range t.Results {
			switch {
			case it.Status == "done":
				b.did[t.ID+"|"+it.Kind] = now
				b.fixed[t.Name] = appendNew(b.fixed[t.Name], it.Text)
				any = true
			case it.Status == "failed":
				b.failed[t.Name] = appendNew(b.failed[t.Name], it.Text+": "+it.Why)
				any = true
			case it.Status == "left" && strings.HasPrefix(it.Why, "needs your OK"):
				why := strings.TrimPrefix(it.Why, "needs your OK: ")
				if it.Ask != "" {
					why = it.Ask
				}
				b.waiting[t.Name] = appendNew(b.waiting[t.Name], it.Text+" — "+why)
				any = true
			}
		}
		if t.Result == "failed" && len(t.Results) == 0 {
			b.failed[t.Name] = appendNew(b.failed[t.Name], t.Done)
			any = true
		}
	}
	return any
}

func appendNew(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

// summary is the day's message once repairSummaryHour has come ("" before that, when it was
// sent today, or when there's nothing to say); what it reports is cleared.
func (b *repairBgState) summary(now time.Time) string {
	t := now.In(tehran)
	day := t.Format("2006-01-02")
	if t.Hour() < repairSummaryHour {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	if b.sent == day {
		return ""
	}
	b.sent = day
	if len(b.fixed)+len(b.failed)+len(b.waiting) == 0 {
		return ""
	}
	var s strings.Builder
	n := func(m map[string][]string) (c int) {
		for _, l := range m {
			c += len(l)
		}
		return c
	}
	fmt.Fprintf(&s, "🛠 Automatic repair, last day: %d fixed", n(b.fixed))
	if k := n(b.failed); k > 0 {
		fmt.Fprintf(&s, ", %d failed", k)
	}
	if k := n(b.waiting); k > 0 {
		fmt.Fprintf(&s, ", %d wait for your OK", k)
	}
	lines := func(icon string, m map[string][]string) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			s.WriteString("\n" + icon + " " + k + " — " + strings.Join(m[k], "; "))
		}
	}
	lines("✅", b.fixed)
	lines("❌", b.failed)
	lines("✋", b.waiting)
	if len(b.waiting) > 0 {
		s.WriteString("\n\nThe ✋ ones: Tunnels → 🛠 Repair in the panel.")
	}
	b.fixed, b.failed, b.waiting = map[string][]string{}, map[string][]string{}, map[string][]string{}
	return s.String()
}
