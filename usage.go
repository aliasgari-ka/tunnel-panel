package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Usage: how many bytes each tunnel and each server's NIC moved. Every usageTick the live
// counters (traffic.go) are read once even when no one is looking, and the increase since
// the last read goes into the current hour's bucket and the current (Tehran) day's. A
// counter that went down was restarted (tunnel restart, reboot): its whole new value is the
// increase. Hours are kept 2 days (the 1-day view), days usageKeepDays (7 / 30 day views);
// all of it is saved to usage.json, so a panel restart loses at most one tick.

const (
	usageTick     = 5 * time.Minute
	usageKeep     = 48  // hours
	usageKeepDays = 400 // days
)

// days start at Tehran's midnight (tehran: servermon.go)
func dayStart(t time.Time) int64 {
	y, m, d := t.In(tehran).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, tehran).Unix()
}

// UsageBytes: Down = towards Iran users (tunnel) / received by the NIC (server); Up the other way.
type UsageBytes struct {
	Down uint64 `json:"d"`
	Up   uint64 `json:"u"`
}

type usageBucket struct {
	Hour    int64                  `json:"h"` // unix, start of the hour (or day)
	Tunnels map[string]*UsageBytes `json:"t"`
	Servers map[string]*UsageBytes `json:"s"` // "" = the panel host
}

type usageLast struct {
	D, U uint64
}

type usageLog struct {
	mu      sync.Mutex
	Buckets []*usageBucket        `json:"buckets"` // hours
	Days    []*usageBucket        `json:"days"`
	Last    map[string]*usageLast `json:"last"` // "t:<id>" / "s:<id>" -> counters at the last read
	Started int64                 `json:"started"`
}

func usagePath() string { return filepath.Join(dataDir, "usage.json") }

func loadUsage() *usageLog {
	u := &usageLog{Last: map[string]*usageLast{}}
	if b, err := os.ReadFile(usagePath()); err == nil {
		_ = json.Unmarshal(b, u)
	}
	if u.Last == nil {
		u.Last = map[string]*usageLast{}
	}
	if len(u.Days) == 0 { // a log from before daily buckets: fold its hours in
		for _, h := range u.Buckets {
			d := u.dayLocked(time.Unix(h.Hour, 0))
			for id, x := range h.Tunnels {
				addBytes(d.Tunnels, id, x.Down, x.Up)
			}
			for id, x := range h.Servers {
				addBytes(d.Servers, id, x.Down, x.Up)
			}
		}
	}
	return u
}

func addBytes(m map[string]*UsageBytes, id string, d, u uint64) {
	x := m[id]
	if x == nil {
		x = &UsageBytes{}
		m[id] = x
	}
	x.Down += d
	x.Up += u
}

func (u *usageLog) saveLocked() {
	b, err := json.Marshal(u)
	if err != nil {
		return
	}
	tmp := usagePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, usagePath())
	}
}

// add records one counter read into the hour and the day; the first read of a counter only
// sets its baseline.
func (u *usageLog) addLocked(now time.Time, kind, id string, d, up uint64) {
	key := kind + ":" + id
	l := u.Last[key]
	u.Last[key] = &usageLast{D: d, U: up}
	if l == nil {
		return
	}
	dd, du := d-l.D, up-l.U
	if d < l.D {
		dd = d
	}
	if up < l.U {
		du = up
	}
	for _, b := range []*usageBucket{u.hourLocked(now), u.dayLocked(now)} {
		m := b.Tunnels
		if kind == "s" {
			m = b.Servers
		}
		addBytes(m, id, dd, du)
	}
}

func bucketIn(list *[]*usageBucket, at int64, keep int) *usageBucket {
	if n := len(*list); n > 0 && (*list)[n-1].Hour == at {
		return (*list)[n-1]
	}
	b := &usageBucket{Hour: at, Tunnels: map[string]*UsageBytes{}, Servers: map[string]*UsageBytes{}}
	*list = append(*list, b)
	if len(*list) > keep {
		*list = (*list)[len(*list)-keep:]
	}
	return b
}

func (u *usageLog) hourLocked(now time.Time) *usageBucket {
	return bucketIn(&u.Buckets, now.Truncate(time.Hour).Unix(), usageKeep)
}

func (u *usageLog) dayLocked(now time.Time) *usageBucket {
	return bucketIn(&u.Days, dayStart(now), usageKeepDays)
}

// usageLoop reads the counters every usageTick for the life of the panel.
func (a *App) usageLoop() {
	time.Sleep(time.Minute) // after the start-up jobs
	for {
		start := time.Now()
		a.trafficCollect()
		a.usageRecord(start)
		time.Sleep(usageTick)
	}
}

// usageRecord takes the totals read since start (a counter that wasn't read — host
// unreachable, tunnel down — keeps its baseline and is counted on its next good read).
func (a *App) usageRecord(start time.Time) {
	type rd struct {
		kind, id string
		d, u     uint64
	}
	var reads []rd
	tm := a.traffic
	tm.mu.Lock()
	fresh := start.Add(-time.Minute).Unix()
	for id, s := range tm.tunnels {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"t", id, s.TotalDown, s.TotalUp})
		}
	}
	for id, s := range tm.servers {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"s", id, s.TotalDown, s.TotalUp})
		}
	}
	tm.mu.Unlock()

	u := a.usage
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Started == 0 {
		u.Started = time.Now().Unix()
	}
	now := time.Now()
	for _, r := range reads {
		u.addLocked(now, r.kind, r.id, r.d, r.u)
	}
	u.saveLocked()
}

// UsageSum is one tunnel's or server's bytes over the asked window, with its series.
type UsageSum struct {
	ID     string   `json:"id"`
	Down   uint64   `json:"down"`
	Up     uint64   `json:"up"`
	Series []uint64 `json:"series"` // down+up per step, oldest first
}

// usageGet: GET /api/usage?days=1|7|30 — bytes per tunnel and per server over the last
// days: 1 day hour by hour (the last 24 hours), more day by day (Tehran days, today included).
func (s *Server2) usageGet(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > usageKeepDays {
		days = 1
	}
	user, admin := s.who(r)
	u := s.app.usage
	if u == nil {
		writeJSON(w, map[string]any{"days": days, "tunnels": []any{}, "servers": []any{}})
		return
	}
	now := time.Now()
	n, step, from := 24, int64(3600), now.Truncate(time.Hour).Add(-23*time.Hour).Unix()
	if days > 1 {
		n, step, from = days, 86400, dayStart(now)-int64(days-1)*86400
	}
	tun, srv := map[string]*UsageSum{}, map[string]*UsageSum{}
	put := func(m map[string]*UsageSum, id string, i int, x *UsageBytes) {
		v := m[id]
		if v == nil {
			v = &UsageSum{ID: id, Series: make([]uint64, n)}
			m[id] = v
		}
		v.Down += x.Down
		v.Up += x.Up
		v.Series[i] += x.Down + x.Up
	}
	u.mu.Lock()
	started := u.Started
	list := u.Buckets
	if days > 1 {
		list = u.Days
	}
	for _, b := range list {
		if b.Hour < from {
			continue
		}
		i := int((b.Hour - from) / step)
		if i >= n {
			continue
		}
		for id, x := range b.Tunnels {
			if s.tunnelVisible(user, admin, id) {
				put(tun, id, i, x)
			}
		}
		for id, x := range b.Servers {
			if admin || (id != "" && s.serverVisible(user, admin, id)) {
				put(srv, id, i, x)
			}
		}
	}
	u.mu.Unlock()
	sorted := func(m map[string]*UsageSum) []*UsageSum {
		out := make([]*UsageSum, 0, len(m))
		for _, v := range m {
			out = append(out, v)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Down+out[i].Up > out[j].Down+out[j].Up })
		return out
	}
	writeJSON(w, map[string]any{"days": days, "from": from, "step": step, "started": started,
		"tunnels": sorted(tun), "servers": sorted(srv)})
}
