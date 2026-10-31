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

// Usage: how many bytes each tunnel and each server's NIC moved, per hour. Every usageTick
// the live counters (traffic.go) are read once even when no one is looking, and the
// increase since the last read goes into the current hour's bucket. A counter that went
// down was restarted (tunnel restart, reboot): its whole new value is the increase.
// Buckets are kept usageKeep and saved to usage.json, so a panel restart loses at most one tick.

const (
	usageTick = 5 * time.Minute
	usageKeep = 8 * 24 // hours
)

// UsageBytes: Down = towards Iran users (tunnel) / received by the NIC (server); Up the other way.
type UsageBytes struct {
	Down uint64 `json:"d"`
	Up   uint64 `json:"u"`
}

type usageBucket struct {
	Hour    int64                  `json:"h"` // unix, start of the hour
	Tunnels map[string]*UsageBytes `json:"t"`
	Servers map[string]*UsageBytes `json:"s"` // "" = the panel host
}

type usageLast struct {
	D, U uint64
}

type usageLog struct {
	mu      sync.Mutex
	Buckets []*usageBucket        `json:"buckets"`
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
	return u
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

// add records one counter read; the first read of a counter only sets its baseline.
func (u *usageLog) addLocked(b *usageBucket, kind, id string, d, up uint64) {
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
	m := b.Tunnels
	if kind == "s" {
		m = b.Servers
	}
	x := m[id]
	if x == nil {
		x = &UsageBytes{}
		m[id] = x
	}
	x.Down += dd
	x.Up += du
}

func (u *usageLog) bucketLocked(now time.Time) *usageBucket {
	h := now.Truncate(time.Hour).Unix()
	if n := len(u.Buckets); n > 0 && u.Buckets[n-1].Hour == h {
		return u.Buckets[n-1]
	}
	b := &usageBucket{Hour: h, Tunnels: map[string]*UsageBytes{}, Servers: map[string]*UsageBytes{}}
	u.Buckets = append(u.Buckets, b)
	if len(u.Buckets) > usageKeep {
		u.Buckets = u.Buckets[len(u.Buckets)-usageKeep:]
	}
	return b
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
	b := u.bucketLocked(time.Now())
	for _, r := range reads {
		u.addLocked(b, r.kind, r.id, r.d, r.u)
	}
	u.saveLocked()
}

// UsageSum is one tunnel's or server's bytes over the asked window, with its hourly series.
type UsageSum struct {
	ID    string   `json:"id"`
	Down  uint64   `json:"down"`
	Up    uint64   `json:"up"`
	Hours []uint64 `json:"hours"` // down+up per hour, oldest first
}

// usageGet: GET /api/usage?hours=24 — bytes per tunnel and per server over the last hours.
func (s *Server2) usageGet(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if hours <= 0 || hours > usageKeep {
		hours = 24
	}
	user, admin := s.who(r)
	u := s.app.usage
	if u == nil {
		writeJSON(w, map[string]any{"hours": hours, "tunnels": []any{}, "servers": []any{}})
		return
	}
	from := time.Now().Truncate(time.Hour).Add(-time.Duration(hours-1) * time.Hour).Unix()
	tun, srv := map[string]*UsageSum{}, map[string]*UsageSum{}
	put := func(m map[string]*UsageSum, id string, i int, x *UsageBytes) {
		v := m[id]
		if v == nil {
			v = &UsageSum{ID: id, Hours: make([]uint64, hours)}
			m[id] = v
		}
		v.Down += x.Down
		v.Up += x.Up
		v.Hours[i] += x.Down + x.Up
	}
	u.mu.Lock()
	started := u.Started
	for _, b := range u.Buckets {
		if b.Hour < from {
			continue
		}
		i := int((b.Hour - from) / 3600)
		if i >= hours {
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
	list := func(m map[string]*UsageSum) []*UsageSum {
		out := make([]*UsageSum, 0, len(m))
		for _, v := range m {
			out = append(out, v)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Down+out[i].Up > out[j].Down+out[j].Up })
		return out
	}
	writeJSON(w, map[string]any{"hours": hours, "from": from, "started": started, "tick": int(usageTick / time.Second),
		"tunnels": list(tun), "servers": list(srv)})
}
