package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Usage: how many bytes each tunnel and each server's NIC moved. Every usageTick the live
// counters (traffic.go) are read once even when no one is looking, and the increase since
// the last read goes into the current hour's bucket and the current (Tehran) day's. A
// counter that went down was restarted (tunnel restart, reboot): its whole new value is the
// increase. Hours are kept usageKeep (hour-by-hour tables), days usageKeepDays; all of it is
// saved to usage.json, so a panel restart loses at most one tick.
//
// What costs is what an Iran server receives (Iran's upload is free). Per tunnel that is its
// users' upload plus what its foreign server sent the Iran server (the peer counters,
// traffic.go peerScript) — tunnels of one Iran server to two foreign servers each get their
// own; tunnels sharing one Iran ⇄ foreign pair split it by their users' download.

const (
	usageTick     = 5 * time.Minute
	usageKeep     = 35 * 24 // hours
	usageKeepDays = 400     // days
)

// hours start at Tehran's full hours (it is UTC+3:30, so not at UTC's)
func hourStart(t time.Time) int64 {
	y, m, d := t.In(tehran).Date()
	return time.Date(y, m, d, t.In(tehran).Hour(), 0, 0, 0, tehran).Unix()
}

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
	Servers map[string]*UsageBytes `json:"s"`           // "" = the panel host
	Peers   map[string]*UsageBytes `json:"p,omitempty"` // "<iran id>|<foreign id>": Down = Iran received from it
}

type usageLast struct {
	D, U uint64
	Src  string `json:"s,omitempty"` // a server's network cards ("eth0+eth1"); other set = new counter
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
// sets its baseline. A peer counter ("p") is one per foreign address, kept under
// "<iran>|<foreign>" in the buckets.
func (u *usageLog) addLocked(now time.Time, kind, id string, d, up uint64) {
	u.addSrcLocked(now, kind, id, "", d, up)
}

// addSrcLocked is addLocked for a counter made of parts (src names them): when the parts
// change the read only sets a new baseline.
func (u *usageLog) addSrcLocked(now time.Time, kind, id, src string, d, up uint64) {
	key := kind + ":" + id
	l := u.Last[key]
	u.Last[key] = &usageLast{D: d, U: up, Src: src}
	if l == nil || l.Src != src {
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
		m, bid := b.Tunnels, id
		switch kind {
		case "s":
			m = b.Servers
		case "p":
			if b.Peers == nil {
				b.Peers = map[string]*UsageBytes{}
			}
			m = b.Peers
			if i := strings.LastIndex(id, "|"); i > 0 {
				bid = id[:i]
			}
		}
		addBytes(m, bid, dd, du)
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
	return bucketIn(&u.Buckets, hourStart(now), usageKeep)
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
		kind, id, src string
		d, u          uint64
	}
	var reads []rd
	tm := a.traffic
	tm.mu.Lock()
	fresh := start.Add(-time.Minute).Unix()
	for id, s := range tm.tunnels {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"t", id, "", s.TotalDown, s.TotalUp})
		}
	}
	for id, s := range tm.servers {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"s", id, s.Source, s.TotalDown, s.TotalUp})
		}
	}
	for id, s := range tm.peers {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"p", id, "", s.TotalDown, s.TotalUp})
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
		u.addSrcLocked(now, r.kind, r.id, r.src, r.d, r.u)
	}
	u.saveLocked()
}

// UsageStep is one hour's (or day's) bytes: users' download / upload, and Paid = what the
// Iran server received for it (the tunnels only).
type UsageStep struct {
	Down uint64 `json:"d"`
	Up   uint64 `json:"u"`
	Paid uint64 `json:"p,omitempty"`
}

// UsageSum is one tunnel's or server's bytes over the asked window, with its steps. For a
// server Down/Up are what its network card received / sent; Paid is unused.
type UsageSum struct {
	ID     string      `json:"id"`
	Down   uint64      `json:"down"`
	Up     uint64      `json:"up"`
	Paid   uint64      `json:"paid,omitempty"`
	Est    bool        `json:"est,omitempty"` // some of Paid is estimated (hours before the peer counters)
	Series []UsageStep `json:"series"`
}

// usagePaid splits one bucket's paid bytes between the tunnels on it. pairs: tunnel id ->
// [iran id, foreign id] of the tunnels the asker sees and the ones that share their servers.
// With peer counters for the Iran server, a tunnel pays its users' upload plus its share
// (by users' download) of what its foreign server sent; before them (est) its Iran server's
// whole intake is split by the users' total.
func usagePaid(b *usageBucket, pairs map[string][2]string) (paid map[string]uint64, est map[string]bool) {
	paid, est = map[string]uint64{}, map[string]bool{}
	hasPeer := map[string]bool{}
	for k := range b.Peers {
		hasPeer[strings.SplitN(k, "|", 2)[0]] = true
	}
	pairDown, srvTot := map[string]uint64{}, map[string]uint64{}
	pairN, srvN := map[string]int{}, map[string]int{}
	for id, p := range pairs {
		x := b.Tunnels[id]
		if x == nil {
			x = &UsageBytes{}
		}
		pk := p[0] + "|" + p[1]
		pairDown[pk] += x.Down
		pairN[pk]++
		srvTot[p[0]] += x.Down + x.Up
		srvN[p[0]]++
	}
	share := func(total, part, sum uint64, n int) uint64 {
		if sum == 0 {
			return total / uint64(n)
		}
		return uint64(float64(total) * float64(part) / float64(sum))
	}
	for id, p := range pairs {
		x := b.Tunnels[id]
		if x == nil {
			x = &UsageBytes{}
		}
		if hasPeer[p[0]] {
			pk := p[0] + "|" + p[1]
			var from uint64
			if pr := b.Peers[pk]; pr != nil {
				from = share(pr.Down, x.Down, pairDown[pk], pairN[pk])
			}
			paid[id] = x.Up + from
			continue
		}
		if nic := b.Servers[p[0]]; nic != nil && nic.Down > 0 {
			paid[id] = share(nic.Down, x.Down+x.Up, srvTot[p[0]], srvN[p[0]])
			est[id] = true
		}
	}
	return paid, est
}

// usageGet: GET /api/usage?days=1|7|30[&hourly=1] or ?date=<unix, a Tehran midnight> —
// bytes per tunnel and per server. days=1 and date are hour by hour (the last 24 hours /
// that day); more days are day by day (Tehran days, today included) unless hourly=1
// (hours are kept usageKeep).
func (s *Server2) usageGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 || days > usageKeepDays {
		days = 1
	}
	date, _ := strconv.ParseInt(q.Get("date"), 10, 64)
	user, admin := s.who(r)
	u := s.app.usage
	if u == nil {
		writeJSON(w, map[string]any{"days": days, "tunnels": []any{}, "servers": []any{}})
		return
	}
	now := time.Now()
	n, step, from := 24, int64(3600), hourStart(now)-23*3600
	switch {
	case date > 0:
		from = dayStart(time.Unix(date, 0))
		days = 1
	case days > 1 && q.Get("hourly") == "1" && days*24 <= usageKeep:
		n, from = days*24, hourStart(now)-int64(days*24-1)*3600
	case days > 1:
		n, step, from = days, 86400, dayStart(now)-int64(days-1)*86400
	}
	// the tunnels' servers, as they are now (a tunnel's whole history is counted on them)
	pairs := map[string][2]string{}
	s.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			pairs[t.ID] = [2]string{t.ServerID, t.ForeignID}
		}
	})
	tun, srv := map[string]*UsageSum{}, map[string]*UsageSum{}
	get := func(m map[string]*UsageSum, id string) *UsageSum {
		v := m[id]
		if v == nil {
			v = &UsageSum{ID: id, Series: make([]UsageStep, n)}
			m[id] = v
		}
		return v
	}
	u.mu.Lock()
	started := u.Started
	list := u.Buckets
	if step == 86400 {
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
		paid, est := usagePaid(b, pairs)
		for id, x := range b.Tunnels {
			if !s.tunnelVisible(user, admin, id) {
				continue
			}
			v := get(tun, id)
			v.Down += x.Down
			v.Up += x.Up
			v.Paid += paid[id]
			v.Est = v.Est || est[id]
			st := &v.Series[i]
			st.Down += x.Down
			st.Up += x.Up
			st.Paid += paid[id]
		}
		for id, x := range b.Servers {
			if admin || (id != "" && s.serverVisible(user, admin, id)) {
				v := get(srv, id)
				v.Down += x.Down
				v.Up += x.Up
				v.Series[i].Down += x.Down
				v.Series[i].Up += x.Up
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
	writeJSON(w, map[string]any{"days": days, "from": from, "step": step, "n": n, "started": started,
		"tunnels": sorted(tun), "servers": sorted(srv)})
}
