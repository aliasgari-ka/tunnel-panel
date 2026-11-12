package main

import (
	"encoding/json"
	"log"
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
// the last read goes into the hour and (Tehran) day buckets, split by time when the interval
// since the last read crosses an hour. A counter that went down was restarted (tunnel
// restart, reboot): its whole new value is the increase. A counter made of parts (cards,
// iptables + ip6tables) is compared part by part, so one part restarting counts only that
// part. Hours are kept usageKeep (hour-by-hour tables), days usageKeepDays; all of it is
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
	// the route each tunnel was counted on ("<iran id>|<foreign id>"), so a tunnel deleted or
	// moved to another server later keeps its share of these hours (buckets from before
	// 2026-11-11 have none: they are priced on the tunnels' routes as the log knows them)
	Pairs map[string]string `json:"tp,omitempty"`
}

type usageLast struct {
	D, U uint64
	// a server's network cards ("eth0+eth1"; another set = a new counter); a tunnel's counter
	// marks ("e:<mark>+<mark>", one per part: another mark = that part was made again from 0)
	Src string      `json:"s,omitempty"`
	P   [][2]uint64 `json:"p,omitempty"` // down/up of each part the totals add up
	At  int64       `json:"a,omitempty"` // when it was read (unix)
}

// usageTun is what the log keeps of a tunnel, so its history is still priced, shown and
// shown to the right account after it was deleted or moved.
type usageTun struct {
	Pair  string `json:"p"` // "<iran id>|<foreign id>"
	Owner string `json:"o,omitempty"`
	Name  string `json:"n,omitempty"`
}

type usageLog struct {
	mu      sync.Mutex
	Buckets []*usageBucket        `json:"buckets"` // hours
	Days    []*usageBucket        `json:"days"`
	Last    map[string]*usageLast `json:"last"` // "t:<id>" / "s:<id>" -> counters at the last read
	Started int64                 `json:"started"`
	Known   map[string]*usageTun  `json:"known,omitempty"` // every tunnel with history: its route, owner, name

	pairNow map[string]string // the running tunnels' routes in the round being booked
	saveErr string            // the last save error, logged once
}

func usagePath() string { return filepath.Join(dataDir, "usage.json") }

// loadUsage reads usage.json, or the copy the last save kept (usage.json.bak) when it is
// missing or damaged. A damaged file is set aside, never written over: it holds the history.
func loadUsage() *usageLog {
	u := &usageLog{Last: map[string]*usageLast{}}
	for _, p := range []string{usagePath(), usagePath() + ".bak"} {
		b, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("usage: cannot read %s: %v", p, err)
			}
			continue
		}
		x := &usageLog{}
		if err := json.Unmarshal(b, x); err != nil {
			bad := p + ".bad-" + time.Now().Format("20060102-150405")
			_ = os.Rename(p, bad)
			log.Printf("usage: %s is damaged (%v): set aside as %s", p, err, bad)
			continue
		}
		u = x
		if p != usagePath() {
			log.Printf("usage: %s was missing or damaged: history taken from %s", usagePath(), p)
		}
		break
	}
	if u.Last == nil {
		u.Last = map[string]*usageLast{}
	}
	if u.Known == nil {
		u.Known = map[string]*usageTun{}
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

// saveLocked writes the log to disk (synced, so a power cut can't leave a half file) and keeps
// the previous one as usage.json.bak.
func (u *usageLog) saveLocked() {
	b, err := json.Marshal(u)
	if err != nil {
		return
	}
	p := usagePath()
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err == nil {
		_, err = f.Write(b)
		if e := f.Sync(); err == nil {
			err = e
		}
		if e := f.Close(); err == nil {
			err = e
		}
	}
	if err == nil {
		if _, e := os.Stat(p); e == nil {
			_ = os.Rename(p, p+".bak")
		}
		err = os.Rename(tmp, p)
	}
	if err != nil {
		if err.Error() != u.saveErr {
			log.Printf("usage: cannot save %s: %v", p, err)
		}
		u.saveErr = err.Error()
		return
	}
	u.saveErr = ""
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
	u.addPartsLocked(now, kind, id, src, d, up, nil)
}

// usageUp is how much a counter grew from old to cur. A single counter that went down was
// restarted: its whole new value is the increase.
func usageUp(old, cur uint64) uint64 {
	if cur < old {
		return cur
	}
	return cur - old
}

// usageSumUp is usageUp for a sum whose parts are not known. A sum that went down may be one
// part restarting while the others run on (one card, the ip6tables chain): its new value is
// then nearly the others' whole lifetime, not an increase. Below half the old value it is
// taken for a whole restart (all parts, or the one that carried most); otherwise only the
// baseline moves and that interval is not counted: losing one tick of one part rather than
// booking again terabytes that were counted already.
func usageSumUp(old, cur uint64) uint64 {
	if cur < old && cur >= old/2 {
		return 0
	}
	return usageUp(old, cur)
}

// usagePartUp is how much one part (down, up) grew. A part restarted when either direction
// went down: both directions then count from zero.
func usagePartUp(old, cur [2]uint64) (uint64, uint64) {
	if cur[0] < old[0] || cur[1] < old[1] {
		return cur[0], cur[1]
	}
	return cur[0] - old[0], cur[1] - old[1]
}

// usageMarks splits a tunnel's counter marks ("e:<m>+<m>", traffic.go); nil when it has none.
func usageMarks(src string) []string {
	if !strings.HasPrefix(src, "e:") {
		return nil
	}
	return strings.Split(src[2:], "+")
}

// usageMarksFit: two reads' marks can be compared part by part.
func usageMarksFit(oe, ne []string, op, np [][2]uint64) bool {
	return len(oe) > 0 && len(oe) == len(ne) && len(op) == len(oe) && len(np) == len(ne)
}

// usageSplitMax: an interval longer than this (the panel was down) is spread over its last
// usageSplitMax seconds only.
const usageSplitMax = 24 * 3600

// addPartsLocked is addSrcLocked with the counter's parts (nil: unknown). Parts are counted
// one by one when the last read had as many; otherwise their sum is (usageSumUp).
func (u *usageLog) addPartsLocked(now time.Time, kind, id, src string, d, up uint64, parts [][2]uint64) {
	key := kind + ":" + id
	l := u.Last[key]
	u.Last[key] = &usageLast{D: d, U: up, Src: src, P: parts, At: now.Unix()}
	if l == nil {
		return
	}
	var dd, du uint64
	restarted := d < l.D || up < l.U
	switch {
	case l.Src != src:
		// a tunnel's counting chains (or its interface) were made again: those parts count
		// from zero, so their whole value is new. Any other change (a card added or gone,
		// the first read with marks) is a new counter: only a new baseline.
		oe, ne := usageMarks(l.Src), usageMarks(src)
		if kind != "t" || !usageMarksFit(oe, ne, l.P, parts) {
			return
		}
		for i, p := range parts {
			if ne[i] != oe[i] {
				dd, du, restarted = dd+p[0], du+p[1], true
				continue
			}
			a, b := usagePartUp(l.P[i], p)
			dd, du = dd+a, du+b
		}
	case len(parts) > 0 && len(parts) == len(l.P):
		for i, p := range parts {
			a, b := usagePartUp(l.P[i], p)
			dd, du = dd+a, du+b
		}
	default:
		dd, du = usageSumUp(l.D, d), usageSumUp(l.U, up)
		if d < l.D/2 || up < l.U/2 { // the whole counter restarted: both directions start again
			dd, du = d, up
		}
	}
	// spread over the hours since the last read by time; a restarted counter's bytes were
	// made after the restart, so they all go to now
	end, from := now.Unix(), l.At
	if restarted || from <= 0 || from >= end || hourStart(time.Unix(from, 0)) == hourStart(now) {
		u.bookLocked(now, kind, id, dd, du)
		return
	}
	if end-from > usageSplitMax {
		from = end - usageSplitMax
	}
	restD, restU := dd, du
	for t := from; t < end; {
		next := min(hourStart(time.Unix(t, 0))+3600, end)
		pd, pu := restD, restU // the last piece takes what is left
		if next < end {
			f := float64(next-t) / float64(end-from)
			pd, pu = min(uint64(float64(dd)*f), restD), min(uint64(float64(du)*f), restU)
		}
		restD, restU = restD-pd, restU-pu
		u.bookLocked(time.Unix(t, 0), kind, id, pd, pu)
		t = next
	}
}

// bookLocked adds bytes to the hour and the day of now.
func (u *usageLog) bookLocked(now time.Time, kind, id string, dd, du uint64) {
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
		if kind == "t" {
			if p := u.pairNow[id]; p != "" {
				if b.Pairs == nil {
					b.Pairs = map[string]string{}
				}
				b.Pairs[id] = p
			}
		}
	}
}

// bucketIn finds or makes the bucket at, keeping the list in time order (a read split over
// two hours books the earlier one when the later may exist already).
func bucketIn(list *[]*usageBucket, at int64, keep int) *usageBucket {
	l := *list
	i := len(l)
	for i > 0 && l[i-1].Hour > at {
		i--
	}
	if i > 0 && l[i-1].Hour == at {
		return l[i-1]
	}
	if i == 0 && len(l) >= keep { // older than all that is kept: a new one would be cut at once
		return l[0]
	}
	b := &usageBucket{Hour: at, Tunnels: map[string]*UsageBytes{}, Servers: map[string]*UsageBytes{}}
	l = append(l, nil)
	copy(l[i+1:], l[i:])
	l[i] = b
	if len(l) > keep {
		l = l[len(l)-keep:]
	}
	*list = l
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
	type rd = usageRead
	var reads []rd
	tm := a.traffic
	tm.mu.Lock()
	fresh := start.Add(-time.Minute).Unix()
	for id, s := range tm.tunnels {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"t", id, s.epoch, s.TotalDown, s.TotalUp, s.parts})
		}
	}
	for id, s := range tm.servers {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"s", id, s.Source, s.TotalDown, s.TotalUp, s.parts})
		}
	}
	for id, s := range tm.peers {
		if s.Error == "" && s.Updated >= fresh {
			reads = append(reads, rd{"p", id, "", s.TotalDown, s.TotalUp, s.parts})
		}
	}
	tm.mu.Unlock()
	pairOf := map[string]string{} // running tunnel -> "<iran>|<foreign>"
	all := map[string]*usageTun{} // every tunnel now
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			all[t.ID] = &usageTun{Pair: t.ServerID + "|" + t.ForeignID, Owner: t.Owner, Name: t.Name}
			if t.Active != "" {
				pairOf[t.ID] = t.ServerID + "|" + t.ForeignID
			}
		}
	})

	u := a.usage
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Started == 0 {
		u.Started = time.Now().Unix()
	}
	u.recordLocked(time.Now(), reads, pairOf)
	u.knowLocked(all)
	u.saveLocked()
}

// renameOwner moves the usage history of deleted tunnels (Known, by owner name) with an
// account renamed to to, or takes it from an account deleted (to = ""): a new account with
// the old name must not see it, and the renamed one must not lose it.
func (u *usageLog) renameOwner(from, to string) {
	if u == nil || from == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	moved := false
	for _, k := range u.Known {
		if k.Owner == from {
			k.Owner, moved = to, true
		}
	}
	if moved {
		u.saveLocked()
	}
}

// knowLocked keeps what the log knows of each tunnel (Known): the ones there are now as they
// are, deleted ones while some kept bucket still has their bytes. A deleted tunnel's last
// counter read is dropped (a tunnel made again with the same id starts a new baseline).
func (u *usageLog) knowLocked(all map[string]*usageTun) {
	if u.Known == nil {
		u.Known = map[string]*usageTun{}
	}
	for id, k := range all {
		u.Known[id] = k
	}
	for key := range u.Last {
		if id, ok := strings.CutPrefix(key, "t:"); ok && all[id] == nil {
			delete(u.Last, key)
		}
	}
	has := map[string]bool{}
	for _, l := range [][]*usageBucket{u.Buckets, u.Days} {
		for _, b := range l {
			for id := range b.Tunnels {
				has[id] = true
			}
		}
	}
	for id := range u.Known {
		if all[id] == nil && !has[id] {
			delete(u.Known, id)
		}
	}
}

// usageStale: a running tunnel not read for this long (its server unreachable, its counters
// broken) no longer holds its route's foreign-server count back.
const usageStale = 15 * 60

// usageRead is one counter read: kind "t" tunnel, "s" server NIC, "p" peer address.
type usageRead struct {
	kind, id, src string
	d, u          uint64
	parts         [][2]uint64 // the counters d/u add up (nil: unknown)
}

// recordLocked adds one round of reads. What comes from a foreign server is counted only
// over an interval its route's running tunnels were all counted in too: a tunnel being
// applied or down is not read, and one re-applied starts its counters again, while the
// address counter runs on — without this the bytes of a whole outage landed in one hour
// against none of the users' (x4.2 on Arshad's route to Germany 1, Nov 8).
//
// A route is counted (its tunnels' reads and its foreign-server read cover the same interval),
// held (a running tunnel missed this read but was read lately: the foreign count keeps its
// last read and is counted with the tunnel's next one — a read cut short loses nothing), or
// started again (a tunnel counted from a new baseline: new, or restarted without a mark that
// says so). A tunnel unread for usageStale is left out: one broken tunnel no longer stopped
// its whole route from being counted.
func (u *usageLog) recordLocked(now time.Time, reads []usageRead, pairOf map[string]string) {
	const pOK, pHold, pRebase = 0, 1, 2
	state := map[string]int{}
	for _, pair := range pairOf {
		state[pair] = pOK
	}
	worse := func(pair string, s int) {
		if s > state[pair] {
			state[pair] = s
		}
	}
	read := map[string]usageRead{}
	for _, r := range reads {
		if r.kind == "t" {
			read[r.id] = r
		}
	}
	for id, pair := range pairOf {
		l := u.Last["t:"+id]
		r, ok := read[id]
		switch {
		case !ok:
			if l != nil && now.Unix()-l.At < usageStale {
				worse(pair, pHold)
			}
		case l == nil:
			worse(pair, pRebase)
		case now.Unix()-l.At >= usageStale:
			// back after a long gap (stopped, unreachable): what the foreign server sent
			// meanwhile was not over a counted interval of this tunnel, even when its new
			// counters look like the old ones made again
			worse(pair, pRebase)
		case l.Src != r.src:
			if !usageMarksFit(usageMarks(l.Src), usageMarks(r.src), l.P, r.parts) {
				worse(pair, pRebase)
			}
		case r.d < l.D || r.u < l.U:
			worse(pair, pRebase)
		}
	}
	u.pairNow = pairOf
	defer func() { u.pairNow = nil }()
	for _, r := range reads {
		if r.kind == "p" {
			s, known := pRebase, false
			if i := strings.LastIndex(r.id, "|"); i > 0 {
				s, known = state[r.id[:i]]
			}
			if l := u.Last["p:"+r.id]; l != nil && now.Unix()-l.At >= usageStale {
				s = pRebase // the address was last read long ago: no interval to count over
			}
			if !known || s == pRebase {
				u.Last["p:"+r.id] = &usageLast{D: r.d, U: r.u, P: r.parts, At: now.Unix()} // a new baseline, nothing counted
				continue
			}
			if s == pHold {
				continue
			}
		}
		u.addPartsLocked(now, r.kind, r.id, r.src, r.d, r.u, r.parts)
	}
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

// dayPaidLocked prices one day bucket. A day the hours still cover is priced hour by hour
// (a day the peer counters started in has measured hours and estimated ones, not one or
// the other); the hours' paid / used is applied to the day's own bytes, as early hours
// were not cut at the same boundaries as the days.
func (u *usageLog) dayPaidLocked(b *usageBucket, pairs map[string][2]string, coef map[string]float64) (map[string]uint64, map[string]bool) {
	paid, est := usagePaidEst(b, pairs, coef)
	if len(u.Buckets) == 0 || u.Buckets[0].Hour > b.Hour {
		return paid, est
	}
	hp, hu, he := map[string]uint64{}, map[string]uint64{}, map[string]bool{}
	for _, h := range u.Buckets {
		if h.Hour >= b.Hour && h.Hour < b.Hour+86400 {
			p, e := usagePaidEst(h, pairs, coef)
			for id, v := range p {
				if x := h.Tunnels[id]; x != nil {
					hp[id] += v
					hu[id] += x.Down + x.Up
					he[id] = he[id] || e[id]
				}
			}
		}
	}
	for id, x := range b.Tunnels {
		if hu[id] > 0 {
			paid[id] = uint64(float64(x.Down+x.Up) * float64(hp[id]) / float64(hu[id]))
			est[id] = he[id]
		}
	}
	return paid, est
}

// usageCoef is each tunnel's measured paid / (download + upload) over the hours that have
// the peer counters — what an estimated hour is priced at.
func usageCoef(hours []*usageBucket, pairs map[string][2]string) map[string]float64 {
	paid, used := map[string]float64{}, map[string]float64{}
	for _, b := range hours {
		p, est := usagePaid(b, pairs)
		for id, v := range p {
			if x := b.Tunnels[id]; x != nil && !est[id] && !usagePaidShort(v, x.Down+x.Up) {
				paid[id] += float64(v)
				used[id] += float64(x.Down + x.Up)
			}
		}
	}
	coef := map[string]float64{}
	for id, n := range used {
		if n >= 1e9 { // at least a GB measured
			coef[id] = paid[id] / n
		}
	}
	return coef
}

// usagePaidEst is usagePaid with an estimated tunnel priced at its measured coefficient
// when it has one: the server's card also carries traffic that is not the tunnels' (another
// panel's tunnels, the server's own), and before 2026-11-06 only one of two cards was read.
func usagePaidEst(b *usageBucket, pairs map[string][2]string, coef map[string]float64) (map[string]uint64, map[string]bool) {
	paid, est := usagePaid(b, pairs)
	for id, x := range b.Tunnels {
		if !est[id] && usagePaidShort(paid[id], x.Down+x.Up) {
			// the foreign-server count missed most of it (2026-11-12: xe108's users went by
			// another path from 11:00 and its route's count fell to ×0.1 while the Iran card
			// still took it all in): estimated, not a total below its traffic
			est[id], paid[id] = true, x.Down+x.Up // priced below at its coefficient when it has one
		}
		if x.Down+x.Up == 0 || (!est[id] && paid[id] > 0) {
			continue
		}
		if c := coef[id]; c > 0 {
			paid[id] = uint64(c * float64(x.Down+x.Up))
			est[id] = true
			continue
		}
		// nothing prices it (a tunnel deleted before its route was kept, or an Iran server
		// with no card count): its users' bytes at ×1, estimated. Leaving it at 0 kept its
		// traffic in the totals but not its pay, so a total came out below every row (×0.96).
		if _, ok := paid[id]; !ok {
			paid[id], est[id] = x.Down+x.Up, true
		}
	}
	return paid, est
}

// usagePaidShort: a measured price well below what the users moved is a count that missed
// the traffic, not a cheap hour — the Iran server takes in at least the users' upload and
// what their downloads came in as. (A small hour is left as measured: its counts are rough.)
func usagePaidShort(paid, used uint64) bool {
	return used >= 256<<20 && float64(paid) < 0.9*float64(used)
}

// usagePaid splits one bucket's paid bytes between the tunnels on it. pairs: tunnel id ->
// [iran id, foreign id] of the tunnels the asker sees and the ones that share their servers.
// With peer counters for the Iran server, a tunnel pays its users' upload plus its share
// (by users' download) of what its foreign server sent; before them (est) its Iran server's
// whole intake is split by the users' total.
//
// A tunnel is priced on the route it was counted on in that bucket (b.Pairs), so moving it
// to another foreign server or deleting it later doesn't change what its past hours cost;
// buckets from before that was kept use pairs. A route with no foreign-server count in the
// bucket (it was started again that hour, or its address counter is new) is estimated.
func usagePaid(b *usageBucket, pairs map[string][2]string) (paid map[string]uint64, est map[string]bool) {
	paid, est = map[string]uint64{}, map[string]bool{}
	hasPeer := map[string]bool{}
	for k := range b.Peers {
		hasPeer[strings.SplitN(k, "|", 2)[0]] = true
	}
	pairOf := map[string][2]string{}
	for id := range b.Tunnels {
		if p, ok := usagePairOf(b, pairs, id); ok {
			pairOf[id] = p
		}
	}
	// only the tunnels in this bucket share it: an idle hour split with tunnels that have no
	// row here gave them shares nothing shows
	pairDown, srvTot := map[string]uint64{}, map[string]uint64{}
	pairN, srvN := map[string]int{}, map[string]int{}
	for id, p := range pairOf {
		x := b.Tunnels[id]
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
	for id, p := range pairOf {
		x := b.Tunnels[id]
		if hasPeer[p[0]] {
			pk := p[0] + "|" + p[1]
			pr := b.Peers[pk]
			if pr == nil { // no count of its foreign server: what its users moved, until a coefficient says better
				paid[id], est[id] = x.Down+x.Up, true
				continue
			}
			paid[id] = x.Up + share(pr.Down, x.Down, pairDown[pk], pairN[pk])
			continue
		}
		if x.Down+x.Up == 0 { // an idle tunnel pays nothing of its server's card
			continue
		}
		if nic := b.Servers[p[0]]; nic != nil && nic.Down > 0 {
			paid[id] = share(nic.Down, x.Down+x.Up, srvTot[p[0]], srvN[p[0]])
			est[id] = true
		}
	}
	return paid, est
}

// usagePairOf is the route [iran, foreign] a tunnel was counted on in bucket b: as the
// bucket kept it, else pairs (the tunnel now, or as the log knew it).
func usagePairOf(b *usageBucket, pairs map[string][2]string, id string) ([2]string, bool) {
	if s, ok := b.Pairs[id]; ok {
		if i := strings.LastIndex(s, "|"); i >= 0 {
			return [2]string{s[:i], s[i+1:]}, true
		}
	}
	p, ok := pairs[id]
	return p, ok
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
	// from / to (unix seconds): any span — hour by hour while the hours are kept, else day by day
	rf, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	rt, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	user, admin := s.who(r)
	u := s.app.usage
	if u == nil {
		writeJSON(w, map[string]any{"days": days, "tunnels": []any{}, "servers": []any{}})
		return
	}
	now := time.Now()
	n, step, from := 24, int64(3600), hourStart(now)-23*3600
	switch {
	case rf > 0 && rt > rf:
		if rt > now.Unix() {
			rt = now.Unix()
		}
		if h := hourStart(time.Unix(rf, 0)); h >= hourStart(now)-int64(usageKeep-1)*3600 {
			from, n = h, min(int((rt-h+3599)/3600), usageKeep)
		} else {
			// day by day; a span longer than the days kept keeps its end (it was cut at the
			// end: the latest days went missing)
			step, from = 86400, dayStart(time.Unix(rf, 0))
			last := dayStart(time.Unix(rt-1, 0))
			n = int((last-from)/86400) + 1
			if n > usageKeepDays {
				from, n = last-int64(usageKeepDays-1)*86400, usageKeepDays
			}
		}
		n = max(1, n)
		days = max(1, int(int64(n)*step/86400))
	case date > 0:
		from = dayStart(time.Unix(date, 0))
		days = 1
	case days > 1 && q.Get("hourly") == "1" && days*24 <= usageKeep:
		n, from = days*24, hourStart(now)-int64(days*24-1)*3600
	case days > 1:
		n, step, from = days, 86400, dayStart(now)-int64(days-1)*86400
	}
	// the tunnels' servers as they are now, and deleted ones' as the log knew them (buckets
	// that kept each tunnel's route are priced on that)
	pairs := map[string][2]string{}
	alive := map[string]bool{}
	s.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			pairs[t.ID] = [2]string{t.ServerID, t.ForeignID}
			alive[t.ID] = true
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
	known := map[string]usageTun{}
	for id, k := range u.Known {
		known[id] = *k
		if _, ok := pairs[id]; !ok {
			if i := strings.LastIndex(k.Pair, "|"); i >= 0 {
				pairs[id] = [2]string{k.Pair[:i], k.Pair[i+1:]}
			}
		}
	}
	// a deleted tunnel is shown to the account it was of
	see := map[string]bool{}
	visibleID := func(id string) bool {
		v, ok := see[id]
		if !ok {
			if alive[id] {
				v = s.tunnelVisible(user, admin, id)
			} else {
				v = visible(user, admin, known[id].Owner)
			}
			see[id] = v
		}
		return v
	}
	coef := usageCoef(u.Buckets, pairs)
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
		paid, est := usagePaidEst(b, pairs, coef)
		if step == 86400 {
			paid, est = u.dayPaidLocked(b, pairs, coef)
		}
		for id, x := range b.Tunnels {
			if !visibleID(id) {
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
	// deleted tunnels that have bytes here: their name and route, for the table
	gone := map[string]map[string]string{}
	for id := range tun {
		if !alive[id] {
			k := known[id]
			gone[id] = map[string]string{"name": k.Name, "pair": k.Pair, "owner": k.Owner}
		}
	}
	writeJSON(w, map[string]any{"days": days, "from": from, "to": from + int64(n)*step, "step": step, "n": n,
		"started": started, "tunnels": sorted(tun), "servers": sorted(srv), "gone": gone})
}
