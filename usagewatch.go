package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Usage watch: a few minutes after every hour closes, the panel checks that the hour adds
// up and tells the admin chat when it doesn't, so a counting fault is seen within the hour
// instead of in the month's bill.
//
//   - an Iran server that counted more from its foreign servers than its network cards
//     received (minus the users' upload, which also arrives on them): bytes counted twice
//   - a tunnel whose paid / (download + upload) left the usual band (it is ×1.01-1.09 on
//     every tunnel): a counter stopped, restarted or doubled
//
// Only hours with at least usageWatchMin bytes are judged; one issue is repeated at most
// every usageWatchRepeat.

const (
	usageWatchMin    = 1e9
	usageWatchRepeat = 6 * time.Hour
)

type usageIssue struct{ key, text string }

// usageWatchCheck judges one hour bucket. names: server and tunnel id -> name.
func usageWatchCheck(b *usageBucket, pairs map[string][2]string, names map[string]string) []usageIssue {
	var out []usageIssue
	from, up := map[string]uint64{}, map[string]uint64{}
	for k, v := range b.Peers {
		from[strings.SplitN(k, "|", 2)[0]] += v.Down
	}
	for id, x := range b.Tunnels {
		if p, ok := usagePairOf(b, pairs, id); ok {
			up[p[0]] += x.Up
		}
	}
	for srv, f := range from {
		nic := b.Servers[srv]
		if nic == nil || nic.Down < usageWatchMin || nic.Down <= up[srv] {
			continue
		}
		if r := float64(f) / float64(nic.Down-up[srv]); r > 1.10 {
			out = append(out, usageIssue{"srv|" + srv, fmt.Sprintf(
				"🔴 %s: از سرورهای خارج %.1f GB شمرده شده ولی کارت شبکه فقط %.1f GB (بدون آپلود کاربران) گرفته — ×%.2f، احتمالاً دوبار شمرده می‌شود",
				names[srv], float64(f)/1e9, float64(nic.Down-up[srv])/1e9, r)})
		}
	}
	paid, est := usagePaid(b, pairs)
	for id, x := range b.Tunnels {
		used := x.Down + x.Up
		if p, _ := usagePairOf(b, pairs, id); est[id] || used < usageWatchMin || p[0] == "" {
			continue
		}
		if c := float64(paid[id]) / float64(used); c > 1.30 || c < 0.80 {
			out = append(out, usageIssue{"tun|" + id, fmt.Sprintf(
				"🟠 تانل %s: ضریب ×%.2f (مصرف کاربران %.1f GB، پولی %.1f GB) — معمولاً ×1.01 تا ×1.09 است",
				names[id], c, float64(used)/1e9, float64(paid[id])/1e9)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func (a *App) usageWatchLoop() {
	sent := map[string]time.Time{}
	for {
		// usageTick after the hour closes, so its last read is in
		next := time.Unix(hourStart(time.Now())+3600, 0).Add(usageTick + time.Minute)
		time.Sleep(time.Until(next))
		hour := hourStart(time.Now()) - 3600
		pairs, names := map[string][2]string{}, map[string]string{}
		a.store.View(func(st *State) {
			for _, s := range st.Servers {
				names[s.ID] = s.Name
			}
			for _, t := range st.Tunnels {
				pairs[t.ID] = [2]string{t.ServerID, t.ForeignID}
				names[t.ID] = t.Name
			}
		})
		u := a.usage
		if u == nil {
			continue
		}
		var issues []usageIssue
		u.mu.Lock()
		for id, k := range u.Known { // deleted tunnels still in this hour
			if _, ok := pairs[id]; !ok {
				if i := strings.LastIndex(k.Pair, "|"); i >= 0 {
					pairs[id] = [2]string{k.Pair[:i], k.Pair[i+1:]}
					names[id] = k.Name
				}
			}
		}
		for _, b := range u.Buckets {
			if b.Hour == hour {
				issues = usageWatchCheck(b, pairs, names)
			}
		}
		u.mu.Unlock()
		now := time.Now()
		var lines []string
		for _, is := range issues {
			if now.Sub(sent[is.key]) >= usageWatchRepeat {
				sent[is.key] = now
				lines = append(lines, is.text)
			}
		}
		if len(lines) > 0 {
			at := time.Unix(hour, 0).In(tehran).Format("15:04")
			a.push("📊 بررسی مصرف — ساعت " + at + " به وقت تهران\n\n" + strings.Join(lines, "\n"))
		}
	}
}
