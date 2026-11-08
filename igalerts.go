package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The igproxy agents log a lot (a WARP swapped, a new IP, Google moved...): almost all of it
// they fix by themselves. igAlertLoop reads their logs every igAlertEvery and sends the admin
// one short message with only what a person may need to know: users' Instagram / Gemini path
// broken (and not back within the round), the router down, Instagram or Google left on a proxy
// (not the Instagram test account: the keyless country check does its job). The same alert of a server waits its cooldown before it is
// sent again.

const igAlertEvery = 10 * time.Minute

type igAlertRule struct {
	re   *regexp.Regexp
	key  string
	icon string
	cool time.Duration
}

var igAlertRules = []igAlertRule{
	{regexp.MustCompile(`router DOWN|restarting router`), "router", "🔴", 30 * time.Minute},
	{regexp.MustCompile(`^user path:.*exits themselves fail`), "exits", "🔴", time.Hour},
	{regexp.MustCompile(`firewall rules were missing`), "fw", "⚠️", 6 * time.Hour},
	{regexp.MustCompile(`WARP [0-9]+ still down|no other WARP is up`), "warpdown", "🟠", 3 * time.Hour},
	{regexp.MustCompile(`^Google: no WARP in an allowed country|no allowed WARP left|no other WARP opens Gemini`), "gproxy", "🟠", 6 * time.Hour},
	{regexp.MustCompile(`^Instagram: (no WARP in a music country \(all|no WARP and no proxy|still no WARP)`), "igproxy", "🟠", 6 * time.Hour},
	{regexp.MustCompile(`^Instagram: WARP [0-9]+ is in a music country`), "igback", "✅", 6 * time.Hour},
	{regexp.MustCompile(`no WARP has music AND`), "nomusic", "🟠", 6 * time.Hour},
}

var (
	igPathFailRe = regexp.MustCompile(`^user path check failed: ?([A-Za-z ]+?)(?: \(| ->|$)`)
	igPathOKRe   = regexp.MustCompile(`^user path works again: ?(.+)$`)
)

type igAlertState struct {
	mu      sync.Mutex
	since   map[string]int64     // server id -> time read up to (unix microseconds)
	sent    map[string]time.Time // server id + key -> last sent
	pathBad map[string]bool      // server id + path: a failure was reported, not its recovery
}

// igAlertLines classifies one server's new log lines into what is worth a message.
func (st *igAlertState) igAlertLines(id string, msgs []string, now time.Time) []string {
	var out []string
	fail := map[string]string{} // path -> its line, while it is not back
	for _, m := range msgs {
		if f := igPathFailRe.FindStringSubmatch(m); f != nil {
			for _, p := range strings.Fields(f[1]) {
				fail[p] = m
			}
			continue
		}
		if f := igPathOKRe.FindStringSubmatch(m); f != nil {
			for _, p := range strings.Fields(f[1]) {
				// broken and back within the round: not worth a message — unless a failure was
				// reported in an earlier round: then its recovery is (left unsent, the path stayed
				// "bad" and every later failure of it went unreported)
				delete(fail, p)
				if st.pathBad[id+p] {
					delete(st.pathBad, id+p)
					out = append(out, "✅ "+p+" works again for the users")
				}
			}
			continue
		}
		for _, r := range igAlertRules {
			if !r.re.MatchString(m) {
				continue
			}
			k := id + "/" + r.key
			if t, ok := st.sent[k]; ok && now.Sub(t) < r.cool {
				break
			}
			st.sent[k] = now
			out = append(out, r.icon+" "+clipTo(m, 170))
			break
		}
	}
	paths := make([]string, 0, len(fail))
	for p := range fail {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		k := id + "/path-" + p
		if t, ok := st.sent[k]; st.pathBad[id+p] || (ok && now.Sub(t) < time.Hour) {
			continue
		}
		st.sent[k], st.pathBad[id+p] = now, true
		out = append(out, "❗ "+p+" broken for the users: "+clipTo(fail[p], 150))
	}
	return out
}

func clipTo(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// igLogSince reads the agent's log lines after since (unix microseconds): their times and texts.
func (a *App) igLogSince(ctx context.Context, srv *Server, since int64) ([]int64, []string, error) {
	h, err := a.igHost(ctx, srv)
	if err != nil {
		return nil, nil, err
	}
	// from the start of since's second: a line later in that second was lost when the next
	// read began at the second after it
	out, err := h.Run(ctx, fmt.Sprintf("journalctl -t igproxy --since @%d -o short-unix --no-pager -q 2>/dev/null | tail -n 400", since/1e6), nil)
	if err != nil {
		return nil, nil, err
	}
	ts, ms := igLogParse(out, since)
	return ts, ms, nil
}

// igLogParse: the lines of journalctl -o short-unix after since (unix microseconds).
func igLogParse(out string, since int64) ([]int64, []string) {
	var ts []int64
	var ms []string
	for _, l := range strings.Split(out, "\n") {
		// "1730800000.123456 host igproxy[123]: message"
		f := strings.SplitN(l, " ", 3)
		if len(f) < 3 {
			continue
		}
		sec, frac, _ := strings.Cut(f[0], ".")
		t, e := strconv.ParseInt(sec, 10, 64)
		_, msg, ok := strings.Cut(f[2], ": ")
		if e != nil || !ok {
			continue
		}
		us, _ := strconv.ParseInt((frac + "000000")[:6], 10, 64)
		if t = t*1e6 + us; t <= since {
			continue
		}
		ts = append(ts, t)
		ms = append(ms, strings.TrimSpace(msg))
	}
	return ts, ms
}

func (a *App) igAlertLoop() {
	st := &igAlertState{since: map[string]int64{}, sent: map[string]time.Time{}, pathBad: map[string]bool{}}
	start := time.Now().Add(-igAlertEvery).UnixMicro() // after a panel restart: not the whole old log
	for {
		time.Sleep(igAlertEvery)
		var list []*Server
		a.store.View(func(s *State) {
			for _, x := range s.Servers {
				if x.Igproxy {
					list = append(list, x)
				}
			}
		})
		type res struct {
			srv *Server
			ts  []int64
			ms  []string
		}
		got := make([]res, len(list))
		var wg sync.WaitGroup
		for i, srv := range list {
			st.mu.Lock()
			since, ok := st.since[srv.ID]
			st.mu.Unlock()
			if !ok {
				since = start
			}
			wg.Add(1)
			go func(i int, srv *Server, since int64) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				if ts, ms, err := a.igLogSince(ctx, srv, since); err == nil {
					got[i] = res{srv, ts, ms}
				}
			}(i, srv, since)
		}
		wg.Wait()
		now := time.Now()
		var b strings.Builder
		st.mu.Lock()
		for _, r := range got {
			if r.srv == nil {
				continue
			}
			if n := len(r.ts); n > 0 {
				st.since[r.srv.ID] = r.ts[n-1]
			} else if _, ok := st.since[r.srv.ID]; !ok {
				st.since[r.srv.ID] = start
			}
			if lines := st.igAlertLines(r.srv.ID, r.ms, now); len(lines) > 0 {
				fmt.Fprintf(&b, "\n%s\n  %s\n", igLabel(r.srv), strings.Join(lines, "\n  "))
			}
		}
		st.mu.Unlock()
		if b.Len() > 0 {
			a.push("🛰 WARP / Instagram / Gemini (last 10 min)\n" + b.String())
		}
	}
}
