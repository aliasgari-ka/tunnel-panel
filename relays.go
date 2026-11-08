package main

// Internal relays (an agent's socks ports gemRelayPort…gemRelayPort+9) are per person: each
// agent machine lets in only the machines of its own person (relay-allow), and a relay of
// another person's machine is taken out of a server's proxy list. A machine added by several
// people (the same IP) belongs to the admin when the admin has it, else to its oldest entry.

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	relayCleanEvery = 6 * time.Hour  // proxy lists are re-read this often (and when a list changed)
	relayAlertEvery = 24 * time.Hour // a failing allow-list update is reported this often per server
	relayParallel   = 6              // servers handled at once
)

// relayOwners: ip -> the person a machine belongs to, over the given servers (admin first, then
// the oldest entry, then the smaller id) and the entry that speaks for it.
func relayOwners(list []*Server) (map[string]string, map[string]*Server) {
	owner := map[string]string{}
	via := map[string]*Server{}
	for _, s := range list {
		if s.IPv4 == "" {
			continue
		}
		cur, ok := via[s.IPv4]
		if !ok || relayWins(s, cur) {
			owner[s.IPv4], via[s.IPv4] = s.Owner, s
		}
	}
	return owner, via
}

func relayWins(s, cur *Server) bool {
	if (s.Owner == "") != (cur.Owner == "") {
		return s.Owner == ""
	}
	if s.CreatedAt != cur.CreatedAt {
		return s.CreatedAt < cur.CreatedAt
	}
	return s.ID < cur.ID
}

// relayAllowLists: the relay allow-list for each agent machine (the id of the entry that speaks
// for it -> sorted IPv4s of its person's agent machines). Other entries of a shared machine get none.
func relayAllowLists(list []*Server) map[string]string {
	owner, via := relayOwners(list)
	ips := map[string][]string{}
	for ip, o := range owner {
		ips[o] = append(ips[o], ip)
	}
	for _, l := range ips {
		sort.Strings(l)
	}
	out := map[string]string{}
	for ip, s := range via {
		out[s.ID] = strings.Join(ips[owner[ip]], "\n")
	}
	return out
}

// relayHost: the host of one prelay entry ("n:host:port", host may be IPv6, bare or in []).
func relayHost(e string) (int, string, bool) {
	e = strings.TrimSpace(e)
	i, j := strings.Index(e, ":"), strings.LastIndex(e, ":")
	if i <= 0 || j <= i {
		return 0, "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(e[:i]))
	if err != nil || n <= 0 {
		return 0, "", false
	}
	h := strings.Trim(strings.TrimSpace(e[i+1:j]), "[]")
	if net.ParseIP(h) == nil {
		return 0, "", false
	}
	return n, net.ParseIP(h).String(), true
}

// foreignRelays: the numbers (highest first, each once) of the proxies in prelay that are relays
// of a machine known to belong to another person than owner. An unknown host is left alone: a
// machine of the same person that is only switched off for a while keeps its relays.
func foreignRelays(prelay, owner string, ipOwner map[string]string) []int {
	seen := map[int]bool{}
	var out []int
	for _, e := range strings.Split(prelay, ",") {
		n, h, ok := relayHost(e)
		if !ok || seen[n] {
			continue
		}
		if o, known := ipOwner[h]; known && o != owner {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

// relayMachines: ip (v4 and v6) -> owner, over every server of the panel (not only the agent
// ones), the same order of precedence as relayOwners.
func relayMachines(all []*Server) map[string]string {
	out := map[string]string{}
	win := map[string]*Server{}
	for _, s := range all {
		for _, ip := range []string{s.IPv4, s.IPv6} {
			p := net.ParseIP(strings.Trim(ip, "[]"))
			if p == nil {
				continue
			}
			k := p.String()
			if cur, ok := win[k]; !ok || relayWins(s, cur) {
				win[k], out[k] = s, s.Owner
			}
		}
	}
	return out
}

// agentLine: the last line of an agent's output for the log — only from the admin's own
// machines; another person's agent is root on its own machine and could put anything there.
func agentLine(s *Server, out string) string {
	if s.Owner != "" {
		return "(output of another person's agent not logged)"
	}
	l := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, lastLineOf(out))
	return clipTo(l, 120)
}

// relayState is what relaySync remembers between rounds.
type relayState struct {
	mu      sync.Mutex
	sent    map[string]string    // server id -> the allow-list it took
	cleaned map[string]time.Time // server id -> its proxy list last checked
	alerted map[string]time.Time // server id -> its failing allow-list last reported
}

func newRelayState() *relayState {
	return &relayState{sent: map[string]string{}, cleaned: map[string]time.Time{}, alerted: map[string]time.Time{}}
}

// relaySync sends each agent machine its allow-list (when it changed) and takes other people's
// relays out of its proxy list (when the list changed, else every relayCleanEvery).
func (a *App) relaySync(list []*Server, st *relayState) {
	var all []*Server
	a.store.View(func(s *State) { all = append(all, s.Servers...) })
	machines := relayMachines(all)
	lists := relayAllowLists(list)
	sem := make(chan struct{}, relayParallel)
	var wg sync.WaitGroup
	for _, s := range list {
		want, ok := lists[s.ID]
		if !ok {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(s *Server, want string) {
			defer func() { <-sem; wg.Done() }()
			a.relaySyncOne(s, want, machines, st)
		}(s, want)
	}
	wg.Wait()
	st.mu.Lock() // forget servers that are gone
	for id := range st.sent {
		if _, ok := lists[id]; !ok {
			delete(st.sent, id)
			delete(st.cleaned, id)
			delete(st.alerted, id)
		}
	}
	st.mu.Unlock()
}

func (a *App) relaySyncOne(s *Server, want string, machines map[string]string, st *relayState) {
	st.mu.Lock()
	changed := st.sent[s.ID] != want
	clean := changed || time.Since(st.cleaned[s.ID]) >= relayCleanEvery
	st.mu.Unlock()
	if changed {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		rc, out := a.igRun(ctx, s, []string{"relay-allow", "-"}, want+"\n", 60, nil)
		cancel()
		st.mu.Lock()
		if rc == 0 {
			st.sent[s.ID] = want
			delete(st.alerted, s.ID)
		}
		alert := rc != 0 && time.Since(st.alerted[s.ID]) >= relayAlertEvery
		if alert {
			st.alerted[s.ID] = time.Now()
		}
		st.mu.Unlock()
		if rc != 0 {
			log.Printf("relay allow-list %s: rc %d: %s", s.Name, rc, agentLine(s, out)) // next round again
			if alert {
				a.pushTo(s.Owner, fmt.Sprintf("🔓 %s: its relay allow-list could not be updated (agent down or too old → Install / update). Until then it keeps its old list, which may let other people's servers use its internal proxies.", igLabel(s)))
			}
			return
		}
	}
	if !clean {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	inf := a.igInfo(ctx, s)
	cancel()
	if inf["rc"] != "0" {
		return
	}
	st.mu.Lock()
	st.cleaned[s.ID] = time.Now()
	st.mu.Unlock()
	del := foreignRelays(inf["prelay"], s.Owner, machines)
	var done []string
	for _, n := range del {
		pn := "proxy" + strconv.Itoa(n)
		var used []string
		for k, v := range inf {
			if v == pn && k != "rc" {
				used = append(used, k)
			}
		}
		sort.Strings(used)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		rc, out := a.igRun(ctx, s, []string{"proxy", "del", strconv.Itoa(n)}, "", 120, nil)
		cancel()
		if rc != 0 {
			log.Printf("relay cleanup %s: proxy %d: rc %d: %s", s.Name, n, rc, agentLine(s, out))
			break
		}
		d := pn
		if len(used) > 0 {
			d += " (used by " + strings.Join(used, ", ") + " → now all proxies)"
		}
		log.Printf("relay cleanup %s: removed %s, a relay of another person's server", s.Name, d)
		done = append(done, d)
	}
	if len(del) > 0 {
		a.igForget(s.ID)
	}
	if len(done) > 0 {
		a.pushTo(s.Owner, fmt.Sprintf("🧹 %s: removed %s — internal relays of another person's server(s), which no longer let it in", igLabel(s), strings.Join(done, "; ")))
	}
}
