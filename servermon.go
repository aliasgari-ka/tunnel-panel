package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // Tehran time even on hosts without a zoneinfo database
)

// The server monitor checks every server every serverEvery: the SSH connection the panel
// already keeps open to it must answer a keepalive, or a live agent must be talking; only
// without one does it connect to the SSH port (a new connection every 10 s made every
// server's sshd fork a child and write two log lines, around the clock — 640 lines an hour
// on the panel host alone, each read by fail2ban too). A family the open connection doesn't
// cover (IPv6 beside a direct IPv4) is connected to once a minute instead. A failed check
// is retried twice a couple of seconds apart, so one lost SYN isn't an outage, but a short
// drop of 10 s still is. Each outage is kept with its exact start and end (also tunnel
// outages, tagged with whether their servers answered at the time), and Telegram hears
// about it when it starts and again when it is over. When the panel host itself can't
// reach the internet, that is logged as the panel's outage, not the servers'.
const (
	serverEvery   = 10 * time.Second
	serverFull    = 6 // rounds between connects to the SSH ports a live connection doesn't cover
	sshTimeout    = 3 * time.Second
	maxOutageLogs = 300 // server, tunnel and panel outages kept
	maxFamilyLogs = 150 // and IPv4-only / IPv6-only ones, apart (trimOutages)
)

// probePlan says which SSH ports this round connects to: a family the panel's own open
// connection already proves (pool4/pool6) never; when the server is known alive some other
// way (another connection, an agent), the rest only on a full round.
func probePlan(pool4, pool6, alive, full bool) (probe4, probe6 bool) {
	return !pool4 && (!alive || full), !pool6 && (!alive || full)
}

// Outage is one stretch of a server or tunnel being unreachable / down.
type Outage struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // server | tunnel | panel
	Target string `json:"target"`
	Name   string `json:"name"`
	Start  int64  `json:"start"`
	End    int64  `json:"end,omitempty"` // 0 = still going on
	Reason string `json:"reason"`
	Cause  string `json:"cause,omitempty"` // tunnels: the servers' state at the time
}

type srvState struct {
	down     bool
	since    time.Time
	outageID string
}

type serverMon struct {
	mu    sync.Mutex
	state map[string]*srvState // server id ("panel" = the panel host's own internet)
	round int                  // rounds so far; every serverFull-th connects to the ports too
}

// tehran is the time zone outages are reported in, and usage hours and days are cut at.
// Iran has had no summer time since 2022: a fixed +3:30, so a server with old time-zone data
// (which still moves clocks in spring) can't shift the hours or make a 23-hour day.
var tehran = time.FixedZone("IRST", 3*3600+1800)

func clock(t time.Time) string { return t.In(tehran).Format("2006-01-02 15:04:05") }

func shortDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func sshAddr(s *Server) string {
	host := orStr(s.SSHHost, orStr(s.IPv4, s.IPv6))
	if host == "" {
		return ""
	}
	port := s.SSHPort
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// tcpUp tries addr up to tries times, pause apart; it reports the time of the first failure.
func tcpUp(addr string, tries int, pause time.Duration) (bool, time.Time) {
	var first time.Time
	for i := 0; i < tries; i++ {
		c, err := net.DialTimeout("tcp", addr, sshTimeout)
		if err == nil {
			c.Close()
			return true, first
		}
		if first.IsZero() {
			first = time.Now()
		}
		if i < tries-1 {
			time.Sleep(pause)
		}
	}
	return false, first
}

func (a *App) addOutage(o Outage) {
	_ = a.store.Update(func(st *State) error {
		var cut int64
		st.Outages, cut = trimOutagesCut(append(st.Outages, o))
		st.OutagesFrom = max(st.OutagesFrom, cut)
		return nil
	})
}

// familyOutage: one address family's SSH down while the other answers — the server is up.
func familyOutage(kind string) bool { return kind == "ssh-v4" || kind == "ssh-v6" }

// trimOutages keeps the newest maxOutageLogs real outages (server, tunnel, panel) and the
// newest maxFamilyLogs IPv4/IPv6-only ones, each counted on its own: one server whose IPv4
// flapped took 176 of the 300 places in a week and pushed the real outages out of the log.
// Open outages are never dropped.
func trimOutages(all []Outage) []Outage {
	out, _ := trimOutagesCut(all)
	return out
}

// trimOutagesCut also says up to when the log is no longer complete: the end of the newest
// server/tunnel/panel outage it dropped (0 = none dropped) — uptime counts from there.
func trimOutagesCut(all []Outage) ([]Outage, int64) {
	var cut int64
	var real, fam int
	for _, o := range all {
		if familyOutage(o.Kind) {
			fam++
		} else {
			real++
		}
	}
	if real <= maxOutageLogs && fam <= maxFamilyLogs {
		return all, 0
	}
	out := make([]Outage, 0, len(all))
	for _, o := range all { // oldest first
		if o.End != 0 {
			if familyOutage(o.Kind) && fam > maxFamilyLogs {
				fam--
				continue
			}
			if !familyOutage(o.Kind) && real > maxOutageLogs {
				real--
				cut = max(cut, o.End)
				continue
			}
		}
		out = append(out, o)
	}
	return out, cut
}

// takeOpenOutages returns the outages of these kinds a restart of the panel left open, for
// the monitor to take up again: the same entry ends when its server or tunnel is back (or
// goes on). Before, a restart closed each one with the restart's time as its end and, when
// the server was still down, the monitor opened a new one and alerted again — one IPv4
// outage of two days was 66 entries, one per restart. Only those keep says are gone (their
// server or tunnel deleted or stopped) are closed now, and a second open entry of a target
// (left by the old way) is closed into the first.
func (a *App) takeOpenOutages(kinds map[string]bool, keep func(st *State, o *Outage) bool) []Outage {
	var out []Outage
	now := time.Now().Unix()
	_ = a.store.Update(func(st *State) error {
		seen := map[string]bool{}
		for i := range st.Outages {
			o := &st.Outages[i]
			if o.End != 0 || !kinds[o.Kind] {
				continue
			}
			if keep(st, o) && !seen[o.Target] {
				seen[o.Target] = true
				out = append(out, *o)
				continue
			}
			o.End = now
			o.Reason += " (panel restarted — end time approximate)"
		}
		return nil
	})
	return out
}

func (a *App) endOutage(id string, end time.Time) {
	_ = a.store.Update(func(st *State) error {
		for i := range st.Outages {
			if st.Outages[i].ID == id {
				st.Outages[i].End = end.Unix()
			}
		}
		return nil
	})
}

// forgetServerMon drops what the monitor keeps of a deleted server: its open outages end
// now (nothing would end them: Clear keeps open ones for good) and its state goes, so a
// server of that id is not taken for down.
func (a *App) forgetServerMon(id string) {
	keys := []string{id, id + "/v4", id + "/v6"}
	if m := a.srvMon; m != nil {
		m.mu.Lock()
		for _, k := range keys {
			delete(m.state, k)
		}
		m.mu.Unlock()
	}
	now := time.Now().Unix()
	_ = a.store.Update(func(st *State) error {
		for i := range st.Outages {
			o := &st.Outages[i]
			if o.End == 0 && (o.Kind == "server" || o.Kind == "ssh-v4" || o.Kind == "ssh-v6") &&
				(o.Target == keys[0] || o.Target == keys[1] || o.Target == keys[2]) {
				o.End = now
				o.Reason += " (server deleted)"
			}
		}
		return nil
	})
}

// serverReachable is the monitor's last word on a server (true when not checked yet).
func (a *App) serverReachable(id string) bool {
	if a.srvMon == nil {
		return true
	}
	a.srvMon.mu.Lock()
	defer a.srvMon.mu.Unlock()
	s := a.srvMon.state[id]
	return s == nil || !s.down
}

func (a *App) serverMonitor() {
	m := &serverMon{state: map[string]*srvState{}}
	a.markOutagesFrom()
	m.resume(a)
	a.srvMon = m
	for {
		a.serverRound(m)
		time.Sleep(serverEvery)
	}
}

// resume takes up the server outages a restart left open (takeOpenOutages): the server is
// taken for down until its first check, which ends the same entry or lets it go on.
func (m *serverMon) resume(a *App) {
	kinds := map[string]bool{"server": true, "ssh-v4": true, "ssh-v6": true, "panel": true}
	open := a.takeOpenOutages(kinds, func(st *State, o *Outage) bool {
		if o.Kind == "panel" {
			return true
		}
		id, _, _ := strings.Cut(o.Target, "/")
		for _, s := range st.Servers {
			if s.ID == id {
				return true
			}
		}
		return false
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range open {
		m.state[o.Target] = &srvState{down: true, since: time.Unix(o.Start, 0), outageID: o.ID}
	}
}

func (a *App) serverRound(m *serverMon) {
	// the panel host's own internet first: if it's gone, nothing below means anything
	netOK, _ := tcpUp("1.1.1.1:443", 1, 0)
	if !netOK {
		netOK, _ = tcpUp("8.8.8.8:53", 2, 2*time.Second)
	}
	a.transition(m, "panel", "panel", "this panel host", !netOK, time.Now(), "the panel host can't reach the internet (1.1.1.1:443, 8.8.8.8:53)")
	if !netOK {
		return
	}
	var servers []*Server
	a.store.View(func(st *State) {
		for _, s := range st.Servers {
			cp := *s
			servers = append(servers, &cp)
		}
	})
	m.mu.Lock()
	m.round++
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range servers {
		addr := sshAddr(s)
		if addr == "" {
			continue
		}
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			a.checkServer(m, s, addr, 2*time.Second)
		}(s)
	}
	wg.Wait()
}

// checkServer checks a server over IPv4 and over IPv6 (when it has both) — the panel's open
// connection answering, else a connect to the SSH port: the server is down only when neither
// answers; one family down alone is logged as such.
func (a *App) checkServer(m *serverMon, s *Server, addr string, pause time.Duration) {
	m.mu.Lock()
	full := m.round%serverFull == 0
	m.mu.Unlock()
	addr6 := s.sshAddr6()
	if addr6 == addr {
		addr6 = ""
	}
	up, up6, any := a.pooledSSH(s.ID)
	agent := a.agents != nil && a.agents.online(s.ID) != nil
	probe4, probe6 := probePlan(up, up6 || addr6 == "", any || agent, full)
	var first time.Time
	if probe4 {
		up, first = tcpUp(addr, 3, pause)
	}
	if probe6 {
		up6, _ = tcpUp(addr6, 3, pause)
	}
	// no address in the reasons: they go to every account with a tunnel on the server (a
	// user's bot, its Outages page) and to the AI analysis, and the address of a server shared
	// with a user is hidden from them (sharedView); the Servers page has it
	reason := "the SSH port doesn't answer"
	if addr6 != "" {
		if !up6 {
			reason = "SSH doesn't answer over IPv4 nor over IPv6"
		}
		// one family down while the other works: worth knowing (and logging) on its own —
		// judged only once both were looked at this round
		// — and only while one of them answers: with both gone it is the server that is down,
		// and "IPv6 back" came next to "Server unreachable" (then flapped when it returned)
		if (up || probe4) && (up6 || probe6) && (up || up6) {
			a.transition(m, s.ID+"/v4", "ssh-v4", s.Name+" (IPv4)", !up && up6, first, "SSH over IPv4 doesn't answer — IPv6 works; the panel manages it over IPv6 meanwhile")
			a.transition(m, s.ID+"/v6", "ssh-v6", s.Name+" (IPv6)", up && !up6, time.Now(), "SSH over IPv6 doesn't answer — IPv4 works")
		}
	}
	alive := up || up6 || any
	if !alive && agent {
		alive = true // SSH is filtered, but the server is alive and talking to the panel
	}
	if alive {
		go a.runCleanups(s.ID) // what it missed while it was unreachable (no-op when nothing)
	}
	a.transition(m, s.ID, "server", s.Name, !alive, first, reason)
}

// transition records a change of state and tells Telegram.
func (a *App) transition(m *serverMon, id, kind, name string, down bool, at time.Time, reason string) {
	m.mu.Lock()
	s := m.state[id]
	if s == nil {
		s = &srvState{}
		m.state[id] = s
	}
	was := s.down
	if down == was {
		m.mu.Unlock()
		return
	}
	s.down = down
	if at.IsZero() {
		at = time.Now()
	}
	if down {
		s.since, s.outageID = at, newID()
		oid := s.outageID
		m.mu.Unlock()
		a.addOutage(Outage{ID: oid, Kind: kind, Target: id, Name: name, Start: at.Unix(), Reason: reason})
		icon := map[string]string{"server": "🔴 Server unreachable", "panel": "⚠ Panel host offline", "ssh-v4": "🟠 SSH over IPv4 down", "ssh-v6": "🟠 SSH over IPv6 down"}[kind]
		srvID, _, _ := strings.Cut(id, "/")
		a.pushServer(srvID, fmt.Sprintf("%s: %s\nsince %s (Tehran)\n%s", icon, name, clock(at), reason))
		return
	}
	since, oid := s.since, s.outageID
	m.mu.Unlock()
	now := time.Now()
	a.endOutage(oid, now)
	icon := map[string]string{"server": "🟢 Server reachable again", "panel": "🟢 Panel host back online", "ssh-v4": "🟢 SSH over IPv4 back", "ssh-v6": "🟢 SSH over IPv6 back"}[kind]
	srvID, _, _ := strings.Cut(id, "/")
	a.pushServer(srvID, fmt.Sprintf("%s: %s\ndown %s\n%s → %s (Tehran)", icon, name, shortDur(now.Sub(since)), clock(since), clock(now)))
}

// tunnelCause says, for a tunnel that just went down, whether its servers answered.
func (a *App) tunnelCause(t *Tunnel) string {
	if !a.serverReachable("panel") {
		return "the panel host itself is offline"
	}
	var bad []string
	if !a.serverReachable(t.ServerID) {
		bad = append(bad, "Iran server "+serverName(a, t.ServerID))
	}
	if t.ForeignID != "" && !a.serverReachable(t.ForeignID) {
		bad = append(bad, "foreign server "+serverName(a, t.ForeignID))
	}
	switch len(bad) {
	case 0:
		return "both servers answer on SSH → the tunnel itself (or its route) dropped, not the servers"
	case 1:
		return bad[0] + " doesn't answer on SSH → the server or its network dropped"
	}
	return bad[0] + " and " + bad[1] + " don't answer on SSH → the servers' networks dropped"
}
