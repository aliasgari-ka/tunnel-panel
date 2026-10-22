package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
	_ "time/tzdata" // Tehran time even on hosts without a zoneinfo database
)

// The server monitor connects to every server's SSH port every serverEvery. A failed
// check is retried twice a couple of seconds apart, so one lost SYN isn't an outage, but
// a short drop of 10 s still is. Each outage is kept with its exact start and end (also
// tunnel outages, tagged with whether their servers answered at the time), and Telegram
// hears about it when it starts and again when it is over. When the panel host itself
// can't reach the internet, that is logged as the panel's outage, not the servers'.
const (
	serverEvery   = 10 * time.Second
	sshTimeout    = 3 * time.Second
	maxOutageLogs = 300
)

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
}

// tehran is the time zone outages are reported in.
var tehran = func() *time.Location {
	if l, err := time.LoadLocation("Asia/Tehran"); err == nil {
		return l
	}
	return time.FixedZone("IRST", 3*3600+1800)
}()

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
		st.Outages = append(st.Outages, o)
		if n := len(st.Outages); n > maxOutageLogs {
			st.Outages = append([]Outage(nil), st.Outages[n-maxOutageLogs:]...)
		}
		return nil
	})
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
	a.srvMon = m
	// close outages left open by a restart of the panel: their real end is unknown
	_ = a.store.Update(func(st *State) error {
		for i := range st.Outages {
			if st.Outages[i].End == 0 {
				st.Outages[i].End = time.Now().Unix()
				st.Outages[i].Reason += " (panel restarted — end time approximate)"
			}
		}
		return nil
	})
	for {
		a.serverRound(m)
		time.Sleep(serverEvery)
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

// checkServer tries the SSH port over IPv4 and over IPv6 (when the server has both): the
// server is down only when neither answers; one family down alone is logged as such.
func (a *App) checkServer(m *serverMon, s *Server, addr string, pause time.Duration) {
	up, first := tcpUp(addr, 3, pause)
	reason := "SSH port " + addr + " doesn't answer"
	addr6 := s.sshAddr6()
	if addr6 == addr {
		addr6 = ""
	}
	up6 := false
	if addr6 != "" {
		up6, _ = tcpUp(addr6, 3, pause)
		if !up6 {
			reason = "SSH doesn't answer on " + addr + " nor over IPv6 on " + addr6
		}
		// one family down while the other works: worth knowing (and logging) on its own
		a.transition(m, s.ID+"/v4", "ssh-v4", s.Name+" (IPv4)", !up && up6, first, "SSH over IPv4 ("+addr+") doesn't answer — IPv6 ("+addr6+") works; the panel manages it over IPv6 meanwhile")
		a.transition(m, s.ID+"/v6", "ssh-v6", s.Name+" (IPv6)", up && !up6, time.Now(), "SSH over IPv6 ("+addr6+") doesn't answer — IPv4 works")
	}
	alive := up || up6
	if !alive && a.agents != nil && a.agents.online(s.ID) != nil {
		alive = true // SSH is filtered, but the server is alive and talking to the panel
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
		a.push(fmt.Sprintf("%s: %s\nsince %s (Tehran)\n%s", icon, name, clock(at), reason))
		return
	}
	since, oid := s.since, s.outageID
	m.mu.Unlock()
	now := time.Now()
	a.endOutage(oid, now)
	icon := map[string]string{"server": "🟢 Server reachable again", "panel": "🟢 Panel host back online", "ssh-v4": "🟢 SSH over IPv4 back", "ssh-v6": "🟢 SSH over IPv6 back"}[kind]
	a.push(fmt.Sprintf("%s: %s\ndown %s\n%s → %s (Tehran)", icon, name, shortDur(now.Sub(since)), clock(since), clock(now)))
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
