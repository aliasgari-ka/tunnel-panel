package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Live traffic. Counters are read on the Iran side (where users connect) only while
// someone is looking (the web page polls /api/traffic, the bot asks for /traffic), so an
// idle panel puts no load on the servers.
//
//   - L3 tunnels: the tunnel interface's rx/tx counters (rx = foreign -> Iran = download).
//   - port forwarders: per-tunnel iptables counting chains on the forwarded ports,
//     TPAO_<id> in OUTPUT (--sport, Iran -> users = download) and TPAI_<id> in INPUT
//     (--dport, users -> Iran = upload). The chains only count (no target) and are created
//     on first read, so tunnels deployed before this feature are covered too.
//   - each server's default-route NIC, for the whole-server picture.

const (
	trafficTick = 2 * time.Second
	trafficIdle = 20 * time.Second // stop polling this long after the last viewer
	trafficHist = 90               // points kept (3 min at 2 s)
)

// TrafficPoint is one rate sample in bits per second.
type TrafficPoint struct {
	T    int64   `json:"t"`
	Down float64 `json:"down"`
	Up   float64 `json:"up"`
}

// TrafficStat is the live state of one tunnel or server NIC.
type TrafficStat struct {
	ID        string         `json:"id"`
	Source    string         `json:"source"` // "iface tp3", "ports", "nic eth0"
	Down      float64        `json:"down"`   // bits/s towards Iran users
	Up        float64        `json:"up"`
	TotalDown uint64         `json:"totalDown"` // bytes since the counter started (tunnel start / boot)
	TotalUp   uint64         `json:"totalUp"`
	Error     string         `json:"error,omitempty"`
	Updated   int64          `json:"updated"`
	Hist      []TrafficPoint `json:"hist"`

	lastT        time.Time
	lastD, lastU uint64
	haveLast     bool
}

// TrafficSnapshot is what /api/traffic returns.
type TrafficSnapshot struct {
	Tunnels map[string]*TrafficStat `json:"tunnels"`
	Servers map[string]*TrafficStat `json:"servers"` // "" = this panel host
	Live    bool                    `json:"live"`
}

type trafficMon struct {
	mu      sync.Mutex
	tunnels map[string]*TrafficStat
	servers map[string]*TrafficStat
	wanted  time.Time
	running bool
	busy    map[string]bool      // server id -> a read is in flight
	backoff map[string]time.Time // server id -> skip until (unreachable)
}

func newTrafficMon() *trafficMon {
	return &trafficMon{tunnels: map[string]*TrafficStat{}, servers: map[string]*TrafficStat{},
		busy: map[string]bool{}, backoff: map[string]time.Time{}}
}

// Traffic marks the data as wanted (starting the collector if idle) and returns a copy.
func (a *App) Traffic() TrafficSnapshot {
	tm := a.traffic
	tm.mu.Lock()
	tm.wanted = time.Now()
	if !tm.running {
		tm.running = true
		go a.trafficLoop()
	}
	snap := TrafficSnapshot{Tunnels: map[string]*TrafficStat{}, Servers: map[string]*TrafficStat{}, Live: true}
	for k, v := range tm.tunnels {
		cp := *v
		cp.Hist = append([]TrafficPoint(nil), v.Hist...)
		snap.Tunnels[k] = &cp
	}
	for k, v := range tm.servers {
		cp := *v
		cp.Hist = append([]TrafficPoint(nil), v.Hist...)
		snap.Servers[k] = &cp
	}
	tm.mu.Unlock()
	return snap
}

func (a *App) trafficLoop() {
	tm := a.traffic
	for {
		a.trafficCollect()
		time.Sleep(trafficTick)
		tm.mu.Lock()
		if time.Since(tm.wanted) > trafficIdle {
			tm.running = false
			// rates are stale once we stop; keep totals, drop the baseline
			for _, s := range tm.tunnels {
				s.haveLast, s.Down, s.Up = false, 0, 0
			}
			for _, s := range tm.servers {
				s.haveLast, s.Down, s.Up = false, 0, 0
			}
			tm.mu.Unlock()
			return
		}
		tm.mu.Unlock()
	}
}

// trafficIface is the interface an L3 tunnel's packets cross on the Iran side.
func trafficIface(t *Tunnel) string {
	if t.Active == "premium" {
		return fmt.Sprintf("bhp%d", t.Index)
	}
	return fmt.Sprintf("tp%d", t.Index)
}

const nicRead = `IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -n "$IF" ] || IF=$(awk -F'[: ]+' 'NR>2{sub(/^ +/,""); split($0,a,/[: ]+/); if (a[1]!="lo" && a[2]+0>=m) {m=a[2]+0; n=a[1]}} END{print n}' /proc/net/dev)
[ -n "$IF" ] && echo "N $(cat /sys/class/net/$IF/statistics/rx_bytes 2>/dev/null || echo -) $(cat /sys/class/net/$IF/statistics/tx_bytes 2>/dev/null || echo -) $IF"
`

// acctChains returns the counting-chain names for a port-forward tunnel.
func acctChains(t *Tunnel) (in, out string) { return "TPAI_" + t.ID, "TPAO_" + t.ID }

// acctScript ensures the counting chains exist and prints "T <id> <down> <up>".
func acctScript(t *Tunnel) string {
	in, out := acctChains(t)
	var rules strings.Builder
	for _, p := range splitPorts(t.Ports) {
		port := strings.ReplaceAll(p.listen, "-", ":")
		if i := strings.LastIndex(port, "]:"); i >= 0 { // "[::1]:443" style binds
			port = port[i+2:]
		} else if strings.Count(port, ":") == 1 && strings.Contains(port, ".") { // "1.2.3.4:443"
			port = port[strings.Index(port, ":")+1:]
		}
		if _, err := strconv.Atoi(strings.SplitN(port, ":", 2)[0]); err != nil {
			continue
		}
		for _, proto := range []string{"tcp", "udp"} {
			fmt.Fprintf(&rules, "  $ipt -w -A %s -p %s --dport %s\n  $ipt -w -A %s -p %s --sport %s\n", in, proto, port, out, proto, port)
		}
	}
	return fmt.Sprintf(`d=0; u=0
for ipt in iptables ip6tables; do
  command -v $ipt >/dev/null 2>&1 || continue
  if ! $ipt -w -nL %[1]s >/dev/null 2>&1; then
    $ipt -w -N %[1]s 2>/dev/null; $ipt -w -N %[2]s 2>/dev/null
%[4]s    $ipt -w -I INPUT -j %[1]s; $ipt -w -I OUTPUT -j %[2]s
  fi
  x=$($ipt -w -nvxL %[2]s 2>/dev/null | awk 'NR>2{s+=$2}END{printf "%%d", s+0}'); d=$((d+x))
  x=$($ipt -w -nvxL %[1]s 2>/dev/null | awk 'NR>2{s+=$2}END{printf "%%d", s+0}'); u=$((u+x))
done
echo "T %[3]s $d $u"
`, in, out, t.ID, rules.String())
}

// acctDown removes a tunnel's counting chains (part of teardown).
func acctDown(t *Tunnel) string {
	in, out := acctChains(t)
	return fmt.Sprintf(`for ipt in iptables ip6tables; do
  command -v $ipt >/dev/null 2>&1 || continue
  while $ipt -w -D INPUT -j %[1]s 2>/dev/null; do :; done
  while $ipt -w -D OUTPUT -j %[2]s 2>/dev/null; do :; done
  $ipt -w -F %[1]s 2>/dev/null; $ipt -w -X %[1]s 2>/dev/null
  $ipt -w -F %[2]s 2>/dev/null; $ipt -w -X %[2]s 2>/dev/null
done
`, in, out)
}

// trafficCollect reads every relevant host once, in parallel.
func (a *App) trafficCollect() {
	tm := a.traffic
	byServer := map[string][]*Tunnel{}
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if t.Active != "" {
				byServer[t.ServerID] = append(byServer[t.ServerID], t)
			}
		}
		// servers with a live agent are cheap to read even without tunnels
		for _, s := range st.Servers {
			if _, ok := byServer[s.ID]; !ok && a.agents != nil && a.agents.online(s.ID) != nil {
				byServer[s.ID] = nil
			}
		}
	})
	var wg sync.WaitGroup
	read := func(id string, ts []*Tunnel) {
		defer wg.Done()
		defer func() { tm.mu.Lock(); delete(tm.busy, id); tm.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var h Host = LocalHost{}
		if id != "" {
			srv := a.store.Server(id)
			if srv == nil {
				return
			}
			hh, err := a.quickHost(ctx, srv)
			if err != nil {
				a.trafficFail(id, ts, "unreachable: "+err.Error())
				return
			}
			h = hh
		}
		var sb strings.Builder
		sb.WriteString(nicRead)
		for _, t := range ts {
			if m := methodByID[t.Active]; m != nil && benchIsL3(m, t.Options[m.ID]) {
				ifc := trafficIface(t)
				fmt.Fprintf(&sb, "echo \"T %s $(cat /sys/class/net/%[2]s/statistics/rx_bytes 2>/dev/null || echo -) $(cat /sys/class/net/%[2]s/statistics/tx_bytes 2>/dev/null || echo -) iface %[2]s\"\n", t.ID, ifc)
			} else {
				sb.WriteString(acctScript(t))
			}
		}
		out, err := h.Run(ctx, sb.String(), nil)
		if err != nil && strings.TrimSpace(out) == "" {
			a.trafficFail(id, ts, err.Error())
			return
		}
		a.trafficParse(id, ts, out)
	}
	tm.mu.Lock()
	jobs := map[string][]*Tunnel{"": byServer[""]} // panel host NIC always
	for id, ts := range byServer {
		jobs[id] = ts
	}
	for id, ts := range jobs {
		if tm.busy[id] || time.Now().Before(tm.backoff[id]) {
			continue
		}
		tm.busy[id] = true
		wg.Add(1)
		go read(id, ts)
	}
	// forget tunnels that stopped or were deleted
	live := map[string]bool{}
	for _, ts := range byServer {
		for _, t := range ts {
			live[t.ID] = true
		}
	}
	for id := range tm.tunnels {
		if !live[id] {
			delete(tm.tunnels, id)
		}
	}
	tm.mu.Unlock()
	wg.Wait()
}

// quickHost returns a host without the store writes reach() does: agent, then a cached SSH client.
func (a *App) quickHost(ctx context.Context, srv *Server) (Host, error) {
	if a.agents != nil && a.agents.online(srv.ID) != nil {
		return AgentHost{hub: a.agents, serverID: srv.ID}, nil
	}
	reachCache.Lock()
	for k, h := range reachCache.m {
		if strings.HasPrefix(k, srv.ID+"|") {
			if sh, ok := h.(*SSHHost); ok {
				reachCache.Unlock()
				if _, err := sh.client(); err == nil {
					return sh, nil
				}
				reachCache.Lock()
				break
			}
		}
	}
	reachCache.Unlock()
	h, _, err := a.reach(ctx, srv, nil)
	return h, err
}

func (a *App) trafficFail(id string, ts []*Tunnel, msg string) {
	tm := a.traffic
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.backoff[id] = time.Now().Add(30 * time.Second)
	for _, t := range ts {
		s := tm.stat(tm.tunnels, t.ID)
		s.Error, s.Down, s.Up, s.haveLast = msg, 0, 0, false
	}
	if s, ok := tm.servers[id]; ok {
		s.Error = msg
	}
}

func (tm *trafficMon) stat(m map[string]*TrafficStat, id string) *TrafficStat {
	s := m[id]
	if s == nil {
		s = &TrafficStat{ID: id}
		m[id] = s
	}
	return s
}

func (a *App) trafficParse(serverID string, ts []*Tunnel, out string) {
	tm := a.traffic
	now := time.Now()
	tm.mu.Lock()
	defer tm.mu.Unlock()
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) >= 4 && f[0] == "N":
			// NIC: rx = into this server = download for an Iran box
			tm.update(tm.stat(tm.servers, serverID), "nic "+f[3], f[1], f[2], now)
		case len(f) >= 4 && f[0] == "T":
			src := "ports"
			s := tm.stat(tm.tunnels, f[1])
			if len(f) >= 5 && f[4] == "iface" {
				src = "iface"
			}
			tm.update(s, src, f[2], f[3], now)
			if src == "iface" && s.Error != "" && len(f) >= 6 {
				s.Error = "tunnel interface " + f[5] + " not found — is the tunnel up on Iran?"
			}
			seen[f[1]] = true
		}
	}
	for _, t := range ts {
		if !seen[t.ID] {
			s := tm.stat(tm.tunnels, t.ID)
			s.Error = "no counters returned"
		}
	}
}

// update turns two cumulative byte counters into rates.
func (tm *trafficMon) update(s *TrafficStat, src, dStr, uStr string, now time.Time) {
	d, err1 := strconv.ParseUint(dStr, 10, 64)
	u, err2 := strconv.ParseUint(uStr, 10, 64)
	if err1 != nil || err2 != nil {
		s.Error = "counters not available yet (is the tunnel up?)"
		s.Down, s.Up, s.haveLast = 0, 0, false
		return
	}
	s.Source, s.Error, s.Updated = src, "", now.Unix()
	s.TotalDown, s.TotalUp = d, u
	if s.haveLast && d >= s.lastD && u >= s.lastU {
		dt := now.Sub(s.lastT).Seconds()
		if dt > 0 {
			s.Down = float64(d-s.lastD) * 8 / dt
			s.Up = float64(u-s.lastU) * 8 / dt
			s.Hist = append(s.Hist, TrafficPoint{T: now.Unix(), Down: s.Down, Up: s.Up})
			if len(s.Hist) > trafficHist {
				s.Hist = s.Hist[len(s.Hist)-trafficHist:]
			}
		}
	} else {
		s.Down, s.Up = 0, 0 // first sample or counter reset (tunnel restarted)
	}
	s.lastT, s.lastD, s.lastU, s.haveLast = now, d, u, true
}

// ---- speed test of a live tunnel ----

// SpeedResult is the last on-demand speed test of a tunnel.
type SpeedResult struct {
	At       int64   `json:"at"`
	OK       bool    `json:"ok"`
	Error    string  `json:"error,omitempty"`
	RTTms    float64 `json:"rttMs"`
	Jitterms float64 `json:"jitterMs"`
	DownMbps float64 `json:"downMbps"`
	UpMbps   float64 `json:"upMbps"`
}

func (a *App) speedResult(id string) *SpeedResult {
	a.speedMu.Lock()
	defer a.speedMu.Unlock()
	return a.speedRes[id]
}

// probePortFor is the per-tunnel port the speed test uses; port forwarders map it to
// the foreign side as a hidden extra port (see withProbePort).
func probePortFor(t *Tunnel) int { return 40000 + t.Index*4 + 2 }

// withProbePort adds the speed-test port to a port-forward tunnel's mappings.
func withProbePort(m *Method, t *Tunnel) string {
	if benchIsL3(m, t.Options[m.ID]) || m.ID == "spoof" {
		return t.Ports
	}
	p := strconv.Itoa(probePortFor(t))
	for _, s := range splitPorts(t.Ports) {
		if s.listen == p {
			return t.Ports
		}
	}
	if strings.TrimSpace(t.Ports) == "" {
		return p
	}
	return t.Ports + "," + p
}

// SpeedTest measures the running tunnel end to end with the probe (RTT, download, upload).
func (a *App) SpeedTest(t *Tunnel, secs int) (*Job, error) {
	if t.Active == "" {
		return nil, fmt.Errorf("start the tunnel first")
	}
	m := methodByID[t.Active]
	if m == nil {
		return nil, fmt.Errorf("unknown method")
	}
	if m.ID == "spoof" {
		return nil, fmt.Errorf("Spoof-Tunnel only carries UDP — test it with your UDP application")
	}
	if secs <= 0 || secs > 20 {
		secs = 5
	}
	j, err := a.jobs.start(t.ID, "speedtest")
	if err != nil {
		return nil, err
	}
	go func() {
		defer a.jobs.done(j)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		res := &SpeedResult{At: time.Now().Unix()}
		fail := func(f string, x ...any) {
			res.Error = fmt.Sprintf(f, x...)
			j.log("ERROR: %s", res.Error)
			a.speedMu.Lock()
			a.speedRes[t.ID] = res
			a.speedMu.Unlock()
			j.finish("error")
		}
		srv := a.store.Server(t.ServerID)
		if srv == nil {
			fail("Iran server not found")
			return
		}
		irHost, _, err := a.reach(ctx, srv, j)
		if err != nil {
			fail("cannot reach Iran: %v", err)
			return
		}
		khHost, _, err := a.foreignHost(ctx, t, j)
		if err != nil {
			fail("cannot reach foreign: %v", err)
			return
		}
		if err := pushArtifacts(ctx, j, "IR", irHost, []Artifact{probeArt}); err != nil {
			fail("probe on Iran: %v", err)
			return
		}
		if err := pushArtifacts(ctx, j, "KH", khHost, []Artifact{probeArt}); err != nil {
			fail("probe on foreign: %v", err)
			return
		}
		port := probePortFor(t)
		d := deriveFor(t, srv, a.store.Server(t.ForeignID), a.settings())
		target := fmt.Sprintf("127.0.0.1:%d", port)
		if benchIsL3(m, t.Options[m.ID]) {
			target = fmt.Sprintf("%s:%d", d.KHv4, port)
		}
		_, _ = khHost.Run(ctx, probeServerUpLife(port, 120), nil)
		defer func() { _, _ = khHost.Run(context.Background(), probeServerDown(port), nil) }()
		j.log("testing %s through %s (%s)", t.Name, m.Title, target)
		rt, err := runProbe[probeRTT](ctx, irHost, fmt.Sprintf("probe rtt -addr %s -n 15", target), 25)
		if err != nil {
			hint := ""
			if !benchIsL3(m, t.Options[m.ID]) {
				hint = " — if this tunnel was started before this panel version, press Re-apply once (it adds the speed-test port)"
			}
			fail("no answer through the tunnel: %v%s", err, hint)
			return
		}
		res.RTTms, res.Jitterms = rt.RTTms, rt.Jitterms
		j.log("RTT %.1f ms, jitter %.1f ms", rt.RTTms, rt.Jitterms)
		if dn, err := runProbe[probeBW](ctx, irHost, fmt.Sprintf("probe bw -down -addr %s -secs %d", target, secs), secs+30); err == nil {
			res.DownMbps = dn.Mbps
			j.log("download (foreign → Iran): %.1f Mbps", dn.Mbps)
		} else {
			j.log("download test failed: %v", err)
		}
		if up, err := runProbe[probeBW](ctx, irHost, fmt.Sprintf("probe bw -addr %s -secs %d", target, secs), secs+30); err == nil {
			res.UpMbps = up.Mbps
			j.log("upload (Iran → foreign): %.1f Mbps", up.Mbps)
		} else {
			j.log("upload test failed: %v", err)
		}
		res.OK = true
		a.speedMu.Lock()
		a.speedRes[t.ID] = res
		a.speedMu.Unlock()
		j.log("DONE — ↓ %.1f Mbps  ↑ %.1f Mbps  RTT %.1f ms", res.DownMbps, res.UpMbps, res.RTTms)
		j.finish("ok")
	}()
	return j, nil
}

// fmtRate renders bits/s for humans.
func fmtRate(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.0f Kbps", bps/1e3)
	}
	return fmt.Sprintf("%.0f bps", bps)
}

// fmtBytes renders a byte count for humans.
func fmtBytes(b uint64) string {
	f := float64(b)
	switch {
	case f >= 1<<40:
		return fmt.Sprintf("%.2f TB", f/(1<<40))
	case f >= 1<<30:
		return fmt.Sprintf("%.2f GB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.1f MB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.0f KB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}
