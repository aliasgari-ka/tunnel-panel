package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server resources: CPU (with iowait and steal — an oversold VPS shows up as steal), RAM,
// swap, disk, load, uptime, open TCP sockets, conntrack and the busiest processes. Read in
// the same command as the live traffic counters (no extra connection, only while someone
// looks), plus once a minute in the background for alerts: CPU, RAM, disk or conntrack
// near the limit for a few minutes in a row → Telegram, and again when it is over.

// resRead prints the raw counters; cheap: /proc files and one df.
const resRead = `read -r _ u n s i w q sq st _ < /proc/stat; echo "C $u $n $s $i $w $q $sq ${st:-0} $(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)"
awk '{m[$1]=$2} END{a=m["MemAvailable:"]; if (a=="") a=m["MemFree:"]+m["Buffers:"]+m["Cached:"]; print "M", m["MemTotal:"]+0, a+0, m["SwapTotal:"]+0, m["SwapFree:"]+0}' /proc/meminfo
echo "L $(cut -d' ' -f1-3 /proc/loadavg) $(cut -d' ' -f1 /proc/uptime)"
df -Pk / 2>/dev/null | awk 'NR==2{print "D", $2, $3}'
echo "K $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -) $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo -) $(cat /proc/net/sockstat /proc/net/sockstat6 2>/dev/null | awk '/^TCP6?:/{s+=$3}END{print s+0}')"
`

// resProcs lists every process's CPU ticks and RSS (the comm may hold spaces and parens), and
// the tunnel unit it runs in ("-" for any other), so each path of a tunnel counts on its own.
// cat, not awk, opens the files: awk stops at the first one that can't be opened, and on a
// busy server a process ends between the glob and the read all the time (iran 1's six
// switchers start a few every second), so every process after it was left out of the list.
// "PE" closes a whole list.
const resProcs = `cat /proc/[0-9]*/stat 2>/dev/null | awk '{s=$0; o=index(s,"("); i=o; while ((j=index(substr(s,i+1),") "))>0) i+=j; c=substr(s,o+1,i-o-1); gsub(/ /,"_",c); split(substr(s,i+2),f," "); if (f[22]>0) { u="-"; cg="/proc/"$1"/cgroup"; while ((getline l < cg) > 0) if (match(l, /\/tp-[^\/]*\.service/)) u=substr(l, RSTART+1, RLENGTH-1); close(cg); print "P", $1, f[12]+f[13], f[22], c, u } } END { print "PE list" }'
`

const (
	resProcEvery = 5   // live reads between process samples (10 s)
	resHist      = 90  // CPU/RAM points kept (3 min at 2 s)
	resProcTop   = 12  // busiest programs kept (a tunnel path is a row of its own)
	clkTck       = 100 // USER_HZ on Linux
	pageKB       = 4
)

// ResPoint is one CPU/RAM sample in percent.
type ResPoint struct {
	T   int64   `json:"t"`
	CPU float64 `json:"cpu"`
	Mem float64 `json:"mem"`
}

// ProcUse is one program's share (all its processes together; in a tunnel's unit, that unit's).
type ProcUse struct {
	Name  string  `json:"name"`
	CPU   float64 `json:"cpu"` // % of the whole machine
	RSSMB float64 `json:"rssMB"`
	N     int     `json:"n"`
	Unit  string  `json:"unit,omitempty"` // the tunnel unit ("" = not a tunnel's)
	Path  string  `json:"path,omitempty"` // which tunnel and path that unit is
}

// ServerRes is a server's live resource picture.
type ServerRes struct {
	Updated   int64      `json:"updated"`
	Error     string     `json:"error,omitempty"`
	Cores     int        `json:"cores"`
	CPU       float64    `json:"cpu"` // % busy (all cores)
	IOWait    float64    `json:"iowait"`
	Steal     float64    `json:"steal"`
	Sys       float64    `json:"sys"`     // kernel on behalf of programs
	SoftIRQ   float64    `json:"softirq"` // kernel moving packets (irq + softirq): no program shows it
	Load      [3]float64 `json:"load"`
	MemTotal  uint64     `json:"memTotal"` // KB
	MemUsed   uint64     `json:"memUsed"`
	SwapTotal uint64     `json:"swapTotal"`
	SwapUsed  uint64     `json:"swapUsed"`
	DiskTotal uint64     `json:"diskTotal"` // KB, the root filesystem
	DiskUsed  uint64     `json:"diskUsed"`
	Uptime    int64      `json:"uptime"` // seconds
	Conntrack int64      `json:"conntrack"`
	CTMax     int64      `json:"ctMax"`
	TCP       int64      `json:"tcp"` // TCP sockets in use
	Procs     []ProcUse  `json:"procs,omitempty"`
	Hist      []ResPoint `json:"hist"`

	cpuPrev  []uint64
	procPrev map[string]uint64 // pid → ticks
	procT    time.Time
	reads    int
}

// resSample is one parsed read.
type resSample struct {
	cpu                []uint64 // user nice system idle iowait irq softirq steal
	cores              int
	mem, avail         uint64
	swap, swapFree     uint64
	load               [3]float64
	uptime             float64
	disk, diskUsed     uint64
	ct, ctMax, tcp     int64
	procs              map[string]uint64 // pid → ticks
	procRSS, procName  map[string]string
	procUnit           map[string]string // pid → tunnel unit, when it runs in one
	hasCPU, hasMem, ok bool
}

func parseRes(out string) resSample {
	s := resSample{ct: -1, ctMax: -1, procs: map[string]uint64{}, procRSS: map[string]string{}, procName: map[string]string{}, procUnit: map[string]string{}}
	u := func(x string) uint64 { n, _ := strconv.ParseUint(x, 10, 64); return n }
	procEnd := false
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "C":
			if len(f) >= 10 {
				for _, x := range f[1:9] {
					s.cpu = append(s.cpu, u(x))
				}
				s.cores, _ = strconv.Atoi(f[9])
				s.hasCPU, s.ok = true, true
			}
		case "M":
			if len(f) >= 5 {
				s.mem, s.avail, s.swap, s.swapFree = u(f[1]), u(f[2]), u(f[3]), u(f[4])
				s.hasMem = s.mem > 0
			}
		case "L":
			for i := 0; i < 3 && i+1 < len(f); i++ {
				s.load[i], _ = strconv.ParseFloat(f[i+1], 64)
			}
			if len(f) >= 5 {
				s.uptime, _ = strconv.ParseFloat(f[4], 64)
			}
		case "D":
			if len(f) >= 3 {
				s.disk, s.diskUsed = u(f[1]), u(f[2])
			}
		case "K":
			if len(f) >= 4 {
				if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					s.ct = n
				}
				if n, err := strconv.ParseInt(f[2], 10, 64); err == nil {
					s.ctMax = n
				}
				s.tcp, _ = strconv.ParseInt(f[3], 10, 64)
			}
		case "PE":
			procEnd = true
		case "P":
			if len(f) >= 5 {
				s.procs[f[1]] = u(f[2])
				s.procRSS[f[1]], s.procName[f[1]] = f[3], f[4]
				if len(f) >= 6 && f[5] != "-" {
					s.procUnit[f[1]] = f[5]
				}
			}
		}
	}
	if !procEnd { // cut off (the read timed out): the processes left out would look idle next time
		s.procs, s.procRSS, s.procName, s.procUnit = map[string]uint64{}, map[string]string{}, map[string]string{}, map[string]string{}
	}
	return s
}

// apply folds a sample into r (rates come from the previous sample).
func (r *ServerRes) apply(s resSample, now time.Time) {
	if !s.ok {
		r.Error = "no resource counters returned"
		return
	}
	r.Error, r.Updated, r.Cores = "", now.Unix(), s.cores
	if r.Cores < 1 {
		r.Cores = 1
	}
	if s.hasCPU && len(r.cpuPrev) == len(s.cpu) {
		var d [8]float64
		var tot float64
		ok := true
		for i := range s.cpu {
			if s.cpu[i] < r.cpuPrev[i] {
				ok = false // counter reset (reboot)
			}
			d[i] = float64(s.cpu[i]) - float64(r.cpuPrev[i])
			tot += d[i]
		}
		if ok && tot > 0 {
			r.CPU = 100 * (tot - d[3] - d[4]) / tot
			r.IOWait, r.Steal = 100*d[4]/tot, 100*d[7]/tot
			r.Sys, r.SoftIRQ = 100*d[2]/tot, 100*(d[5]+d[6])/tot
		}
	}
	r.cpuPrev = s.cpu
	if s.hasMem {
		r.MemTotal, r.MemUsed = s.mem, s.mem-min(s.avail, s.mem)
		r.SwapTotal, r.SwapUsed = s.swap, s.swap-min(s.swapFree, s.swap)
	}
	r.Load, r.Uptime = s.load, int64(s.uptime)
	r.DiskTotal, r.DiskUsed = s.disk, s.diskUsed
	r.Conntrack, r.CTMax, r.TCP = s.ct, s.ctMax, s.tcp
	if len(s.procs) > 0 {
		if r.procPrev != nil {
			dt := now.Sub(r.procT).Seconds()
			by := map[string]*ProcUse{}
			for pid, ticks := range s.procs {
				// a program in a tunnel's unit counts per unit: 12 Paqet paths are 12 rows
				key := s.procName[pid] + "|" + s.procUnit[pid]
				p := by[key]
				if p == nil {
					p = &ProcUse{Name: s.procName[pid], Unit: s.procUnit[pid]}
					by[key] = p
				}
				p.N++
				rss, _ := strconv.ParseFloat(s.procRSS[pid], 64)
				p.RSSMB += rss * pageKB / 1024
				if prev, ok := r.procPrev[pid]; ok && ticks >= prev && dt > 0 {
					p.CPU += 100 * float64(ticks-prev) / clkTck / dt / float64(r.Cores)
				}
			}
			list := make([]ProcUse, 0, len(by))
			for _, p := range by {
				list = append(list, *p)
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].CPU != list[j].CPU {
					return list[i].CPU > list[j].CPU
				}
				return list[i].RSSMB > list[j].RSSMB
			})
			if len(list) > resProcTop {
				list = list[:resProcTop]
			}
			r.Procs = list
		}
		r.procPrev, r.procT = s.procs, now
	}
	r.Hist = append(r.Hist, ResPoint{T: now.Unix(), CPU: r.CPU, Mem: pct(r.MemUsed, r.MemTotal)})
	if len(r.Hist) > resHist {
		r.Hist = r.Hist[len(r.Hist)-resHist:]
	}
}

func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// resScript is what the live reader adds for a server: the counters, and every
// resProcEvery reads the process list too.
func (a *App) resScript(id string) string {
	tm := a.traffic
	tm.mu.Lock()
	defer tm.mu.Unlock()
	r := tm.resOf(id)
	r.reads++
	if r.reads%resProcEvery == 1 {
		return resRead + resProcs
	}
	return resRead
}

func (tm *trafficMon) resOf(id string) *ServerRes {
	if tm.res == nil {
		tm.res = map[string]*ServerRes{}
	}
	r := tm.res[id]
	if r == nil {
		r = &ServerRes{}
		tm.res[id] = r
	}
	return r
}

func (a *App) resParse(id, out string) {
	s := parseRes(out)
	var paths map[string]string
	if len(s.procUnit) > 0 {
		paths = a.unitPaths()
	}
	tm := a.traffic
	tm.mu.Lock()
	r := tm.resOf(id)
	r.apply(s, time.Now())
	// only a read that sampled the processes names them; the reads between keep their names
	for i := range r.Procs {
		if u := r.Procs[i].Unit; u != "" && paths != nil {
			r.Procs[i].Path = paths[u]
		}
	}
	tm.mu.Unlock()
}

// unitPaths names every tunnel unit: "<tunnel> · <method> <family>" for a path, the switcher
// (Iran) or probe server (foreign) of a hot-standby tunnel, or the tunnel itself.
func (a *App) unitPaths() map[string]string {
	m := map[string]string{}
	a.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			m[unitName(t)] = t.Name + " · " + methodTitle(t.Active)
			if !t.HotStandby {
				continue
			}
			m[unitName(hsUnitTunnel(t))] = t.Name + " · hot-standby switcher / probe"
			for _, p := range t.Paths {
				m[unitName(pathTunnel(t, p))] = t.Name + " · " + methodTitle(p.Method) + " " + famName(p.Family)
			}
		}
	})
	return m
}

// resSnapshot copies the live resources (for the API and the bot).
func (tm *trafficMon) resSnapshot() map[string]*ServerRes {
	out := map[string]*ServerRes{}
	for k, v := range tm.res {
		cp := *v
		cp.Hist = append([]ResPoint(nil), v.Hist...)
		cp.Procs = append([]ProcUse(nil), v.Procs...)
		cp.cpuPrev, cp.procPrev = nil, nil
		out[k] = &cp
	}
	return out
}

// ---- alerts ----

const (
	resWatchEvery = time.Minute
	resAlertAfter = 3 // minutes in a row
	resCPUHigh    = 90.0
	resMemHigh    = 95.0
	resDiskHigh   = 90.0
	resCTHigh     = 90.0
)

type resAlert struct {
	n     int // minutes over the threshold in a row
	on    bool
	since time.Time
	peak  float64
}

// resWatch reads every server once a minute and tells Telegram when one runs out of CPU,
// RAM, disk or conntrack entries for a few minutes, and when that is over.
func (a *App) resWatch() {
	time.Sleep(90 * time.Second)
	prev := map[string]*ServerRes{}
	alerts := map[string]*resAlert{}
	for {
		var servers []*Server
		a.store.View(func(st *State) {
			for _, s := range st.Servers {
				cp := *s
				servers = append(servers, &cp)
			}
		})
		servers = append(servers, &Server{ID: "", Name: "this panel host"})
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, s := range servers {
			if s.ID != "" && !a.serverReachable(s.ID) {
				continue
			}
			wg.Add(1)
			go func(s *Server) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				var h Host = LocalHost{}
				if s.ID != "" {
					hh, err := a.quickHost(ctx, s)
					if err != nil {
						return
					}
					h = hh
				}
				out, _ := h.Run(ctx, resRead, nil)
				smp := parseRes(out)
				if !smp.ok {
					return
				}
				mu.Lock()
				r := prev[s.ID]
				if r == nil {
					r = &ServerRes{}
					prev[s.ID] = r
				}
				first := r.cpuPrev == nil
				r.apply(smp, time.Now())
				mu.Unlock()
				if first {
					return // CPU needs two samples
				}
				for _, c := range resChecks(r) {
					mu.Lock()
					k := s.ID + "/" + c.kind
					al := alerts[k]
					if al == nil {
						al = &resAlert{}
						alerts[k] = al
					}
					msg := al.step(c, s.Name)
					mu.Unlock()
					if msg != "" {
						var owner string // a user's own server: their bot hears about its load too
						a.store.View(func(*State) { owner = s.Owner })
						a.pushTo(owner, msg)
					}
				}
			}(s)
		}
		wg.Wait()
		time.Sleep(resWatchEvery)
	}
}

type resCheck struct {
	kind, what string
	value, max float64
}

func resChecks(r *ServerRes) []resCheck {
	out := []resCheck{
		{"cpu", fmt.Sprintf("CPU %.0f%% (load %.2f on %d cores, steal %.0f%%)", r.CPU, r.Load[0], r.Cores, r.Steal), r.CPU, resCPUHigh},
		{"mem", fmt.Sprintf("RAM %.0f%% (%s of %s)", pct(r.MemUsed, r.MemTotal), kbText(r.MemUsed), kbText(r.MemTotal)), pct(r.MemUsed, r.MemTotal), resMemHigh},
		{"disk", fmt.Sprintf("disk / %.0f%% (%s of %s)", pct(r.DiskUsed, r.DiskTotal), kbText(r.DiskUsed), kbText(r.DiskTotal)), pct(r.DiskUsed, r.DiskTotal), resDiskHigh},
	}
	if r.CTMax > 0 && r.Conntrack >= 0 {
		out = append(out, resCheck{"ct", fmt.Sprintf("conntrack table %.0f%% (%d of %d) — new connections get dropped when it is full", pct(uint64(r.Conntrack), uint64(r.CTMax)), r.Conntrack, r.CTMax), pct(uint64(r.Conntrack), uint64(r.CTMax)), resCTHigh})
	}
	return out
}

// step advances one alert by a minute; it returns a message when the state changes.
func (al *resAlert) step(c resCheck, name string) string {
	now := time.Now()
	if c.value >= c.max {
		al.n++
		if al.n == 1 {
			al.since, al.peak = now, 0
		}
		al.peak = max(al.peak, c.value)
		if !al.on && al.n >= resAlertAfter {
			al.on = true
			return fmt.Sprintf("🔥 %s: %s — for %d min (since %s Tehran)", name, c.what, al.n, clock(al.since))
		}
		return ""
	}
	al.n = 0
	if al.on {
		al.on = false
		return fmt.Sprintf("✅ %s: %s back to normal — now %s (peak %.0f%%, %s → %s Tehran)", name, c.kind, c.what, al.peak, clock(al.since), clock(now))
	}
	return ""
}

func kbText(kb uint64) string {
	switch {
	case kb >= 1<<30:
		return fmt.Sprintf("%.1f TB", float64(kb)/(1<<30))
	case kb >= 1<<20:
		return fmt.Sprintf("%.1f GB", float64(kb)/(1<<20))
	}
	return fmt.Sprintf("%.0f MB", float64(kb)/(1<<10))
}

func upText(s int64) string {
	d := s / 86400
	h := s % 86400 / 3600
	if d > 0 {
		return fmt.Sprintf("%dd %dh", d, h)
	}
	return fmt.Sprintf("%dh %dm", h, s%3600/60)
}

// resText is one server's resources for the bot.
func resText(name string, r *ServerRes) string {
	if r == nil {
		return "• <b>" + esc(name) + "</b>: not read yet\n"
	}
	if r.Error != "" {
		return "• <b>" + esc(name) + "</b>: " + esc(r.Error) + "\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "• <b>%s</b> — up %s\n", esc(name), upText(r.Uptime))
	fmt.Fprintf(&b, "   CPU %s %.0f%% · %d cores · load %.2f", resBar(r.CPU), r.CPU, r.Cores, r.Load[0])
	if r.Steal >= 5 {
		fmt.Fprintf(&b, " · ⚠ steal %.0f%%", r.Steal)
	}
	if r.IOWait >= 10 {
		fmt.Fprintf(&b, " · iowait %.0f%%", r.IOWait)
	}
	if r.SoftIRQ >= 15 {
		fmt.Fprintf(&b, " · packets in the kernel %.0f%%", r.SoftIRQ)
	}
	fmt.Fprintf(&b, "\n   RAM %s %.0f%% (%s / %s)", resBar(pct(r.MemUsed, r.MemTotal)), pct(r.MemUsed, r.MemTotal), kbText(r.MemUsed), kbText(r.MemTotal))
	if r.SwapUsed > 0 {
		fmt.Fprintf(&b, " · swap %s", kbText(r.SwapUsed))
	}
	fmt.Fprintf(&b, "\n   Disk %s %.0f%% (%s / %s)\n", resBar(pct(r.DiskUsed, r.DiskTotal)), pct(r.DiskUsed, r.DiskTotal), kbText(r.DiskUsed), kbText(r.DiskTotal))
	fmt.Fprintf(&b, "   TCP %d", r.TCP)
	if r.CTMax > 0 && r.Conntrack >= 0 {
		fmt.Fprintf(&b, " · conntrack %d / %d", r.Conntrack, r.CTMax)
	}
	b.WriteString("\n")
	if len(r.Procs) > 0 {
		var ps []string
		for _, p := range r.Procs[:min(4, len(r.Procs))] {
			n := p.Name
			if p.Path != "" {
				n += " (" + p.Path + ")"
			}
			ps = append(ps, fmt.Sprintf("%s %.0f%% %.0fMB", n, p.CPU, p.RSSMB))
		}
		b.WriteString("   top: <code>" + esc(strings.Join(ps, " · ")) + "</code>\n")
	}
	return b.String()
}

func resBar(p float64) string {
	n := int(p/20 + 0.5)
	if n > 5 {
		n = 5
	}
	icon := "🟩"
	switch {
	case p >= 90:
		icon = "🟥"
	case p >= 70:
		icon = "🟧"
	}
	return strings.Repeat(icon, n) + strings.Repeat("⬜", 5-n)
}

// resourcesText reads every server live (two samples, for the CPU) and formats it.
func (a *App) resourcesText() string {
	var ids []string
	names := map[string]string{"": "🖥 this panel host"}
	a.store.View(func(st *State) {
		for _, s := range st.Servers {
			ids = append(ids, s.ID)
			icon := "🌍"
			if s.Role != "foreign" {
				icon = "🇮🇷"
			}
			names[s.ID] = icon + " " + s.Name
		}
	})
	ids = append(ids, "")
	start := time.Now()
	ready := func(snap TrafficSnapshot) bool {
		for _, id := range ids {
			r := snap.Res[id]
			if r == nil || (r.Error == "" && len(r.Hist) < 2) {
				return false
			}
		}
		return true
	}
	snap := a.Traffic()
	for time.Since(start) < 15*time.Second && !ready(snap) {
		time.Sleep(time.Second)
		snap = a.Traffic()
	}
	var b strings.Builder
	b.WriteString("🖥 <b>Servers — live resources</b>\n\n")
	for _, id := range ids {
		r := snap.Res[id]
		b.WriteString(resText(names[id], r))
		if n := snap.Servers[id]; n != nil && n.Error == "" && r != nil && r.Error == "" {
			fmt.Fprintf(&b, "   NIC ↓ %s ↑ %s\n", mbpsText(n.Down), mbpsText(n.Up))
		}
		b.WriteString("\n")
	}
	b.WriteString("<i>alerts: CPU ≥ 90 %, RAM ≥ 95 %, disk ≥ 90 % or conntrack ≥ 90 % for 3 min → a message here, and another when it is over</i>")
	return b.String()
}

func mbpsText(bps float64) string {
	if bps >= 1e6 {
		return fmt.Sprintf("%.1f Mbps", bps/1e6)
	}
	return fmt.Sprintf("%.0f kbps", bps/1e3)
}
