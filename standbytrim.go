package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// Standby trim: a hot-standby path the users aren't on still runs its core, and that core can
// sit on resources it no longer needs. Seen live: after the users moved to another path, the
// BackPack core of xe108's foreign side kept 1.5 GB for days and a TP Reverse core 690 MB,
// both passing 2 kbit/s; an emulated TP Reverse core that never got its connection spun at
// 97 % of a core on a 2-core server. Restarting such a core costs nobody anything — the
// switcher sees the path down for a few seconds, the users are elsewhere — and frees it all.

const (
	standbyTrimEvery = time.Hour
	standbyMemMB     = 300      // anonymous memory a core without traffic may keep
	standbyCPU       = 50       // % of one core a core without traffic may burn
	standbyIdleKbit  = 100      // below this a path carries probes only
	standbyMinUp     = 6 * 3600 // seconds a core runs before it is looked at (no restart loop)
	standbyViewAge   = 5 * 60   // seconds: older than this, the switcher's view isn't trusted
	standbySample    = 10       // seconds the CPU and the traffic are measured over
)

// standbyUse is what one standby unit used during the sample.
type standbyUse struct {
	unit   string
	anonMB int   // anonymous memory of the unit's cgroup
	cpu    int   // % of one core
	kbit   int   // read + written by its processes
	up     int64 // seconds since the unit started
}

// trim says why the unit should restart, or "" when it should be left alone: it carries
// traffic (open connections of users who haven't moved yet), it started not long ago, or it
// is as small and quiet as a waiting core should be.
func (u standbyUse) trim() string {
	if u.kbit >= standbyIdleKbit || u.up < standbyMinUp {
		return ""
	}
	switch {
	case u.anonMB >= standbyMemMB:
		return fmt.Sprintf("held %d MB with no traffic", u.anonMB)
	case u.cpu >= standbyCPU:
		return fmt.Sprintf("burned %d%% of a core with no traffic", u.cpu)
	}
	return ""
}

// standbyUseScript measures the given units for standbySample seconds and prints one
// "SU <unit> <anon MB> <cpu %> <kbit/s> <up s>" line for each that runs a process (a oneshot
// kernel path has none). cgroup v2 only; on anything else it prints nothing.
func standbyUseScript(units []string) string {
	return fmt.Sprintf(`us=%s
snap() {
  for u in $us; do
    cg=/sys/fs/cgroup/system.slice/$u
    [ -r "$cg/cgroup.procs" ] && [ -r "$cg/cpu.stat" ] || continue
    io=0
    for p in $(cat "$cg/cgroup.procs" 2>/dev/null); do
      x=$(awk '/^rchar|^wchar/{s+=$2} END{print s+0}' /proc/$p/io 2>/dev/null); io=$((io + ${x:-0}))
    done
    echo "$u $(awk '/^usage_usec/{print $2}' "$cg/cpu.stat") $io"
  done
}
a=$(snap); sleep %[2]d; b=$(snap)
now=$(cut -d. -f1 /proc/uptime)
echo "$b" | while read -r u c1 i1; do
  [ -n "$u" ] || continue
  set -- $(echo "$a" | awk -v u="$u" '$1==u{print $2, $3}')
  [ -n "$2" ] || continue
  anon=$(awk '$1=="anon"{print int($2/1048576)}' /sys/fs/cgroup/system.slice/$u/memory.stat 2>/dev/null)
  st=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$u" 2>/dev/null)
  d=$((i1 - $2)); [ "$d" -ge 0 ] || d=0
  echo "SU $u ${anon:-0} $(( (c1 - $1) / (%[2]d * 10000) )) $(( d * 8 / %[2]d / 1000 )) $(( now - ${st:-0} / 1000000 ))"
done
`, shq(strings.Join(units, " ")), standbySample)
}

func parseStandbyUse(out string) []standbyUse {
	var us []standbyUse
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 6 || f[0] != "SU" {
			continue
		}
		n := make([]int64, 4)
		ok := true
		for i := range n {
			v, err := strconv.ParseInt(f[i+2], 10, 64)
			if err != nil {
				ok = false
			}
			n[i] = v
		}
		if ok {
			us = append(us, standbyUse{unit: f[1], anonMB: int(n[0]), cpu: int(n[1]), kbit: int(n[2]), up: n[3]})
		}
	}
	return us
}

// standbyUnits are the units of the running paths the users aren't on. Nothing when the
// switcher's view is missing or old, or doesn't say where the users are.
func standbyUnits(t *Tunnel, good []HSPath, v *hsView, now int64) []string {
	if v == nil || now-v.Read > standbyViewAge || v.Active < 0 || v.Active >= len(v.Keys) {
		return nil
	}
	var us []string
	for _, p := range good {
		if p.Method+"|"+p.Family != v.Keys[v.Active] {
			us = append(us, unitName(pathTunnel(t, p)))
		}
	}
	return us
}

// standbyTrimHost measures the units on one server and restarts the ones trim picks. Returns
// "<unit>: <why>" for each restart.
func standbyTrimHost(ctx context.Context, h Host, units []string) []string {
	done, _ := standbyTrimHostUse(ctx, h, units)
	return done
}

// standbyTrimHostUse is standbyTrimHost that also returns what each unit used.
func standbyTrimHostUse(ctx context.Context, h Host, units []string) ([]string, []standbyUse) {
	if h == nil || len(units) == 0 {
		return nil, nil
	}
	out, _ := h.Run(ctx, standbyUseScript(units), nil)
	var done []string
	uses := parseStandbyUse(out)
	for _, u := range uses {
		why := u.trim()
		if why == "" {
			continue
		}
		if _, err := h.Run(ctx, "systemctl restart "+shq(u.unit), nil); err == nil {
			done = append(done, u.unit+": "+why)
		}
	}
	return done, uses
}

// standbyTrim looks at every hot-standby tunnel once an hour.
func (a *App) standbyTrim() {
	time.Sleep(20 * time.Minute)
	for {
		var ts []*Tunnel
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.Active != "" && t.HotStandby {
					ts = append(ts, t)
				}
			}
		})
		for _, t := range ts {
			if a.jobs.running(t.ID) != "" || !a.serverReachable(t.ServerID) || (t.ForeignID != "" && !a.serverReachable(t.ForeignID)) {
				continue
			}
			if done := a.standbyTrimOne(t); len(done) > 0 {
				log.Printf("%s: standby cores restarted: %s", t.Name, strings.Join(done, "; "))
				a.pushTInfo(t, fmt.Sprintf("🧹 %s: standby core(s) without users restarted to free the server:\n%s", t.Name, strings.Join(done, "\n")))
			}
		}
		time.Sleep(standbyTrimEvery)
	}
}

func (a *App) standbyTrimOne(t *Tunnel) []string {
	good, _ := a.hsGoodNow(t)
	units := standbyUnits(t, good, a.hsViewOf(t.ID), time.Now().Unix())
	if len(units) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return nil
	}
	keyOf := map[string]string{}
	for _, p := range good {
		keyOf[unitName(pathTunnel(t, p))] = p.Method + "|" + p.Family
	}
	var done []string
	if ir, _, err := a.reach(ctx, srv, nil); err == nil {
		d, uses := standbyTrimHostUse(ctx, ir, units)
		done = append(done, d...)
		a.noteIdleUse(t, keyOf, uses, true)
	}
	if kh, _, err := a.foreignHost(ctx, t, nil); err == nil {
		d, uses := standbyTrimHostUse(ctx, kh, units)
		done = append(done, d...)
		a.noteIdleUse(t, keyOf, uses, false)
	}
	return done
}

// idleCPU is what one standby path's cores burned while the users were elsewhere: % of one
// core on each server (-1 = not measured), as the last trim round measured it. Shown on the
// path's row, so an expensive standby is seen before it slows the server down.
type idleCPU struct {
	IR, KH int
	At     int64
}

// idleShowAge: an idle reading older than this isn't shown.
const idleShowAge = 3 * 3600

// noteIdleUse keeps the CPU of t's standby units that carried no users' traffic (iran: the
// Iran server's side). A unit that carried traffic clears its side (it wasn't idle).
func (a *App) noteIdleUse(t *Tunnel, keyOf map[string]string, uses []standbyUse, iran bool) {
	now := time.Now().Unix()
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	if a.idleUse == nil {
		a.idleUse = map[string]idleCPU{}
	}
	for _, u := range uses {
		key := keyOf[u.unit]
		if key == "" {
			continue
		}
		cpu := u.cpu
		if u.kbit >= standbyIdleKbit {
			cpu = -1
		}
		k := t.ID + "|" + key
		c, ok := a.idleUse[k]
		if !ok || now-c.At > standbySample*30 {
			c = idleCPU{IR: -1, KH: -1} // the other side is from an older round: not mixed in
		}
		if iran {
			c.IR = cpu
		} else {
			c.KH = cpu
		}
		c.At = now
		a.idleUse[k] = c
	}
}

// idleOfLocked fills v's per-path idle CPU (a copy for the page; call with healthMu held).
// The users' own path shows none: it isn't idle.
func (a *App) idleOfLocked(id string, v *hsView, now int64) {
	v.IdleIR, v.IdleKH = nil, nil
	found := false
	ir, kh := make([]int, len(v.Keys)), make([]int, len(v.Keys))
	for k, key := range v.Keys {
		ir[k], kh[k] = -1, -1
		if c, ok := a.idleUse[id+"|"+key]; ok && now-c.At <= idleShowAge && k != v.Active {
			ir[k], kh[k], found = c.IR, c.KH, true
		}
	}
	if found {
		v.IdleIR, v.IdleKH = ir, kh
	}
}
