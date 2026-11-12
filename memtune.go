package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// memUnit is a systemd unit of a tunnel on one host, and whether it may restart now.
type memUnit struct {
	name    string
	restart bool
}

// memTune gives the units of a running tunnel the Go memory settings (goMemEnv) when they were
// written before those existed: a drop-in next to each unit, so nothing is rebuilt. A unit no
// user is on (a hot-standby path the users aren't on, the probe server) restarts at once to
// take it; the path the users are on — and a tunnel without hot standby — takes it at its next
// restart (or the nightly memNightly), so nobody is cut. Returns how many units got the drop-in.
func (a *App) memTune(ctx context.Context, j *Job, t *Tunnel, ir, kh Host) int {
	n, _ := a.memTuneUnits(ctx, j, t, ir, kh, false)
	return n
}

// memTuneUnits is memTune; users=true also restarts the units users are on. Besides the units
// that got a new drop-in, a unit that may restart and whose running process still has older
// values restarts too. Returns how many units got the drop-in and how many restarted.
func (a *App) memTuneUnits(ctx context.Context, j *Job, t *Tunnel, ir, kh Host, users bool) (int, int) {
	irU, khU := a.memUnitsFor(t, users)
	n, r := 0, 0
	for _, side := range []struct {
		h  Host
		us []memUnit
	}{{ir, irU}, {kh, khU}} {
		if side.h == nil || len(side.us) == 0 {
			continue
		}
		out, err := side.h.Run(ctx, memTuneScript(side.us), nil)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(out, "\n") {
			l = strings.TrimSpace(l)
			if rest, ok := strings.CutPrefix(l, "MEMTUNED"); ok {
				n += len(strings.Fields(rest))
			} else if rest, ok := strings.CutPrefix(l, "MEMRESTARTED"); ok {
				r += len(strings.Fields(rest))
			}
		}
	}
	if n > 0 && j != nil {
		j.log("· %s: Go memory settings added to %d unit(s); paths without users restarted to take them", t.Name, n)
	}
	return n, r
}

// memTuneNeed is memTune's dry run (Repair's check, repair.go): how many units on each side
// lack the current drop-in. It only reads.
func (a *App) memTuneNeed(ctx context.Context, t *Tunnel, ir, kh Host) (irN, khN int) {
	irU, khU := a.memUnitsFor(t, false)
	count := func(h Host, us []memUnit) int {
		if h == nil || len(us) == 0 {
			return 0
		}
		out, err := h.Run(ctx, memNeedScript(us), nil)
		if err != nil {
			return 0
		}
		for _, l := range strings.Split(out, "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "MEMNEED"); ok {
				return len(strings.Fields(rest))
			}
		}
		return 0
	}
	return count(ir, irU), count(kh, khU)
}

// memNeedScript prints "MEMNEED <units whose drop-in is missing or older>"; it changes nothing.
func memNeedScript(us []memUnit) string {
	var all []string
	for _, u := range us {
		all = append(all, shq(u.name))
	}
	return fmt.Sprintf(`need=""
for u in %[1]s; do
  f=/etc/systemd/system/$u
  [ -f "$f" ] || continue
  printf '%%s' %[2]s | cmp -s - "$f.d/90-tunnel-panel-memory.conf" || need="$need $u"
done
echo "MEMNEED$need"
`, strings.Join(all, " "), shq(goMemDropIn))
}

// memUnitsFor lists a tunnel's units on the Iran and on the foreign side, and which may
// restart (users=true: also the ones users are on).
func (a *App) memUnitsFor(t *Tunnel, users bool) (irU, khU []memUnit) {
	var hot bool
	var good []HSPath
	a.store.View(func(*State) { hot, good = t.HotStandby, hsGood(t) })
	if !hot {
		u := memUnit{name: unitName(t), restart: users}
		irU, khU = []memUnit{u}, []memUnit{u}
	} else {
		usersOn := "" // the path the users are on ("" = not known: restart nothing)
		if v := a.hsViewOf(t.ID); v != nil && v.Active >= 0 && v.Active < len(v.Keys) {
			usersOn = v.Keys[v.Active]
		}
		for _, p := range good {
			u := memUnit{name: unitName(pathTunnel(t, p)), restart: users || usersOn != "" && p.Method+"|"+p.Family != usersOn}
			irU, khU = append(irU, u), append(khU, u)
		}
		// the foreign side's probe server carries no users (the switcher waits out its restart)
		khU = append(khU, memUnit{name: unitName(hsUnitTunnel(t)), restart: true})
	}
	return irU, khU
}

// memTuneScript writes the drop-in where a unit lacks the current settings (none yet, or older
// values: the drop-in overrides what the unit file itself says), restarts the ones that may
// restart when they got it or their running process has older values, and prints
// "MEMTUNED <units it changed>" and "MEMRESTARTED <units it restarted>". A unit without a
// running process (oneshot kernel tunnels, a stopped path) is never restarted.
func memTuneScript(us []memUnit) string {
	var all, again []string
	for _, u := range us {
		all = append(all, shq(u.name))
		if u.restart {
			again = append(again, shq(u.name))
		}
	}
	if len(again) == 0 {
		again = []string{"''"}
	}
	return fmt.Sprintf(`done=""; again=""
for u in %[1]s; do
  f=/etc/systemd/system/$u
  [ -f "$f" ] || continue
  printf '%%s' %[3]s | cmp -s - "$f.d/90-tunnel-panel-memory.conf" && continue
  mkdir -p "$f.d" && printf '%%s' %[3]s > "$f.d/90-tunnel-panel-memory.conf" && done="$done $u"
done
[ -n "$done" ] && systemctl daemon-reload
for u in %[2]s; do
  [ -f "/etc/systemd/system/$u" ] || continue
  pid=$(systemctl show -p MainPID --value "$u" 2>/dev/null)
  [ "${pid:-0}" -gt 0 ] 2>/dev/null || continue
  case " $done " in *" $u "*) ;; *) tr '\0' '\n' < /proc/$pid/environ 2>/dev/null | grep -qx %[4]s && continue ;; esac
  systemctl restart "$u" && again="$again $u"
done
echo "MEMTUNED$done"
echo "MEMRESTARTED$again"
`, strings.Join(all, " "), strings.Join(again, " "), shq(goMemDropIn), shq("GOMEMLIMIT="+goMemLimit))
}

// memNightHour is when (Tehran time) memNightly restarts the units users are on — VPN use
// in Iran is at its lowest then.
const memNightHour = "05:00"

// memNightly restarts, once a night, the cores users are on that still run with older memory
// settings (memTune leaves them alone during the day so nobody is cut). A tunnel whose cores
// are current is not touched, so on most nights nothing restarts.
func (a *App) memNightly() {
	done := ""
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for range tick.C {
		now := time.Now().In(tehran)
		if now.Format("15:04") != memNightHour || done == now.Format("2006-01-02") {
			continue
		}
		done = now.Format("2006-01-02")
		var ts []*Tunnel
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.Active != "" {
					ts = append(ts, t)
				}
			}
		})
		var restarted []string
		for _, t := range ts {
			if a.jobs.running(t.ID) != "" || !a.serverReachable(t.ServerID) || (t.ForeignID != "" && !a.serverReachable(t.ForeignID)) {
				continue
			}
			if n := a.memNightOne(t); n > 0 {
				restarted = append(restarted, fmt.Sprintf("%s (%d unit(s))", t.Name, n))
			}
		}
		if len(restarted) > 0 {
			a.pushInfo("🌙 Night restart for the new memory settings (less CPU on the tunnel cores):\n" + strings.Join(restarted, "\n"))
		}
	}
}

func (a *App) memNightOne(t *Tunnel) int {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return 0
	}
	ir, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return 0
	}
	kh, _, err := a.foreignHost(ctx, t, nil)
	if err != nil {
		return 0
	}
	_, r := a.memTuneUnits(ctx, nil, t, ir, kh, true)
	return r
}
