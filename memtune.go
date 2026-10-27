package main

import (
	"context"
	"fmt"
	"strings"
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
// restart, so nobody is cut. Returns how many units got the drop-in.
func (a *App) memTune(ctx context.Context, j *Job, t *Tunnel, ir, kh Host) int {
	var hot bool
	var good []HSPath
	a.store.View(func(*State) { hot, good = t.HotStandby, hsGood(t) })
	var irU, khU []memUnit
	if !hot {
		u := memUnit{name: unitName(t)}
		irU, khU = []memUnit{u}, []memUnit{u}
	} else {
		usersOn := "" // the path the users are on ("" = not known: restart nothing)
		if v := a.hsViewOf(t.ID); v != nil && v.Active >= 0 && v.Active < len(v.Keys) {
			usersOn = v.Keys[v.Active]
		}
		for _, p := range good {
			u := memUnit{name: unitName(pathTunnel(t, p)), restart: usersOn != "" && p.Method+"|"+p.Family != usersOn}
			irU, khU = append(irU, u), append(khU, u)
		}
		// the foreign side's probe server carries no users (the switcher waits out its restart)
		khU = append(khU, memUnit{name: unitName(hsUnitTunnel(t)), restart: true})
	}
	n := 0
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
			if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "MEMTUNED"); ok {
				n += len(strings.Fields(rest))
			}
		}
	}
	if n > 0 && j != nil {
		j.log("· %s: Go memory settings added to %d unit(s); paths without users restarted to take them", t.Name, n)
	}
	return n
}

// memTuneScript writes the drop-in where a unit lacks the settings, restarts the ones that may
// restart, and prints "MEMTUNED <units it changed>".
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
	return fmt.Sprintf(`done=""
for u in %[1]s; do
  f=/etc/systemd/system/$u
  [ -f "$f" ] || continue
  grep -q GOMEMLIMIT "$f" && continue
  [ -f "$f.d/90-tunnel-panel-memory.conf" ] && continue
  mkdir -p "$f.d" && printf '%%s' %[3]s > "$f.d/90-tunnel-panel-memory.conf" && done="$done $u"
done
if [ -n "$done" ]; then
  systemctl daemon-reload
  for u in %[2]s; do case " $done " in *" $u "*) systemctl restart "$u" ;; esac; done
fi
echo "MEMTUNED$done"
`, strings.Join(all, " "), strings.Join(again, " "), shq(goMemDropIn))
}
