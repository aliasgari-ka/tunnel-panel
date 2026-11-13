package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// A new path list for a switcher that already runs (a path removed, the route's choices
// applied) is one round trip on the Iran server: only the files that changed are written
// (each path's files are named by its key, so the others stay as they are), and the running
// switcher takes the new list on SIGHUP — it keeps what it knows of every path and the users
// stay where they are. A switcher running another script (an older panel's, or one whose
// unit changed) is restarted once instead, as a deploy did every time.

// hsPathFile is the part of path p's own switcher files' names (up-<it>.sh, flush-<it>.sh).
func hsPathFile(p HSPath) string { return p.Method + "." + p.Family }

// hsKeys: "method|family" of each path, in the switcher's order.
func hsKeys(paths []HSPath) []string {
	keys := make([]string, 0, len(paths))
	for _, p := range paths {
		keys = append(keys, p.Method+"|"+p.Family)
	}
	return keys
}

// hsSwitcherSum is the sha256 of the switcher script: a running switcher writes its own to
// "running", and only one running this script is sent a reload.
var hsSwitcherSum = func() string {
	s := sha256.Sum256([]byte(hsSwitcher))
	return hex.EncodeToString(s[:])
}()

// hsReloadWait is how long the panel waits for the switcher to take a new list (a round of
// checks is at most ~5 s) before it restarts it.
const hsReloadWait = 20 * time.Second

// hsReloadScript runs after the switcher's files are written: the setup, then a reload of a
// running switcher of this script, else a restart; then the files of paths no longer on the
// list go. Prints "TP-SW reload" or "TP-SW restart"; "TP-SW-NOPROBE" (exit 75, nothing done)
// when the probe binary is missing.
func hsReloadScript(t *Tunnel, setup string, paths []HSPath) string {
	u, dir := unitName(hsUnitTunnel(t)), hsDir(t)
	var keep []string
	for _, p := range paths {
		keep = append(keep, "up-"+hsPathFile(p)+".sh", "flush-"+hsPathFile(p)+".sh")
	}
	sort.Strings(keep)
	return fmt.Sprintf(`[ -x %[1]s ] || { echo TP-SW-NOPROBE; exit 75; }
( set -e
%[2]s) || exit 1
u=%[3]s; cd %[4]s || exit 1
how=restart
pid=$(systemctl show -p MainPID --value $u 2>/dev/null)
if [ "$(systemctl show -p NeedDaemonReload --value $u 2>/dev/null)" != yes ] && systemctl is-active -q $u && [ -s running ] && read -r rp rs < running \
  && [ -n "$pid" ] && [ "$pid" != 0 ] && [ "$rp" = "$pid" ] && [ "$rs" = %[5]s ] && [ "$(sha256sum < switch.sh | cut -c1-64)" = %[5]s ]; then
  rq=$(date +%%s%%N); echo "$rq" > reload.req; rm -f reload.done
  if kill -HUP "$pid" 2>/dev/null; then
    for i in $(seq %[6]d); do
      if [ -s reload.done ] && read -r ra rb < reload.done && [ "$ra" = "$rq" ]; then [ "$rb" = ok ] && how=reload; break; fi
      sleep 0.1
    done
  fi
  [ $how = reload ] || echo "the switcher didn't take the new list in %[7]d s — restarting it"
fi
if [ $how = restart ]; then
  rm -f /etc/systemd/system/$u.d/90-tunnel-panel-memory.conf
  systemctl daemon-reload
  systemctl enable $u >/dev/null 2>&1
  jl() { journalctl -u $u -n 25 --no-pager -o cat; }
  if ! systemctl restart $u; then jl; exit 1; fi
  sleep 2
  st=$(systemctl is-active $u)
  if [ "$st" != active ]; then echo "unit $u: $st"; jl; exit 1; fi
fi
# the files of paths no longer on the list (and those named by index, before tp-switcher 14)
keep=" %[8]s "
for f in up-*.sh flush-*.sh; do [ -e "$f" ] || continue; case "$keep" in *" $f "*) ;; *) rm -f "$f" ;; esac; done
rm -f reload.req
echo "TP-SW $how"
`, shq(probeBin), setup, shq(u), shq(dir), hsSwitcherSum, int(hsReloadWait/(100*time.Millisecond)), int(hsReloadWait/time.Second), strings.Join(keep, " "))
}

// hsSwitcherUpdate gives the running switcher of t the path list paths (before: the list it
// runs with now, for the users' place). One round trip on ir in the usual case.
func (a *App) hsSwitcherUpdate(ctx context.Context, j *Job, ir Host, t *Tunnel, before, paths []HSPath) error {
	t0 := time.Now()
	sw := a.hsSwitcherPlan(t, paths)
	files := make(map[string]FileSpec, len(sw.Files)+1)
	for k, v := range sw.Files {
		files[k] = v
	}
	files["/etc/systemd/system/"+unitName(hsUnitTunnel(t))] = FileSpec{Content: []byte(renderUnit(sw.Unit)), Mode: 0o644}
	script := hsReloadScript(t, hsActiveRemap(hsDir(t), before, paths)+sw.Setup, paths)
	run := func() (string, string, string, error) {
		var mu sync.Mutex
		how, wrote := "", ""
		out, err := runWithFiles(ctx, ir, files, script, func(l string) {
			s := strings.TrimSpace(l)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.HasPrefix(s, "TP-SW "):
				how = strings.TrimPrefix(s, "TP-SW ")
			case s == "TP-SW-NOPROBE":
			case strings.HasPrefix(s, "wrote ") || strings.HasPrefix(s, "files up to date"):
				wrote = s
			case s != "":
				j.log("[IR] %s", s)
			}
		})
		mu.Lock()
		defer mu.Unlock()
		return out, how, wrote, err
	}
	out, how, wrote, err := run()
	if strings.Contains(out, "TP-SW-NOPROBE") {
		// no probe binary on the server (nothing else was done): installed, then once more
		if err := pushArtifacts(ctx, j, "IR", ir, sw.Artifacts); err != nil {
			return err
		}
		out, how, wrote, err = run()
	}
	if err != nil {
		return withTail(err, stripBatch(out))
	}
	what := "updated"
	switch how {
	case "reload":
		what = "took the new list in place (no restart, users stay on their path)"
	case "restart":
		what = "restarted with the new list"
	}
	if wrote == "" {
		wrote = fmt.Sprintf("%d file(s)", len(files))
	}
	j.log("[IR] switcher: %d paths — %s; %s (%.1f s)", len(paths), wrote, what, time.Since(t0).Seconds())
	return nil
}

// hsHosts reaches the Iran and the foreign server of t at the same time.
func (a *App) hsHosts(ctx context.Context, t *Tunnel) (ir, kh Host, irErr, khErr error) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		kh, _, khErr = a.foreignHost(ctx, t, nil)
	}()
	if srv := a.store.Server(t.ServerID); srv == nil {
		irErr = fmt.Errorf("Iran server not found")
	} else {
		ir, _, irErr = a.reach(ctx, srv, nil)
	}
	wg.Wait()
	return
}
