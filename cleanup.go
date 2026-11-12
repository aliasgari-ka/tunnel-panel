package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cleanups a server missed: a Stop or a delete while it was unreachable left the tunnel's
// unit, interface and firewall chains behind there. The teardown is kept and run as soon as
// the server answers again, and until then the tunnel's numbers (interface tpN, subnet,
// ports) are not handed to a new tunnel, which would clash with the leftovers.

// Cleanup is one teardown waiting for its server.
type Cleanup struct {
	ServerID string `json:"serverId"` // "" = this panel host (never pending: always reachable)
	TunnelID string `json:"tunnelId"`
	Name     string `json:"name"`
	Indices  []int  `json:"indices"` // the tunnel's index and its hot-standby paths'
	Script   string `json:"script"`
	Since    int64  `json:"since"`
}

// cleanupScript is everything a tunnel may have left on a server.
func cleanupScript(t *Tunnel) string { return teardownScript(t) + hsTeardown(t) }

func tunnelIndices(t *Tunnel) []int {
	out := []int{t.Index}
	for _, p := range t.Paths {
		if p.Index != t.Index {
			out = append(out, p.Index)
		}
	}
	return out
}

// teardownOn removes t from server id over h; when the script doesn't run to its end (the
// connection dropped), the cleanup is kept for when the server answers again.
func (a *App) teardownOn(ctx context.Context, h Host, id string, t *Tunnel, log func(string)) bool {
	out, _ := h.Run(ctx, cleanupScript(t)+"\necho TP-TEARDOWN-DONE\n", log)
	if strings.Contains(out, "TP-TEARDOWN-DONE") {
		a.dropCleanup(id, t.ID)
		return true
	}
	a.deferCleanup(id, t)
	return false
}

// applyTeardown runs an apply's own teardown of t on server id; once it ran to its end, a
// cleanup a Stop left there for t has been done too and is dropped — run later, it would
// take the new deploy down. It reports whether the script ran to its end.
func (a *App) applyTeardown(ctx context.Context, j *Job, side string, h Host, id string, t *Tunnel, script string) bool {
	out, _ := h.Run(ctx, script+"\necho TP-TEARDOWN-DONE\n", func(l string) {
		if l != "TP-TEARDOWN-DONE" {
			j.log("[%s] %s", side, l)
		}
	})
	if strings.Contains(out, "TP-TEARDOWN-DONE") {
		a.dropCleanup(id, t.ID)
		return true
	}
	return false
}

// teardownPaths stops hot-standby paths that are leaving t.Paths on both servers. Once a
// path is out of t.Paths no Stop or delete of t knows its unit any more, so a side where the
// teardown doesn't run to its end keeps a cleanup of its own, under the path's id (a cleanup
// under t's id would be dropped as soon as t runs again).
//
// All of them, on both servers, go down at the same time: each path is its own unit and
// files, and waiting for one before the next only made a removal take longer.
func (a *App) teardownPaths(ctx context.Context, ir, kh Host, t *Tunnel, paths []HSPath) {
	var wg sync.WaitGroup
	for _, p := range paths {
		pt := pathTunnel(t, p)
		for _, s := range []struct {
			h  Host
			id string
		}{{ir, t.ServerID}, {kh, t.ForeignID}} {
			if s.h == nil {
				a.deferCleanupScript(s.id, pt, teardownScript(pt))
				continue
			}
			wg.Add(1)
			go func(h Host, id string) {
				defer wg.Done()
				if out, _ := h.Run(ctx, teardownScript(pt)+"\necho TP-TEARDOWN-DONE\n", nil); !strings.Contains(out, "TP-TEARDOWN-DONE") {
					a.deferCleanupScript(id, pt, teardownScript(pt))
				}
			}(s.h, s.id)
		}
	}
	wg.Wait()
}

// deferHSLeftovers keeps cleanups, under their own ids, for paths of t (and its switcher
// and probe server when hot standby goes off) on the sides whose teardown didn't run to its end.
func (a *App) deferHSLeftovers(t *Tunnel, paths []HSPath, ir, kh, switcher bool) {
	for _, s := range []struct {
		failed bool
		id     string
	}{{ir, t.ServerID}, {kh, t.ForeignID}} {
		if !s.failed {
			continue
		}
		for _, p := range paths {
			pt := pathTunnel(t, p)
			a.deferCleanupScript(s.id, pt, teardownScript(pt))
		}
		if switcher {
			hs := hsUnitTunnel(t)
			hs.Index = -1 // holds no tunnel number
			a.deferCleanupScript(s.id, hs, teardownScript(hs)+hsSelectDown(t)+hsAcctDown(t))
		}
	}
}

// deferCleanup remembers that server id still has t's leftovers.
func (a *App) deferCleanup(id string, t *Tunnel) { a.deferCleanupScript(id, t, cleanupScript(t)) }

// deferCleanupScript remembers that server id still needs script run for t.
func (a *App) deferCleanupScript(id string, t *Tunnel, script string) {
	if id == "" {
		return
	}
	c := Cleanup{ServerID: id, TunnelID: t.ID, Name: t.Name, Indices: tunnelIndices(t), Script: script, Since: time.Now().Unix()}
	_ = a.store.Update(func(st *State) error {
		for i, x := range st.Cleanups {
			if x.ServerID == id && x.TunnelID == t.ID {
				st.Cleanups[i] = c // the newest teardown covers the older one
				return nil
			}
		}
		st.Cleanups = append(st.Cleanups, c)
		return nil
	})
}

// dropCleanup: the tunnel was torn down on that server after all (a later Stop or apply).
func (a *App) dropCleanup(id, tunnelID string) {
	_ = a.store.Update(func(st *State) error {
		keep := st.Cleanups[:0]
		for _, x := range st.Cleanups {
			if !(x.ServerID == id && x.TunnelID == tunnelID) {
				keep = append(keep, x)
			}
		}
		st.Cleanups = keep
		return nil
	})
}

var cleanupBusy sync.Map // server id → a cleanup run is in progress

// runCleanups runs what server id missed (called when the server monitor sees it answer).
func (a *App) runCleanups(id string) {
	var todo []Cleanup
	a.store.View(func(st *State) {
		for _, x := range st.Cleanups {
			if x.ServerID == id {
				todo = append(todo, x)
			}
		}
	})
	if len(todo) == 0 {
		return
	}
	if _, busy := cleanupBusy.LoadOrStore(id, true); busy {
		return
	}
	defer cleanupBusy.Delete(id)
	srv := a.store.Server(id)
	if srv == nil {
		_ = a.store.Update(func(st *State) error { // the server itself was deleted
			keep := st.Cleanups[:0]
			for _, x := range st.Cleanups {
				if x.ServerID != id {
					keep = append(keep, x)
				}
			}
			st.Cleanups = keep
			return nil
		})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	h, _, err := a.reach(ctx, srv, nil)
	if err != nil {
		return
	}
	for _, c := range todo {
		// a tunnel that runs again (re-applied meanwhile) has its own units in place: skip
		var active, applying string
		owner, inUse := c.TunnelID, false
		if t := a.store.Tunnel(c.TunnelID); t != nil {
			a.store.View(func(*State) { active, applying = t.Active, t.Applying })
		} else if parent, part := splitCleanupID(c.TunnelID); part != "" {
			// a hot-standby path ("<id>x<n>") or switcher ("<id>hs") of a tunnel that still exists:
			// back in use when the tunnel lists that path again / runs hot standby again
			if t := a.store.Tunnel(parent); t != nil {
				owner = parent
				a.store.View(func(*State) {
					applying = t.Applying
					if part == "hs" {
						inUse = t.HotStandby && t.Active != ""
					}
					for _, p := range t.Paths {
						inUse = inUse || part == "x"+strconv.Itoa(p.Index)
					}
				})
			}
		}
		if active != "" || inUse {
			a.dropCleanup(id, c.TunnelID)
			continue
		}
		// being applied right now (Active is empty mid-deploy): the teardown would take the new
		// deploy down — left for the apply, which drops it after its own teardown
		if applying != "" || a.jobs.running(owner) != "" {
			continue
		}
		if out, _ := h.Run(ctx, c.Script+"\necho TP-TEARDOWN-DONE\n", nil); !strings.Contains(out, "TP-TEARDOWN-DONE") {
			return // didn't get through: the next time the server answers
		}
		a.dropCleanup(id, c.TunnelID)
		a.pushChInfo(fmt.Sprintf("🧹 %s: removed what tunnel %q left there while the server was unreachable (since %s Tehran)", srv.Name, c.Name, clock(time.Unix(c.Since, 0))))
	}
}

// splitCleanupID splits a hot-standby part's id into its tunnel's id and the part ("x97",
// "hs"); a tunnel's own id gives part "".
func splitCleanupID(id string) (tunnel, part string) {
	if len(id) <= 12 {
		return id, ""
	}
	return id[:12], id[12:]
}

// pendingIndices are tunnel numbers still held by leftovers on some server.
func pendingIndices(st *State) map[int]bool {
	out := map[int]bool{}
	for _, c := range st.Cleanups {
		for _, i := range c.Indices {
			out[i] = true
		}
	}
	return out
}
