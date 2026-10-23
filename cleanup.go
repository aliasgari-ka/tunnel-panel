package main

import (
	"context"
	"fmt"
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

// deferCleanup remembers that server id still has t's leftovers.
func (a *App) deferCleanup(id string, t *Tunnel) {
	if id == "" {
		return
	}
	c := Cleanup{ServerID: id, TunnelID: t.ID, Name: t.Name, Indices: tunnelIndices(t), Script: cleanupScript(t), Since: time.Now().Unix()}
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
		if t := a.store.Tunnel(c.TunnelID); t != nil && t.Active != "" {
			a.dropCleanup(id, c.TunnelID)
			continue
		}
		if out, _ := h.Run(ctx, c.Script+"\necho TP-TEARDOWN-DONE\n", nil); !strings.Contains(out, "TP-TEARDOWN-DONE") {
			return // didn't get through: the next time the server answers
		}
		a.dropCleanup(id, c.TunnelID)
		a.push(fmt.Sprintf("🧹 %s: removed what tunnel %q left there while the server was unreachable (since %s Tehran)", srv.Name, c.Name, clock(time.Unix(c.Since, 0))))
	}
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
