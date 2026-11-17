package main

import "reflect"

// One machine, one driver.
//
// The same machine can be on the IG Routing page twice: once as the admin's server and once as
// another person's (nl = هلند1, usa = usa-kharej). Each entry had its own automatic state, so the
// loops that move routes and size the WARP pool ran twice against one agent, with two memories:
// on 2026-11-17 one entry moved NL's Google "back from own IP" at 04:50 and the other "to own IP"
// at 04:58, 05:22 … - five router restarts between 08:19 and 09:54 Tehran, each one cutting every
// user of that server and changing Instagram's exit IP.
//
// Now only one entry per machine drives it: the admin's, or the first one when none is the
// admin's. The other entries (twins) are never acted on; they show a copy of the driver's state.

// igDrivers returns the IG Routing servers the automatic loops act on: one per machine (IPv4).
func igDrivers(servers []*Server) []*Server {
	at := map[string]int{}
	var out []*Server
	for _, x := range servers {
		if !x.Igproxy {
			continue
		}
		if x.IPv4 == "" {
			out = append(out, x)
			continue
		}
		i, ok := at[x.IPv4]
		switch {
		case !ok:
			at[x.IPv4] = len(out)
			out = append(out, x)
		case out[i].Owner != "" && x.Owner == "":
			out[i] = x // the admin's entry drives
		}
	}
	return out
}

// igTwinMap: twin entry id -> its driver's id.
func igTwinMap(servers []*Server) map[string]string {
	drv := map[string]string{}
	for _, d := range igDrivers(servers) {
		if d.IPv4 != "" {
			drv[d.IPv4] = d.ID
		}
	}
	tw := map[string]string{}
	for _, x := range servers {
		if x.Igproxy && x.IPv4 != "" && drv[x.IPv4] != "" && drv[x.IPv4] != x.ID {
			tw[x.ID] = drv[x.IPv4]
		}
	}
	return tw
}

func igAutoClone(m map[string]*IgAutoSvc) map[string]*IgAutoSvc {
	if m == nil {
		return nil
	}
	out := make(map[string]*IgAutoSvc, len(m))
	for k, v := range m {
		if v != nil {
			c := *v
			out[k] = &c
		}
	}
	return out
}

func wpClone(p *WarpPool) *WarpPool {
	if p == nil {
		return nil
	}
	c := *p
	if p.BadAt != nil {
		c.BadAt = make(map[string]int64, len(p.BadAt))
		for k, v := range p.BadAt {
			c.BadAt[k] = v
		}
	}
	return &c
}

// igTwinCopy puts the driver's records on its twins in st; it reports whether anything changed.
func igTwinCopy(st *State) bool {
	changed := false
	for tw, drv := range igTwinMap(st.Servers) {
		if !reflect.DeepEqual(st.IgAuto[tw], st.IgAuto[drv]) {
			if st.IgAuto[drv] == nil {
				delete(st.IgAuto, tw)
			} else {
				st.IgAuto[tw] = igAutoClone(st.IgAuto[drv])
			}
			changed = true
		}
		if !reflect.DeepEqual(st.WarpPool[tw], st.WarpPool[drv]) {
			if st.WarpPool[drv] == nil {
				delete(st.WarpPool, tw)
			} else {
				st.WarpPool[tw] = wpClone(st.WarpPool[drv])
			}
			changed = true
		}
	}
	return changed
}

// igTwinSync shows the driver's state on the twin entries (their cards read it by their own id).
// The store is written only when something differs.
func (a *App) igTwinSync() {
	need := false
	var tw map[string]string
	a.store.View(func(st *State) {
		tw = igTwinMap(st.Servers)
		for t, d := range tw {
			if !reflect.DeepEqual(st.IgAuto[t], st.IgAuto[d]) || !reflect.DeepEqual(st.WarpPool[t], st.WarpPool[d]) {
				need = true
			}
		}
	})
	if need {
		_ = a.store.Update(func(st *State) error {
			igTwinCopy(st)
			return nil
		})
	}
	// the live readings (memory only): the twin's card shows what the driver read
	igExMem.Lock()
	for t, d := range tw {
		if m := igExMem.live[d]; m != nil {
			igExMem.live[t] = m
		}
	}
	igExMem.Unlock()
}
