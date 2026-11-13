package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// Narrowing the packet filter of Backhaul Premium ipx cores that already run.
//
// A core started by a unit of this version narrows its own filter (premiumCarrierFilter, its
// ExecStartPost). Units written before it — and a core whose socket the watcher missed —
// are narrowed from here: soon after the panel starts, then every hour, on both servers of
// every tunnel with such a path. Nothing restarts: the filter of the running socket is
// replaced in place and the carrier's own packets (tcp 443 -> 443 from the peer) pass as
// before, so it is safe on the users' own path too.

const premiumFilterEvery = time.Hour

// premiumTCPUnits are t's units that run a Premium ipx core with the tcp carrier (the
// running hot-standby paths, or the tunnel itself). Call inside the store lock.
func premiumTCPUnits(t *Tunnel) []string {
	var pts []*Tunnel
	if t.HotStandby && len(t.Paths) > 0 {
		for _, p := range t.Paths {
			if p.Method == methodPremium.ID && p.Failed == "" {
				pts = append(pts, pathTunnel(t, p))
			}
		}
	} else if t.Active == methodPremium.ID {
		pts = append(pts, t)
	}
	var us []string
	for _, pt := range pts {
		get, _ := resolveOptions(methodPremium, pt.Options[methodPremium.ID])
		if get("mode") == "ipx" && get("profile") == "tcp" {
			us = append(us, unitName(pt))
		}
	}
	return us
}

// premiumFilterScript narrows the filter of each unit's core (peer: the other server's public
// IPv4). One line per unit from the probe; an old probe without the command prints nothing.
func premiumFilterScript(units []string, peer string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "P=%s\n[ -x \"$P\" ] || exit 0\n", probeBin)
	for _, u := range units {
		fmt.Fprintf(&b, "pid=$(systemctl show -p MainPID --value %[1]s 2>/dev/null); [ \"${pid:-0}\" -gt 0 ] 2>/dev/null && timeout 20 \"$P\" pktfilter -pid \"$pid\" -unit %[1]s -peer %[2]s -proto 6 -sport 443 -dport 443 -wait 0s 2>&1 | sed 's/^/%[3]s: /'\n",
			shq(u), shq(peer), strings.TrimSuffix(u, ".service"))
	}
	return b.String()
}

func (a *App) premiumFilterSweep() {
	time.Sleep(2 * time.Minute)
	for {
		type item struct {
			t     *Tunnel
			units []string
		}
		var items []item
		a.store.View(func(st *State) {
			for _, t := range st.Tunnels {
				if t.Active == "" {
					continue
				}
				if us := premiumTCPUnits(t); len(us) > 0 {
					items = append(items, item{t, us})
				}
			}
		})
		for _, it := range items {
			if a.jobs.running(it.t.ID) != "" || !a.serverReachable(it.t.ServerID) || (it.t.ForeignID != "" && !a.serverReachable(it.t.ForeignID)) {
				continue
			}
			for _, l := range a.premiumFilterOne(it.t, it.units) {
				if strings.Contains(l, "narrowed") {
					log.Printf("%s: %s", it.t.Name, l)
				}
			}
		}
		time.Sleep(premiumFilterEvery)
	}
}

// premiumFilterOne narrows the cores of units on both servers of t; returns what the probe said.
func (a *App) premiumFilterOne(t *Tunnel, units []string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	srv := a.store.Server(t.ServerID)
	if srv == nil {
		return nil
	}
	khPub := a.settings().LocalIPv4
	if f := a.store.Server(t.ForeignID); f != nil {
		khPub = f.IPv4
	}
	var out []string
	side := func(label string, h Host, peer string) {
		if h == nil || peer == "" {
			return
		}
		if err := pushArtifacts(ctx, &Job{}, label, h, []Artifact{probeArt}); err != nil {
			return
		}
		o, _ := h.Run(ctx, premiumFilterScript(units, peer), nil)
		for _, l := range strings.Split(strings.TrimSpace(o), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, label+" "+l)
			}
		}
	}
	if ir, _, err := a.reach(ctx, srv, nil); err == nil {
		side("IR", ir, khPub)
	}
	if kh, _, err := a.foreignHost(ctx, t, nil); err == nil {
		side("KH", kh, srv.IPv4)
	}
	return out
}
