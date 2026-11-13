package main

import (
	"fmt"
	"strings"
)

// Standby cost: every hot-standby path runs its cores all the time, also while nobody is on
// it. A core the server has to emulate (the amd64 Backhaul Premium and TP Tunnel cores under
// box64/qemu on an arm64 server, the arm64-only Premium v1 under qemu on amd64) costs several
// times its native CPU for each packet, and on a server with 2 cores that standby took a
// share the users' own path needed (usa-kharej, 2 arm64 cores, ~90 % busy, 2026-11-13).
//
// Auto mode leaves such a path out of the standby list on that route when at least
// hsCheapEnough cheaper paths worked on the route's benchmark. It never takes out a path that
// runs (the next full Start of the tunnel plans without it), nor one the user asked for by
// hand (put back after a removal, or "use" on it: HSWant); the user can still remove or
// add any path on the card.

// hsCheapEnough: cheaper paths that must have worked on the benchmark before an expensive
// one is left out (the switcher still needs somewhere to go).
const hsCheapEnough = 2

// hsSmallCores: a server with at most this many cores can't spare an emulated standby core.
const hsSmallCores = 2

func archIsARM(arch string) bool {
	a := strings.ToLower(arch)
	return strings.HasPrefix(a, "aarch64") || strings.HasPrefix(a, "arm")
}

func archIsX86(arch string) bool {
	a := strings.ToLower(arch)
	return a == "x86_64" || a == "amd64"
}

// methodEmulatedOn: m's core runs under emulation on a server of this arch.
func methodEmulatedOn(m *Method, arch string) bool {
	switch {
	case m == nil || arch == "":
		return false
	case m.HelperArch == "amd64":
		return archIsARM(arch)
	case m.ID == methodPremiumV1.ID: // the vendor's arm64 build only (v1Emulated)
		return archIsX86(arch)
	}
	return false
}

// hsCostlyOn says why m is expensive as a standby path between srv and fsrv ("" = it isn't):
// it is emulated on a server with at most hsSmallCores cores (its size as last read).
func hsCostlyOn(m *Method, srv, fsrv *Server) string {
	for _, s := range []*Server{srv, fsrv} {
		if s == nil || s.HW == nil || s.HW.Cores <= 0 || s.HW.Cores > hsSmallCores {
			continue
		}
		if methodEmulatedOn(m, s.Arch) {
			return fmt.Sprintf("%s runs emulated on %s (%s, %d cores)", m.Title, s.Name, s.Arch, s.HW.Cores)
		}
	}
	return ""
}

// hsLeaveOutForCost: auto mode doesn't add m over f to t's standby paths (see above). have
// lists the paths that run now; they stay.
func (a *App) hsLeaveOutForCost(t *Tunnel, m *Method, f string, have map[string]bool) string {
	key := m.ID + "|" + f
	if have[key] {
		return ""
	}
	var srv, fsrv *Server
	want := false
	a.store.View(func(*State) { want = contains(t.HSWant, key) })
	if want {
		return ""
	}
	srv, fsrv = a.store.Server(t.ServerID), a.store.Server(t.ForeignID)
	why := hsCostlyOn(m, srv, fsrv)
	if why == "" {
		return ""
	}
	// cheaper paths that worked on this route's benchmark
	cheap := 0
	for _, fam := range a.routeFamilies(t) {
		for _, r := range a.benchResults(t.ServerID, t.ForeignID, fam) {
			o := methodByID[r.Method]
			if !r.OK || r.Score <= 0 || o == nil || (o.ID == m.ID && fam == f) || hsCostlyOn(o, srv, fsrv) != "" || !a.hsCandidateBase(t, o, fam) {
				continue
			}
			cheap++
		}
	}
	if cheap < hsCheapEnough {
		return ""
	}
	return why
}

// hsWantPath records that the user asked for mid|fam on t by hand (or, on, takes it off).
func (a *App) hsWantPath(t *Tunnel, key string, on bool) {
	_ = a.store.Update(func(*State) error {
		var keep []string
		for _, k := range t.HSWant {
			if k != key {
				keep = append(keep, k)
			}
		}
		if on {
			keep = append(keep, key)
		}
		t.HSWant = keep
		return nil
	})
}
