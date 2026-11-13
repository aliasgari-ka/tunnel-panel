package main

import "time"

// Hardware is a server's size — CPU cores, RAM and the root disk — as the once-a-minute
// resource check (resWatch: nproc, /proc/meminfo, df /) last read it. Kept in the state so
// the Servers page shows it at once, also while the server is unreachable. Bytes.
type Hardware struct {
	Cores     int    `json:"cores"`
	MemTotal  uint64 `json:"memTotal"`
	MemUsed   uint64 `json:"memUsed"` // total - available (what programs really hold)
	DiskTotal uint64 `json:"diskTotal"`
	DiskFree  uint64 `json:"diskFree"` // free for programs (df's Available)
	At        int64  `json:"at"`       // when it was read
}

// hwSaveEvery: an unchanged size is written again after this long (so "read N min ago" stays
// true); hwShift: a change in used RAM or free disk of this share of the total is written at once.
const (
	hwSaveEvery = 30 * time.Minute
	hwShift     = 0.05
)

// hwOf turns one resource read into a Hardware; nil when the read had no CPU or RAM line.
func hwOf(s resSample, now time.Time) *Hardware {
	if !s.ok || !s.hasMem || s.cores <= 0 {
		return nil
	}
	used := uint64(0)
	if s.mem > s.avail {
		used = s.mem - s.avail
	}
	free := s.diskAvail
	if free == 0 && s.disk > s.diskUsed { // an older read without df's Available column
		free = s.disk - s.diskUsed
	}
	return &Hardware{Cores: s.cores, MemTotal: s.mem * 1024, MemUsed: used * 1024, DiskTotal: s.disk * 1024, DiskFree: free * 1024, At: now.Unix()}
}

// hwChanged: worth a state write — a first read, other hardware (cores, RAM or disk size —
// a resized VPS), used RAM or free disk moved by hwShift of the total, or the last write is old.
func hwChanged(old, nw *Hardware, now time.Time) bool {
	if nw == nil {
		return false
	}
	if old == nil || old.Cores != nw.Cores || moved(old.MemTotal, nw.MemTotal, nw.MemTotal, 0.01) || moved(old.DiskTotal, nw.DiskTotal, nw.DiskTotal, 0.01) {
		return true
	}
	if moved(old.MemUsed, nw.MemUsed, nw.MemTotal, hwShift) || moved(old.DiskFree, nw.DiskFree, nw.DiskTotal, hwShift) {
		return true
	}
	return now.Sub(time.Unix(old.At, 0)) >= hwSaveEvery
}

func moved(a, b, total uint64, share float64) bool {
	d := float64(a) - float64(b)
	if d < 0 {
		d = -d
	}
	return d > share*float64(total)
}

// saveHW stores what one round of the resource check read, in one state write (none when
// nothing changed enough). Key "" is this panel host.
func (a *App) saveHW(seen map[string]*Hardware, now time.Time) {
	dirty := false
	a.store.View(func(st *State) {
		for id, hw := range seen {
			if id == "" {
				dirty = dirty || hwChanged(st.HostHW, hw, now)
				continue
			}
			for _, s := range st.Servers {
				if s.ID == id && hwChanged(s.HW, hw, now) {
					dirty = true
				}
			}
		}
	})
	if !dirty {
		return
	}
	_ = a.store.Update(func(st *State) error {
		for id, hw := range seen {
			if id == "" {
				if hwChanged(st.HostHW, hw, now) {
					st.HostHW = hw
				}
				continue
			}
			for _, s := range st.Servers {
				if s.ID == id && hwChanged(s.HW, hw, now) {
					s.HW = hw
				}
			}
		}
		return nil
	})
}
