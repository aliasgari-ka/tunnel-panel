package main

import (
	"testing"
	"time"
)

// A resource read (the same lines resRead prints) gives the server's size in bytes.
func TestHardwareFromRead(t *testing.T) {
	out := "C 10 0 5 100 1 0 0 0 4\nM 4000000 3000000 0 0\nD 41000000 11000000 28000000\n"
	hw := hwOf(parseRes(out), time.Unix(1000, 0))
	if hw == nil {
		t.Fatal("no hardware from a full read")
	}
	if hw.Cores != 4 || hw.MemTotal != 4000000*1024 || hw.MemUsed != 1000000*1024 || hw.DiskTotal != 41000000*1024 || hw.DiskFree != 28000000*1024 || hw.At != 1000 {
		t.Fatalf("got %+v", hw)
	}
	// an old-style df line (no Available): free = total - used
	hw = hwOf(parseRes("C 1 0 1 1 0 0 0 0 2\nM 100 50 0 0\nD 1000 400\n"), time.Unix(1, 0))
	if hw == nil || hw.DiskFree != 600*1024 {
		t.Fatalf("old df: %+v", hw)
	}
	if hwOf(parseRes("M 100 50 0 0\n"), time.Now()) != nil {
		t.Fatal("a read without the CPU line must give nothing")
	}
}

// Only a real change (or an old record) is written; the minute-by-minute jitter is not.
func TestHardwareChanged(t *testing.T) {
	now := time.Unix(100000, 0)
	old := &Hardware{Cores: 2, MemTotal: 1000, MemUsed: 400, DiskTotal: 10000, DiskFree: 5000, At: now.Unix() - 60}
	same := *old
	same.MemUsed, same.DiskFree, same.At = 420, 4900, now.Unix()
	if hwChanged(old, &same, now) {
		t.Fatal("2% RAM / 1% disk move must not be written")
	}
	if !hwChanged(nil, &same, now) {
		t.Fatal("a first read must be written")
	}
	more := same
	more.Cores = 4
	if !hwChanged(old, &more, now) {
		t.Fatal("other core count must be written")
	}
	ram := same
	ram.MemUsed = 600
	if !hwChanged(old, &ram, now) {
		t.Fatal("a 20% RAM move must be written")
	}
	if !hwChanged(old, &same, now.Add(hwSaveEvery)) {
		t.Fatal("an old record must be refreshed")
	}
}

// saveHW writes the servers' and the panel host's sizes, and leaves an unchanged one alone.
func TestSaveHW(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = append(s.Servers, &Server{ID: "s1", Name: "a"}, &Server{ID: "s2", Name: "b"})
		return nil
	})
	a := &App{store: st, jobs: newJobs(), agents: newAgentHub()}
	now := time.Unix(5000, 0)
	a.saveHW(map[string]*Hardware{"s1": {Cores: 2, MemTotal: 1 << 30, DiskTotal: 1 << 34, At: 5000}, "": {Cores: 8, MemTotal: 1 << 33, At: 5000}}, now)
	st.View(func(s *State) {
		if s.Servers[0].HW == nil || s.Servers[0].HW.Cores != 2 || s.Servers[1].HW != nil || s.HostHW == nil || s.HostHW.Cores != 8 {
			t.Fatalf("after save: s1=%+v s2=%+v host=%+v", s.Servers[0].HW, s.Servers[1].HW, s.HostHW)
		}
	})
	// a jitter-only read a minute later keeps the stored record (and its time)
	a.saveHW(map[string]*Hardware{"s1": {Cores: 2, MemTotal: 1 << 30, MemUsed: 1 << 20, DiskTotal: 1 << 34, At: 5060}}, now.Add(time.Minute))
	st.View(func(s *State) {
		if s.Servers[0].HW.At != 5000 {
			t.Fatalf("jitter rewrote the record: %+v", s.Servers[0].HW)
		}
	})
}
