package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The scripts run on this host's real /proc and come back as sane numbers.
func TestResourcesLocal(t *testing.T) {
	ctx := context.Background()
	r := &ServerRes{}
	for i := 0; i < 2; i++ {
		out, err := LocalHost{}.Run(ctx, resRead+resProcs, nil)
		if err != nil && out == "" {
			t.Fatal(err)
		}
		r.apply(parseRes(out), time.Now())
		// some CPU work between the samples, so a process shows up
		end := time.Now().Add(300 * time.Millisecond)
		for time.Now().Before(end) {
		}
	}
	t.Logf("cpu %.1f%% iowait %.1f steal %.1f cores %d load %v mem %d/%d disk %d/%d up %d tcp %d ct %d/%d procs %+v",
		r.CPU, r.IOWait, r.Steal, r.Cores, r.Load, r.MemUsed, r.MemTotal, r.DiskUsed, r.DiskTotal, r.Uptime, r.TCP, r.Conntrack, r.CTMax, r.Procs)
	if r.Error != "" || r.Cores < 1 || r.MemTotal == 0 || r.MemUsed > r.MemTotal || r.DiskTotal == 0 || r.CPU < 0 || r.CPU > 100 || len(r.Hist) != 2 {
		t.Fatalf("bad sample: %+v", r)
	}
	if len(r.Procs) == 0 {
		t.Error("no process list")
	}
	txt := resText("test", r)
	if !strings.Contains(txt, "CPU") || !strings.Contains(txt, "RAM") {
		t.Errorf("bot text: %s", txt)
	}
}

func TestResAlert(t *testing.T) {
	al := &resAlert{}
	c := resCheck{"cpu", "CPU 97%", 97, 90}
	var msgs []string
	for i := 0; i < 4; i++ {
		if m := al.step(c, "iran-1"); m != "" {
			msgs = append(msgs, m)
		}
	}
	c.value, c.what = 20, "CPU 20%"
	if m := al.step(c, "iran-1"); m != "" {
		msgs = append(msgs, m)
	}
	if len(msgs) != 2 || !strings.Contains(msgs[0], "🔥 iran-1: CPU 97%") || !strings.Contains(msgs[1], "back to normal") {
		t.Fatalf("alerts: %q", msgs)
	}
}

// Processes in a tunnel's unit count per unit (each path its own row); others by name, and
// irq + softirq show up as the kernel's packet work.
func TestResPerUnit(t *testing.T) {
	r := &ServerRes{}
	read := func(c string, ticks [4]int) string {
		return c + fmt.Sprintf(`
P 10 %d 1000 paqet-plus tp-aaax1.service
P 11 %d 1000 paqet-plus tp-aaax2.service
P 12 %d 500 xray -
P 13 %d 500 xray -
PE list
`, ticks[0], ticks[1], ticks[2], ticks[3])
	}
	r.apply(parseRes(read("C 100 0 50 800 0 10 40 0 4", [4]int{0, 0, 0, 0})), time.Unix(0, 0))
	r.apply(parseRes(read("C 200 0 100 1600 0 20 80 0 4", [4]int{400, 40, 100, 100})), time.Unix(10, 0))
	if len(r.Procs) != 3 {
		t.Fatalf("rows: %+v", r.Procs)
	}
	if p := r.Procs[0]; p.Unit != "tp-aaax1.service" || p.N != 1 || p.CPU < 9.9 || p.CPU > 10.1 {
		t.Errorf("busiest row: %+v", p)
	}
	if p := r.Procs[1]; p.Name != "xray" || p.N != 2 || p.Unit != "" {
		t.Errorf("by name: %+v", p)
	}
	if r.SoftIRQ < 4.9 || r.SoftIRQ > 5.1 || r.Sys < 4.9 || r.Sys > 5.1 {
		t.Errorf("softirq %.1f sys %.1f", r.SoftIRQ, r.Sys)
	}
}

// The reads between process samples keep each path's name.
func TestResPathNameKept(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Tunnels = []*Tunnel{{ID: "aaa", Name: "nl", HotStandby: true, Paths: []HSPath{{Method: "paqet_plus", Family: "v6", Index: 1}}}}
		return nil
	})
	a := &App{store: st, traffic: newTrafficMon()}
	a.resParse("s", "C 100 0 50 800 0 10 40 0 4\nP 10 0 1000 paqet-plus tp-aaax1.service\nPE list\n")
	a.resParse("s", "C 200 0 100 1600 0 20 80 0 4\nP 10 400 1000 paqet-plus tp-aaax1.service\nPE list\n")
	a.resParse("s", "C 300 0 150 2400 0 30 120 0 4\n")
	p := a.traffic.res["s"].Procs
	if len(p) != 1 || !strings.HasPrefix(p[0].Path, "nl · ") {
		t.Fatalf("procs: %+v", p)
	}
}

// A list cut off part way (the read timed out) is left out: the processes missing from it
// would otherwise look idle on the next sample.
func TestResProcListCut(t *testing.T) {
	r := &ServerRes{}
	r.apply(parseRes(`C 100 0 50 800 0 10 40 0 4
P 10 0 1000 paqet-plus tp-aaax1.service
P 11 0 1000 backpack tp-aaax2.service
PE list
`), time.Unix(0, 0))
	r.apply(parseRes(`C 200 0 100 1600 0 20 80 0 4
P 10 100 1000 paqet-plus tp-aaax1.service
`), time.Unix(5, 0))
	r.apply(parseRes(`C 300 0 150 2400 0 30 120 0 4
P 10 400 1000 paqet-plus tp-aaax1.service
P 11 400 1000 backpack tp-aaax2.service
PE list
`), time.Unix(10, 0))
	if len(r.Procs) != 2 || r.Procs[0].CPU < 9.9 || r.Procs[1].CPU < 9.9 {
		t.Fatalf("procs: %+v", r.Procs)
	}
}

// Packet work piled on one core (one receive queue, RPS off) is named, with the fix; spread
// over the cores it isn't.
func TestResPerCoreIRQ(t *testing.T) {
	read := func(c0, c1 int) string {
		return fmt.Sprintf(`C 100 0 50 800 0 10 40 0 4
c 0 1000 %d
c 1 1000 %d
c 2 1000 0
c 3 1000 0
Q eth0 1 0
`, c0, c1)
	}
	r := &ServerRes{}
	r.apply(parseRes(read(0, 0)), time.Unix(0, 0))
	r.apply(parseRes(strings.ReplaceAll(read(600, 20), "c 0 1000", "c 0 2000")+"c 9 0 0\n"), time.Unix(10, 0))
	if r.CoreIRQ != nil {
		t.Fatalf("a core more than before: no per-core rates, got %v", r.CoreIRQ)
	}
	r = &ServerRes{}
	r.apply(parseRes(read(0, 0)), time.Unix(0, 0))
	next := strings.NewReplacer("c 0 1000", "c 0 2000", "c 1 1000", "c 1 2000", "c 2 1000", "c 2 2000", "c 3 1000", "c 3 2000").Replace(read(600, 20))
	r.apply(parseRes(next), time.Unix(10, 0))
	if len(r.CoreIRQ) != 4 || r.CoreIRQ[0] < 59.9 || r.CoreIRQ[0] > 60.1 || r.CoreIRQ[1] < 1.9 || r.CoreIRQ[1] > 2.1 {
		t.Fatalf("per core: %v", r.CoreIRQ)
	}
	if !strings.Contains(r.IRQHint, "core 0 (60%") || !strings.Contains(r.IRQHint, "echo f > $f") {
		t.Errorf("hint: %q", r.IRQHint)
	}
	r.CoreIRQ = []float64{30, 25, 28, 31}
	if h := irqHint(r); h != "" {
		t.Errorf("spread evenly, still a hint: %q", h)
	}
	r.CoreIRQ, r.RPS = []float64{70, 2, 2, 2}, "f"
	if h := irqHint(r); !strings.Contains(h, "RPS mask f") {
		t.Errorf("RPS on: %q", h)
	}
}
