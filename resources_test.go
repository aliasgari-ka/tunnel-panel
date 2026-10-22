package main

import (
	"context"
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
