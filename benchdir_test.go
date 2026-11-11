package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A method whose upload stalls is no working tunnel, even when its download passes (seen
// live: the pck turbo copy's upload timed out, its download "measured" 244 Mbit/s, and
// the benchmark ranked it best on the route).
func TestBenchOneDirectionStallsIsFailure(t *testing.T) {
	for _, dir := range []string{"up", "down"} {
		ir, kh := &h2Host{name: "ir"}, &h2Host{name: "kh"}
		ir.fn = func(_ context.Context, s string) (string, error, bool) {
			isDown := strings.Contains(s, "probe bw -down")
			if strings.Contains(s, "probe bw") && (isDown == (dir == "down")) {
				return `{"error":"send failed: write tcp 127.0.0.1:62152->127.0.0.1:41002: i/o timeout"}`, nil, true
			}
			return "", nil, false
		}
		tn := &Tunnel{ID: "t1", Name: "one", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1}
		a, _ := h2App(t, tn, ir, kh)
		j, err := a.Bench(BenchRequest{IranID: "ir", ForeignID: "kh", Family: "v4", Methods: []string{"gre"}})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; j.snapshot().Status == "running" && i < 1500; i++ {
			time.Sleep(20 * time.Millisecond)
		}
		rs := a.benchResults("ir", "kh", "v4")
		if len(rs) != 1 || rs[0].OK || rs[0].Recommended || !strings.Contains(rs[0].Error, "stalls") {
			t.Errorf("%s stalls: %+v", dir, rs)
		}
	}
}
