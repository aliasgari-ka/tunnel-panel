package main

import "testing"

func TestHistAfter(t *testing.T) {
	h := []TrafficPoint{{T: 10}, {T: 12}, {T: 14}}
	at := func(p TrafficPoint) int64 { return p.T }
	if got := histAfter(h, 12, at); len(got) != 1 || got[0].T != 14 {
		t.Fatalf("after 12: %v", got)
	}
	if got := histAfter(h, 5, at); len(got) != 3 {
		t.Fatalf("after 5: %v", got)
	}
	if got := histAfter(h, 20, at); len(got) != 0 {
		t.Fatalf("after 20: %v", got)
	}
}
