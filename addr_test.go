package main

import (
	"context"
	"os"
	"testing"
)

type fakeHost struct{ out string }

func (f fakeHost) Label() string { return "IR" }
func (f fakeHost) Run(context.Context, string, func(string)) (string, error) {
	return f.out, nil
}
func (f fakeHost) WriteFile(string, []byte, os.FileMode) error { return nil }

func TestDetectAddrs(t *testing.T) {
	cases := []struct{ out, v4, v6 string }{
		{"V4=185.10.20.30\nV6=2a01:4f8:1:2::5\n", "185.10.20.30", "2a01:4f8:1:2::5"},
		{"V4=10.0.0.5\nV6=\nPUB4=5.6.7.8\n", "5.6.7.8", ""},
		{"V4=10.0.0.5\nV6=fd42:1::1\nPUB4=\n", "", ""},
		{"V4=100.70.1.1\nV6=fe80::1\nPUB4=garbage\n", "", ""},
	}
	for _, c := range cases {
		v4, v6 := detectAddrs(context.Background(), fakeHost{c.out})
		if v4 != c.v4 || v6 != c.v6 {
			t.Errorf("%q: got %q %q, want %q %q", c.out, v4, v6, c.v4, c.v6)
		}
	}
}

func TestWithTail(t *testing.T) {
	out := "Oct 22 10:00:00 h backhaul[12]: FATAL bad port 0\nunit tp-x.service: failed\n"
	err := withTail(errString("Process exited with status 1"), out)
	if err == nil || err.Error() != "Process exited with status 1 — FATAL bad port 0" {
		t.Fatalf("got %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRankBench(t *testing.T) {
	rs := []BenchResult{
		{Method: "a", OK: true, DownMbps: 20, UpMbps: 10, Mbps: 15, RTTms: 110},
		{Method: "b", OK: false, Error: "x"},
		{Method: "s", Skipped: true},
		{Method: "c", OK: true, DownMbps: 200, UpMbps: 80, Mbps: 140, RTTms: 115},
	}
	rankBench(rs)
	if rs[0].Method != "c" || !rs[0].Recommended || rs[1].Method != "a" || rs[0].Score <= rs[1].Score {
		t.Fatalf("bad ranking: %+v", rs)
	}
	if rs[2].Method != "b" || rs[3].Method != "s" {
		t.Fatalf("failed should precede skipped: %+v", rs)
	}
}
