package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// nsHost runs on one network namespace (the filesystem is shared).
type nsHost struct{ ns string }

func (h nsHost) Label() string { return h.ns }
func (h nsHost) Run(ctx context.Context, script string, log func(string)) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", h.ns, "bash", "-s")
	cmd.Stdin = strings.NewReader(scriptPrelude + script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func (h nsHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	return LocalHost{}.WriteFile(path, data, mode)
}

func TestReversePreflightNS(t *testing.T) {
	if os.Getenv("TP_NS_TEST") == "" {
		t.Skip()
	}
	dataDir = t.TempDir()
	st, err := LoadStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}, {ID: "kh", Name: "ovh", IPv4: "10.99.0.2", Role: "foreign"}}
		return nil
	})
	a := &App{store: st, jobs: newJobs()}
	m := methodByID["backhaul"]
	tn := &Tunnel{ID: "rv", Name: "rev", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "28579", Index: 7, Options: map[string]map[string]string{}}
	j, _ := a.jobs.start("", "t")
	ctx := context.Background()
	changed, err := a.reversePreflight(ctx, j, tn, m, nsHost{"tir"}, nsHost{"tkh"})
	for _, l := range j.snapshot().Lines {
		t.Log(l)
	}
	t.Logf("changed=%v err=%v options=%v", changed, err, tn.Options)
	if want := os.Getenv("TP_NS_WANT"); want == "error" {
		if err == nil {
			t.Fatal("expected an error")
		}
	} else if err != nil || tn.Options["backhaul"]["tunnel_port"] != want {
		t.Fatalf("want tunnel_port=%s", want)
	}
}
