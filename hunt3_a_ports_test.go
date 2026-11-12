package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// hunt3: a fake host that also keeps what was written (path -> content).
type h3Host struct {
	h2Host
	fmu   sync.Mutex
	files map[string]string
}

func (h *h3Host) WriteFile(path string, b []byte, m os.FileMode) error {
	h.fmu.Lock()
	if h.files == nil {
		h.files = map[string]string{}
	}
	h.files[path] = string(b)
	h.fmu.Unlock()
	return h.h2Host.WriteFile(path, b, m)
}

func (h *h3Host) file(path string) string {
	h.fmu.Lock()
	defer h.fmu.Unlock()
	return h.files[path]
}

// BUG (portClash / iranPorts ignore non-TCP reverse tunnel ports): the BackPack pck
// methods added today (bp_pckfec, bp_pckturbo) listen on their Iran tunnel port, and the
// firewall opening (tunnelListenPort) knows it, but iranPortSpans only counts a tunnel port
// when reverseTCPPort says "TCP dial" — so another tunnel forwarding the same Iran port,
// or another reverse tunnel pinned to the same tunnel port, is never reported as a clash.
func TestHunt3A_PckTunnelPortNotInClash(t *testing.T) {
	pck := &Tunnel{ID: "aaaaaaaaaaaa", Name: "pck", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 1, Active: "bp_pckfec",
		Options: map[string]map[string]string{"bp_pckfec": {"tunnel_port": "8443"}}}
	// B forwards 8443 to users (GRE: kernel DNAT of Iran:8443 into the tunnel)
	b := &Tunnel{ID: "bbbbbbbbbbbb", Name: "B", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "8443", Index: 2,
		Options: map[string]map[string]string{}}
	st := &State{Tunnels: []*Tunnel{pck, b}}
	if irL, _ := tunnelListenPort(methodByID["bp_pckfec"], pck, func(k string) string { return pck.Options["bp_pckfec"][k] }, deriveFor(pck, &Server{IPv4: "1.1.1.1"}, &Server{IPv4: "2.2.2.2"}, Settings{})); irL != "8443" {
		t.Fatalf("precondition: the pck tunnel listens on Iran %q", irL)
	}
	if _, ok := iranPorts(pck, "")[8443]; !ok {
		t.Errorf("iranPorts(pck tunnel) lacks its Iran tunnel port 8443: %v", iranPorts(pck, ""))
	}
	if err := portClash(st, b, "gre"); err == nil {
		t.Errorf("no clash reported: tunnel B forwards Iran 8443 while tunnel %q's BackPack pck listens on Iran 8443", pck.Name)
	}
	// the same for a second reverse tunnel pinned to the same tunnel port
	c := &Tunnel{ID: "cccccccccccc", Name: "C", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "2096", Index: 3,
		Options: map[string]map[string]string{"bp_pckturbo": {"tunnel_port": "8443"}}}
	st.Tunnels = append(st.Tunnels, c)
	if err := portClash(st, c, "bp_pckturbo"); err == nil {
		t.Errorf("no clash reported: two BackPack pck tunnels on one Iran server both use tunnel port 8443")
	}
	// (bp_reverse with a UDP-based transport has the same gap: kcp listens on UDP 8443)
	d := &Tunnel{ID: "dddddddddddd", Name: "D", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "2097", Index: 4,
		Options: map[string]map[string]string{"bp_reverse": {"transport": "kcp", "tunnel_port": "8443"}}}
	st.Tunnels = append(st.Tunnels, d)
	if err := portClash(&State{Tunnels: []*Tunnel{b, d}}, d, "bp_reverse"); err == nil {
		t.Errorf("no clash reported: BackPack kcp tunnel port 8443 vs tunnel B's forwarded 8443")
	}
}

// BUG (Failback test copy reuses the live tunnel's moved tunnel port): the preflight saves
// a working port (here 8443, the only one the route lets in) in the original method's
// options; on failover the backup reverse method's preflight finds the same port (the
// original is torn down, so 8443 is free). Failback's check then deploys the original on
// the benchmark slot with t.Options[orig] — tunnel_port 8443, the port the live backup
// holds on Iran — so the test copy can't bind, the original "still doesn't work", and the
// tunnel never fails back.
func TestHunt3A_FailbackBenchCopyTakesLivePort(t *testing.T) {
	cacheDir = t.TempDir()
	_ = os.WriteFile(filepath.Join(cacheDir, "backhaul-v0.7.2-amd64"), []byte("bin"), 0o755)
	_ = os.WriteFile(filepath.Join(cacheDir, "backpack-"+backpackVersion+"-amd64"), []byte("bin"), 0o755)
	ir, kh := &h3Host{h2Host: h2Host{name: "ir"}}, &h3Host{h2Host: h2Host{name: "kh"}}
	kh.fn = func(_ context.Context, s string) (string, error, bool) {
		if strings.Contains(s, "echo OK ") && strings.Contains(s, "probe rtt") {
			// 8443 gets through from abroad, and so does 2053 (once 8443 is taken)
			out := ""
			for _, p := range []string{"8443", "2053"} {
				if strings.Contains(s, ":"+p+" ") {
					out += "OK " + p + "\n"
				}
			}
			return out, nil, true
		}
		return "", nil, false
	}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "3000", Index: 1}
	a, st := h2App(t, tn, ir, kh)
	// the original path
	j, err := a.Apply(tn, "bp_reverse")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "ok" {
		t.Fatalf("apply bp_reverse %s:\n%s", s.Status, strings.Join(s.Lines, "\n"))
	}
	// the failover's backup
	j, err = a.Apply(tn, "backhaul")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, j)
	if s := j.snapshot(); s.Status != "ok" {
		t.Fatalf("apply backhaul %s:\n%s", s.Status, strings.Join(s.Lines, "\n"))
	}
	var orig, live string
	st.View(func(*State) {
		orig, live = tn.Options["bp_reverse"]["tunnel_port"], tn.Options["backhaul"]["tunnel_port"]
	})
	t.Logf("original bp_reverse tunnel_port=%s, live backhaul tunnel_port=%s", orig, live)
	liveCfg := ir.file(tunnelDir(tn) + "/backhaul.toml")
	if !strings.Contains(liveCfg, `bind_addr = "0.0.0.0:8443"`) {
		t.Fatalf("precondition: the live backup binds Iran 8443:\n%s", liveCfg)
	}
	// Failback's check of the original on the bench slot
	_ = st.Update(func(*State) error { tn.Failover = &FailoverState{Method: "bp_reverse", Family: "v4"}; return nil })
	jb, _ := a.jobs.start("bench", "failback-check")
	_ = a.testPathOnBenchSlot(context.Background(), jb, tn, "bp_reverse", "v4")
	a.jobs.done(jb)
	bt := &Tunnel{ID: "bench"}
	benchCfg := ir.file(tunnelDir(bt) + "/tp-bench.toml")
	if benchCfg == "" {
		t.Fatalf("the bench copy wasn't written; writes: %v", ir.writes)
	}
	if !strings.Contains(benchCfg, `bind_addr = "0.0.0.0:2053"`) {
		t.Errorf("the failback copy should have moved to the next working port (2053):\n%s", benchCfg)
	}
	if strings.Contains(benchCfg, `bind_addr = "0.0.0.0:8443"`) {
		t.Errorf("the failback test copy binds Iran 0.0.0.0:8443 — the port the live backup tunnel already listens on; the check can only fail:\n%s", benchCfg)
	}
}
