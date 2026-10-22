package main

// Failover end to end, through the real Apply/Stop/deploy code (systemd replaced by
// testdata/fakesd). Each namespace gets its own /etc/tunnel-panel, /etc/systemd and
// /etc/backpack via /etc/netns/<ns>/ bind mounts. Needs root and a kernel with ip6gre;
// run with TP_FAILOVER_E2E=1.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nsSD struct{ ns, fake string }

func (h nsSD) Label() string { return h.ns }
func (h nsSD) Run(ctx context.Context, script string, log func(string)) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", h.ns, "env", "PATH="+h.fake+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "bash", "-s")
	cmd.Stdin = strings.NewReader(scriptPrelude + "export PATH=" + h.fake + ":$PATH\n" + script)
	out, err := cmd.CombinedOutput()
	if log != nil {
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			log(l)
		}
	}
	return string(out), err
}
func (h nsSD) WriteFile(path string, data []byte, mode os.FileMode) error {
	for _, p := range []string{"/etc/tunnel-panel", "/etc/systemd", "/etc/backpack"} {
		if strings.HasPrefix(path, p) {
			path = "/etc/netns/" + h.ns + strings.TrimPrefix(path, "/etc")
		}
	}
	return LocalHost{}.WriteFile(path, data, mode)
}

func TestFailoverNS(t *testing.T) {
	if os.Getenv("TP_FAILOVER_E2E") == "" {
		t.Skip("set TP_FAILOVER_E2E=1 (root, network namespaces, ip6gre)")
	}
	fake, _ := filepath.Abs("testdata/fakesd")
	sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done")
	for _, ns := range []string{"tir", "tkh"} {
		sh(t, "rm -rf /etc/netns/"+ns+" && mkdir -p /etc/netns/"+ns+"/tunnel-panel /etc/netns/"+ns+"/systemd/system /etc/netns/"+ns+"/backpack /etc/tunnel-panel /etc/backpack")
	}
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/tir /etc/netns/tkh")
	e2eTopology(t, "v6")
	// dual-stack underlay: add IPv4 too, so failover can move v6 → v4
	sh(t, "ip -n tir addr add 10.99.0.1/24 dev vir; ip -n tkh addr add 10.99.0.2/24 dev vkh")

	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	_ = st.Update(func(s *State) error {
		s.Servers = []*Server{{ID: "ir", Name: "iran", IPv4: "10.99.0.1", IPv6: "2001:db8:99::1"},
			{ID: "kh", Name: "foreign", IPv4: "10.99.0.2", IPv6: "2001:db8:99::2", Role: "foreign"}}
		s.Tunnels = []*Tunnel{{ID: "fo1", Name: "failover-test", ServerID: "ir", ForeignID: "kh", Family: "v6",
			Ports: "28579", Index: 30, Options: map[string]map[string]string{}, Secrets: map[string]string{}}}
		return nil
	})
	a := &App{store: st, jobs: newJobs(), traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	a.hostFor = func(s *Server) Host {
		if s.ID == "ir" {
			return nsSD{"tir", fake}
		}
		return nsSD{"tkh", fake}
	}
	tn := st.Tunnel("fo1")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	user := func() bool {
		for k := 0; k < 6; k++ {
			if strings.HasPrefix(sh(t, "ip netns exec tus curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 6 http://10.98.0.1:28579/blob.bin"), "200 2097152") {
				return true
			}
			time.Sleep(2 * time.Second)
		}
		return false
	}
	step := func(name string, ok bool) {
		mark := "✓"
		if !ok {
			mark = "✕"
			t.Errorf("FAILED: %s", name)
		}
		t.Logf("%s %s   [now: %s %s, failover=%v]", mark, name, tn.Active, tn.Family, tn.Failover != nil)
	}
	jobLog := func(prefix string) {
		for _, j := range []*Job{a.jobs.latestFor("fo1"), a.jobs.latestFor(failoverJobKey + "fo1")} {
			if j != nil {
				for _, l := range j.snapshot().Lines {
					if strings.Contains(l, "trying") || strings.Contains(l, "✓") || strings.Contains(l, "✕") || strings.Contains(l, "ERROR") || strings.Contains(l, "restoring") {
						t.Log("   " + prefix + " " + l)
					}
				}
			}
		}
	}

	err := a.applyAndWait(ctx, tn, "gre")
	step("start Plain GRE over IPv6", err == nil)
	if err != nil {
		jobLog("apply")
		t.FailNow()
	}
	step("user traffic passes on GRE/v6", user())

	// many real servers drop ping: health and Diagnose must still see a working tunnel
	sh(t, "ip netns exec tkh iptables -w -I INPUT -p icmp --icmp-type echo-request -j DROP")
	_, _, link := a.Health(ctx, tn)
	step("ping blocked → health still says link up ("+link+")", link == "up")
	if dj, err := a.Diagnose(tn); err == nil {
		for dj.snapshot().Status == "running" {
			time.Sleep(time.Second)
		}
		var crosses []string
		for _, l := range dj.snapshot().Lines {
			if strings.Contains(l, "✕") || strings.Contains(l, "⚠") || strings.Contains(l, "DONE") {
				crosses = append(crosses, strings.TrimSpace(l))
				t.Log("   diagnose " + strings.TrimSpace(l))
			}
		}
		step("ping blocked → Diagnose finds no problem", strings.Contains(strings.Join(crosses, "\n"), "no problem found"))
	} else {
		step("diagnose starts: "+err.Error(), false)
	}
	sh(t, "ip netns exec tkh iptables -w -D INPUT -p icmp --icmp-type echo-request -j DROP")

	sh(t, "ip netns exec tkh ip6tables -w -I INPUT -p 47 -j DROP")
	step("ip6gre blocked → user traffic stops", !user())

	a.Failover(tn, "test: ip6gre blocked on the path")
	jobLog("failover")
	step("failover found a working path", tn.Failover != nil && !(tn.Active == "gre" && tn.Family == "v6"))
	step("user traffic passes on the backup path", user())

	sh(t, "ip netns exec tkh ip6tables -w -D INPUT -p 47 -j DROP")
	a.Failback(tn)
	step("failback returned to the original GRE/v6", tn.Active == "gre" && tn.Family == "v6" && tn.Failover == nil)
	step("user traffic passes after failback", user())

	j, _ := a.Stop(tn)
	for j.snapshot().Status == "running" {
		time.Sleep(time.Second)
	}
	left := sh(t, "for n in tir tkh; do ip netns exec $n iptables-save; ip netns exec $n ip6tables-save; done 2>/dev/null | grep -cE 'TPI_|TPF_|TPM_|TP_tp|tp-trace|TPA[IO]_'")
	step("stop leaves no firewall rules ("+left+")", left == "0")
}
