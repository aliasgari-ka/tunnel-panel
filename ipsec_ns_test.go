package main

// IPsec end to end in network namespaces, with a real strongSwan (charon-systemd + swanctl
// must be installed). Each namespace gets its own /etc/swanctl and strongswan.conf (via
// /etc/netns/<ns>/, so the vici sockets differ), and a stand-in systemctl that runs
// strongswan.service the way systemd does: charon-systemd, then swanctl --load-all, and
// the service fails when that fails. A broken config in the old one-line format is left
// in the foreign conf.d first, as on servers that tried IPsec with an earlier version.
// Run as root with TP_IPSEC_E2E=v4 or v6.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fakeSystemctlIPsec = `#!/bin/bash
F=/etc/tp-fake
cmd=$1; shift; args="$*"
start() {
  [ -f $F/charon.pid ] && kill $(cat $F/charon.pid) 2>/dev/null && sleep 0.5
  setsid nohup /usr/sbin/charon-systemd >>$F/charon.log 2>&1 </dev/null & echo $! > $F/charon.pid
  for i in $(seq 1 30); do swanctl --stats >/dev/null 2>&1 && break; sleep 0.3; done
  # ExecStartPost of strongswan.service: a config that doesn't load fails the service
  swanctl --load-all --noprompt >>$F/charon.log 2>&1 || { kill $(cat $F/charon.pid); rm -f $F/charon.pid; exit 1; }
}
case "$cmd" in
  cat) [[ "$args" == *strongswan.service* ]] && exit 0; exit 1;;
  is-active) exit 1;;
  restart|start) [[ "$args" == *strongswan* && "$args" != *starter* ]] && start; exit 0;;
  stop) [[ "$args" == *strongswan* && "$args" != *starter* && -f $F/charon.pid ]] && kill $(cat $F/charon.pid) 2>/dev/null; exit 0;;
  *) exit 0;;
esac
`

const fakeJournalctlIPsec = "#!/bin/bash\ntail -n 8 /etc/tp-fake/charon.log 2>/dev/null\n"

type nsIPsec struct{ ns, fake string }

func (h nsIPsec) Label() string { return h.ns }
func (h nsIPsec) Run(ctx context.Context, script string, log func(string)) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", h.ns, "env", "PATH="+h.fake+":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "bash", "-s")
	cmd.Stdin = strings.NewReader(scriptPrelude + "export PATH=" + h.fake + ":$PATH\n" + script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func (h nsIPsec) WriteFile(path string, data []byte, mode os.FileMode) error {
	if strings.HasPrefix(path, "/etc/swanctl/") {
		path = "/etc/netns/" + h.ns + strings.TrimPrefix(path, "/etc")
	}
	return LocalHost{}.WriteFile(path, data, mode)
}

func TestIPsecNS(t *testing.T) {
	fam := os.Getenv("TP_IPSEC_E2E")
	if fam == "" {
		t.Skip("set TP_IPSEC_E2E=v4 or v6 (root, network namespaces, strongSwan installed)")
	}
	if _, err := exec.LookPath("charon-systemd"); err != nil {
		t.Skip("charon-systemd not installed")
	}
	fake := t.TempDir()
	_ = os.WriteFile(filepath.Join(fake, "systemctl"), []byte(fakeSystemctlIPsec), 0o755)
	_ = os.WriteFile(filepath.Join(fake, "journalctl"), []byte(fakeJournalctlIPsec), 0o755)
	e2eTopology(t, fam)
	// ip netns exec binds /etc/netns/<ns>/X over /etc/X only where /etc/X exists
	sh(t, "mkdir -p /etc/tp-fake")
	defer sh(t, "for n in tir tkh tus; do ip netns pids $n 2>/dev/null | xargs -r kill; sleep 0.5; ip netns pids $n 2>/dev/null | xargs -r kill -9; ip netns del $n 2>/dev/null; done; rm -rf /etc/netns/tir /etc/netns/tkh; rmdir /etc/tp-fake")
	for _, ns := range []string{"tir", "tkh"} {
		sh(t, fmt.Sprintf(`rm -rf /etc/netns/%[1]s && mkdir -p /etc/netns/%[1]s/tp-fake && cp -a /etc/swanctl /etc/netns/%[1]s/swanctl && rm -f /etc/netns/%[1]s/swanctl/conf.d/*
cat > /etc/netns/%[1]s/strongswan.conf <<'EOF'
charon {
  load_modular = yes
  plugins {
    include strongswan.d/charon/*.conf
    vici {
      socket = unix:///run/tp-%[1]s-charon.vici
    }
  }
}
include strongswan.d/*.conf
charon-systemd {
  plugins {
    vici {
      socket = unix:///run/tp-%[1]s-charon.vici
    }
  }
}
swanctl {
  socket = unix:///run/tp-%[1]s-charon.vici
}
EOF`, ns))
	}
	// what an earlier version left behind after a failed deploy
	sh(t, `printf 'connections {\n  tp9 {\n    local  { auth = psk  id = kh-tp9 }\n    remote { auth = psk  id = ir-tp9 }\n  }\n}\n' > /etc/netns/tkh/swanctl/conf.d/tp9.conf`)

	ir := &Server{ID: "ir", Name: "iran", IPv4: "10.99.0.1"}
	kh := &Server{ID: "kh", Name: "foreign", IPv4: "10.99.0.2", Role: "foreign"}
	if fam == "v6" {
		ir.IPv4, ir.IPv6 = "", "2001:db8:99::1"
		kh.IPv4, kh.IPv6 = "", "2001:db8:99::2"
	}
	tn := &Tunnel{ID: "ips1", Name: "ipsec-test", ServerID: "ir", ForeignID: "kh", Family: fam,
		Ports: "28579", Index: 5, Options: map[string]map[string]string{}, Secrets: map[string]string{}}
	irP, khP, err := buildPlans(methodIPsecV6, tn, ir, kh, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base := t.TempDir()
	sk := &e2eSide{ns: "tkh", label: "KH", dir: base + "/kh", h: nsIPsec{"tkh", fake}, plan: khP}
	si := &e2eSide{ns: "tir", label: "IR", dir: base + "/ir", h: nsIPsec{"tir", fake}, plan: irP}
	j := &Job{Status: "running"}
	logs := func() {
		for _, ns := range []string{"tkh", "tir"} {
			t.Logf("%s charon log:\n%s", ns, sh(t, "grep -v '^plugin ' /etc/netns/"+ns+"/tp-fake/charon.log | tail -n 25"))
			t.Logf("%s view: %s", ns, sh(t, "ls -la /etc/netns/"+ns+"/swanctl/conf.d/; ip netns exec "+ns+" ls -la /etc/swanctl/conf.d/; ip netns exec "+ns+" env PATH="+fake+":$PATH swanctl --list-conns 2>/dev/null | head -5; ip netns exec "+ns+" ip -br link; ip netns exec "+ns+" env PATH="+fake+":$PATH swanctl --list-sas 2>&1 | grep -v '^plugin' | head"))
		}
	}
	if err := sk.up(ctx, t, j, tn); err != nil {
		logs()
		t.Fatalf("foreign deploy: %v", err)
	}
	if err := si.up(ctx, t, j, tn); err != nil {
		logs()
		t.Fatalf("Iran deploy: %v", err)
	}
	if sh(t, "ls /etc/netns/tkh/swanctl/conf.d/tp9.conf 2>/dev/null") != "" {
		t.Error("the broken old-format config was not removed")
	} else {
		t.Log("✓ broken config from the earlier version removed; strongSwan started")
	}
	var got string
	for k := 0; k < 15; k++ {
		got = sh(t, "ip netns exec tus curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 8 http://10.98.0.1:28579/blob.bin")
		if strings.HasPrefix(got, "200 2097152") {
			break
		}
		time.Sleep(2 * time.Second)
	}
	sas := sh(t, "ip netns exec tir env PATH="+fake+":$PATH swanctl --list-sas 2>/dev/null | grep -E 'tp5|ESTABLISHED|INSTALLED|bytes_i' | head -6")
	t.Logf("Iran SAs:\n%s", sas)
	if n := strings.Count(sas, "ESTABLISHED, IKEv2"); n != 1 {
		t.Errorf("%d IKE SAs, want exactly 1", n)
	}
	if strings.HasPrefix(got, "200 2097152") {
		t.Logf("✓ IPsec over %s: 2 MB from an IPv4 user through Iran → ESP → foreign service", fam)
	} else {
		logs()
		t.Errorf("user traffic over IPsec fails (%s)", got)
	}
	espOuter := sh(t, "ip netns exec tir ip -s xfrm state 2>/dev/null | grep -m1 -E '^src' ")
	t.Logf("xfrm state: %s", espOuter)
	si.down(ctx, tn)
	sk.down(ctx, tn)
	if c := sh(t, "ls /etc/netns/tir/swanctl/conf.d/ /etc/netns/tkh/swanctl/conf.d/ | grep -c tp5"); c != "0" {
		t.Errorf("tp5.conf left after stop (%s)", c)
	}
	left := sh(t, "for n in tir tkh; do ip netns exec $n iptables-save 2>/dev/null; ip netns exec $n ip6tables-save 2>/dev/null; done | grep -cE 'TPI_|TPF_|TPM_|TP_tp'")
	if left != "0" {
		t.Errorf("%s firewall rules left after stop", left)
	}
}
