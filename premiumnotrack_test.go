package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Seen live 2026-11-11 21:55 UTC: the IG agent's wide catch (nat OUTPUT -p tcp --dports
// 80,443 -j REDIRECT) took every packet of the Premium ipx tcp carrier (443 -> 443, no
// handshake: each packet a new connection to NAT) into a local proxy, and every Premium ipx
// path stopped. The carrier stays out of connection tracking on both servers, like PCK's.
func TestPremiumIpxNotrack(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	tn := &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "443", Index: 3, Secrets: map[string]string{}}
	ir, kh, err := buildPlans(methodPremium, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		side string
		p    SidePlan
		peer string
	}{{"iran", ir, "198.51.100.2"}, {"foreign", kh, "192.0.2.1"}} {
		var up, down string
		for path, f := range c.p.Files {
			switch filepath.Base(path) {
			case "fw-up.sh":
				up = string(f.Content)
			case "fw-down.sh":
				down = string(f.Content)
			}
		}
		for _, want := range []string{
			"-t raw -I OUTPUT -p tcp -d " + c.peer + " --sport 443 --dport 443",
			"-t raw -I PREROUTING -p tcp -s " + c.peer + " --sport 443 --dport 443",
		} {
			if !strings.Contains(up, want) || !strings.Contains(up, "-j NOTRACK") {
				t.Errorf("%s fw-up.sh lacks %q:\n%s", c.side, want, up)
			}
		}
		if !strings.Contains(down, "-t raw -D OUTPUT -p tcp -d "+c.peer) || !strings.Contains(down, "-t raw -D PREROUTING -p tcp -s "+c.peer) {
			t.Errorf("%s fw-down.sh doesn't remove them:\n%s", c.side, down)
		}
		if _, err := exec.LookPath("bash"); err != nil {
			continue
		}
		// up twice adds each rule once; down removes them all
		dir := t.TempDir()
		fake := `rules=` + filepath.ToSlash(filepath.Join(dir, "rules")) + `; touch $rules
iptables() { local a=("$@"); local op=""; local i; for i in "${!a[@]}"; do case "${a[$i]}" in -C|-I|-D|-A|-N|-F|-X) op=${a[$i]}; r="${a[*]:$((i+1))}";; esac; done
  [ "${a[3]}" = raw ] || [ "${a[2]}" = raw ] || return 0
  case $op in -C) grep -qxF "$r" $rules;; -I) echo "$r" >> $rules;; -D) grep -qxF "$r" $rules || return 1; grep -vxF "$r" $rules > $rules.n; mv $rules.n $rules;; esac; }
`
		run := func(s string) {
			cmd := exec.Command("bash", "-c", fake+strings.TrimPrefix(s, "#!/bin/bash\n"))
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, b)
			}
		}
		run(up)
		run(up)
		b, _ := os.ReadFile(filepath.Join(dir, "rules"))
		if n := strings.Count(string(b), "NOTRACK"); n != 2 {
			t.Errorf("%s: after fw-up twice %d NOTRACK rules, want 2:\n%s", c.side, n, b)
		}
		run(down)
		b, _ = os.ReadFile(filepath.Join(dir, "rules"))
		if strings.TrimSpace(string(b)) != "" {
			t.Errorf("%s: fw-down left %q", c.side, b)
		}
	}
}
