package main

import (
	"strings"
	"testing"
)

// BUG (hot standby: a pinned tunnel port is given to the method's v4 AND v6 path): the
// path's options are the tunnel's options (pathTunnel), so a tunnel port the user set for a
// reverse method goes to both of that method's paths. On Iran the v4 path binds
// 0.0.0.0:<port> and the v6 path [::]:<port> — a dual-stack listener that collides with the
// first (Linux default bindv6only=0: "address already in use"). The preflight never moves a
// pinned port, portClash skips the tunnel's own paths, so the second path always fails and
// its hourly retry fails again, forever.
func TestHunt3A_HSPinnedPortSharedByBothFamilies(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.10", IPv6: "2001:db8::10"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.20", IPv6: "2001:db8::20", Role: "foreign"}
	tn := &Tunnel{ID: "aaaaaaaaaaaa", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "2096", Index: 1, HotStandby: true,
		Options: map[string]map[string]string{"bp_multi": {"tunnel_port": "8443"}}, Secrets: map[string]string{}}
	p4 := HSPath{Method: "bp_multi", Family: "v4", Index: 7}
	p6 := HSPath{Method: "bp_multi", Family: "v6", Index: 8}
	binds := map[string]string{}
	for _, p := range []HSPath{p4, p6} {
		pt := pathTunnel(tn, p)
		ir, _, err := buildPlans(methodByID["bp_multi"], pt, srv, fsrv, Settings{})
		if err != nil {
			t.Fatal(err)
		}
		for path, f := range ir.Files {
			if strings.HasSuffix(path, ".toml") {
				for _, l := range strings.Split(string(f.Content), "\n") {
					if strings.HasPrefix(l, "bind_addr") {
						binds[p.Family] = l
					}
				}
			}
		}
	}
	t.Logf("v4 path: %s | v6 path: %s", binds["v4"], binds["v6"])
	if strings.HasSuffix(binds["v4"], ":8443\"") && strings.HasSuffix(binds["v6"], ":8443\"") {
		t.Errorf("both hot-standby paths of bp_multi listen on Iran port 8443 (0.0.0.0 and [::]): the second can't bind")
	}
	// and nothing reports it
	st := &State{Tunnels: []*Tunnel{tn}}
	if err := portClash(st, pathTunnel(tn, p6), "bp_multi"); err == nil {
		t.Logf("(portClash: no clash reported for the v6 path)")
	}
}
