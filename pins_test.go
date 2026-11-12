package main

import (
	"strings"
	"testing"
)

// Third-party cores are pinned (no "latest"), with a sha256 per arch, so the two ends of
// a tunnel can't drift onto different releases and a download prefix can't swap them.
func TestThirdPartyCoresPinned(t *testing.T) {
	set := Settings{GitHubProxy: "https://ghproxy.example/"}
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	tn := &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "8443=443", Index: 3, Secrets: map[string]string{},
		Options: map[string]map[string]string{"spoof": {"spoof_ip": "192.0.2.9", "peer_spoof_ip": "198.51.100.9"}}}
	spoof, _, err := buildPlans(methodSpoofTunnel, tn, srv, fsrv, set)
	if err != nil {
		t.Fatal(err)
	}
	arts := []Artifact{artFRP(set, "frps"), artFRP(set, "frpc"), artBackpack(set), artBackhaul(set), artPaqet(set)}
	arts = append(arts, spoof.Artifacts...)
	for _, a := range arts {
		if strings.Contains(a.Name, "latest") || strings.Contains(a.Fetch, "/latest") {
			t.Errorf("%s follows latest", a.Name)
		}
		if !strings.Contains(a.Fetch, "sha256sum -c") {
			t.Errorf("%s is not checksum-checked", a.Name)
		}
		if !strings.Contains(a.Fetch, "amd64)") || !strings.Contains(a.Fetch, "arm64)") {
			t.Errorf("%s lacks a pinned sum for both arches", a.Name)
		}
		if !strings.Contains(a.Fetch, set.GitHubProxy) {
			t.Errorf("%s ignores the download prefix", a.Name)
		}
	}
	if n := artFRP(Settings{}, "frps").Name; n != "frp-frps-"+frpDefault {
		t.Errorf("blank FRP version gives %q", n)
	}
	if n := artFRP(Settings{FRPVersion: "v" + frpDefault}, "frpc").Name; n != "frp-frpc-"+frpDefault {
		t.Errorf("v-prefixed default gives %q", n)
	}
	// another version from Settings: its own release's checksum list
	o := artFRP(Settings{FRPVersion: "0.71.1"}, "frpc")
	if o.Name != "frp-frpc-0.71.1" || !strings.Contains(o.Fetch, "frp_sha256_checksums.txt") || !strings.Contains(o.Fetch, "VER='0.71.1'") {
		t.Errorf("Settings FRP version not honoured: %s\n%s", o.Name, o.Fetch)
	}
}
