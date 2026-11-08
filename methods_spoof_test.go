package main

import (
	"strings"
	"testing"
)

// A mapped port "8443=443": users connect to 8443 on Iran, the foreign side delivers to its
// service on 443 (it forwarded to 127.0.0.1:8443, where nothing listens).
func TestSpoofForwardsToMappedPort(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "192.0.2.1"}
	fsrv := &Server{ID: "kh", IPv4: "198.51.100.2"}
	tn := &Tunnel{ID: "t1", Name: "t", Family: "v4", Ports: "8443=443", Index: 3, Secrets: map[string]string{},
		Options: map[string]map[string]string{"spoof": {"spoof_ip": "192.0.2.9", "peer_spoof_ip": "198.51.100.9"}}}
	ir, kh, err := buildPlans(methodSpoofTunnel, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	var irCfg, khCfg string
	for path, f := range ir.Files {
		if strings.HasSuffix(path, "/spoof.json") {
			irCfg = string(f.Content)
		}
	}
	for path, f := range kh.Files {
		if strings.HasSuffix(path, "/spoof.json") {
			khCfg = string(f.Content)
		}
	}
	if !strings.Contains(khCfg, `"forward": "127.0.0.1:443"`) {
		t.Errorf("foreign config does not forward to the mapped port:\n%s", khCfg)
	}
	if !strings.Contains(irCfg, `"listen": "0.0.0.0:8443"`) || !strings.Contains(irCfg, `"spoof_port": 8443`) {
		t.Errorf("Iran config does not listen on the users' port:\n%s", irCfg)
	}
}
