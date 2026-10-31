package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"strings"
	"testing"
)

// WireGuard: each side's config names the other's public key (derived from its private
// key), both share one preshared key, only the dialer has an Endpoint, and the keys stay
// the same on every apply.
func TestWireGuardBuild(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "81.12.35.113", IPv6: "2a05:9080::1"}
	fsrv := &Server{ID: "kh", IPv4: "51.68.197.222", IPv6: "2001:41d0::1", Role: "foreign"}
	tn := &Tunnel{ID: "t1", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 2}

	ir, kh, err := buildPlans(methodWireGuard, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	irConf, khConf := wgConf(t, ir), wgConf(t, kh)
	if irConf["ListenPort"] != "40010" || khConf["ListenPort"] != "40010" {
		t.Errorf("per-tunnel port should be BasePort+2 = 40010, got %q / %q", irConf["ListenPort"], khConf["ListenPort"])
	}
	if irConf["PublicKey"] != pubOf(t, khConf["PrivateKey"]) || khConf["PublicKey"] != pubOf(t, irConf["PrivateKey"]) {
		t.Error("each side must name the other's public key")
	}
	if irConf["PrivateKey"] == khConf["PrivateKey"] {
		t.Error("the two sides need different keys")
	}
	if irConf["PresharedKey"] == "" || irConf["PresharedKey"] != khConf["PresharedKey"] {
		t.Error("both sides need the same preshared key")
	}
	// Iran dials by default; the foreign side only listens
	if irConf["Endpoint"] != "51.68.197.222:40010" || irConf["PersistentKeepalive"] != "25" {
		t.Errorf("Iran should dial the foreign server, got endpoint %q keepalive %q", irConf["Endpoint"], irConf["PersistentKeepalive"])
	}
	if khConf["Endpoint"] != "" {
		t.Error("the foreign side should only listen")
	}
	irUp := scriptBody(ir, "/up.sh")
	for _, want := range []string{"ip link add tp2 type wireguard", "cat /etc/tunnel-panel/t/t1/wg.conf | wg setconf tp2 /dev/stdin", "mtu 1380", "ip addr add 10.10.2.1/30 dev tp2", "--to-destination 10.10.2.2"} {
		if !strings.Contains(irUp, want) {
			t.Errorf("Iran up.sh missing %q", want)
		}
	}
	if strings.Contains(irUp, "wg-quick") {
		t.Error("wg-quick would change the host's routes")
	}
	for _, p := range []SidePlan{ir, kh} {
		if f := p.Files["/etc/tunnel-panel/t/t1/wg.conf"]; f.Mode != 0o600 {
			t.Errorf("wg.conf holds the private key: mode %o, want 600", f.Mode)
		}
		if !strings.Contains(p.Setup, "wireguard-tools") {
			t.Error("setup should install the wg tool when missing")
		}
	}
	// the listening side opens its port to everyone (the dialer may come from another address)
	if !strings.Contains(scriptBody(kh, "/fw-in-up.sh"), "-p udp --dport 40010 -j ACCEPT") {
		t.Error("foreign firewall should open the WireGuard port")
	}

	// the same keys on the next apply
	ir2, _, _ := buildPlans(methodWireGuard, tn, srv, fsrv, Settings{})
	if wgConf(t, ir2)["PrivateKey"] != irConf["PrivateKey"] {
		t.Error("keys must not change between applies")
	}

	// foreign dials over IPv6, own port
	tn6 := &Tunnel{ID: "t2", Name: "uk6", ServerID: "ir", ForeignID: "kh", Family: "v6", Ports: "443", Index: 3,
		Options: map[string]map[string]string{"wg": {"dialer": "foreign", "port": "51820"}}}
	ir6, kh6, err := buildPlans(methodWireGuard, tn6, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if c := wgConf(t, kh6); c["Endpoint"] != "[2a05:9080::1]:51820" {
		t.Errorf("foreign should dial Iran's IPv6, got %q", c["Endpoint"])
	}
	if wgConf(t, ir6)["Endpoint"] != "" {
		t.Error("Iran should only listen when the foreign side dials")
	}
	if !strings.Contains(scriptBody(ir6, "/fw-in-up.sh"), "--dport 51820 -j ACCEPT") {
		t.Error("Iran firewall should open the WireGuard port when it listens")
	}

	tnBad := &Tunnel{ID: "t3", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 4,
		Options: map[string]map[string]string{"wg": {"port": "70000"}}}
	if _, _, err := buildPlans(methodWireGuard, tnBad, srv, fsrv, Settings{}); err == nil {
		t.Error("port 70000 should be refused")
	}

	if !benchIsL3(methodWireGuard, nil) || userspaceIran(methodWireGuard, tn) {
		t.Error("WireGuard is a kernel L3 tunnel")
	}
}

func wgConf(t *testing.T, p SidePlan) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, ln := range strings.Split(scriptBody(p, "/wg.conf"), "\n") {
		if k, v, ok := strings.Cut(ln, " = "); ok {
			out[k] = v
		}
	}
	if out["PrivateKey"] == "" {
		t.Fatal("no wg.conf with a private key")
	}
	return out
}

func pubOf(t *testing.T, priv string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad private key %q", priv)
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
