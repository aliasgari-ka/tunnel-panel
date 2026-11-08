package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func tpkConf(t *testing.T, p SidePlan) map[string]any {
	t.Helper()
	for path, f := range p.Files {
		if strings.HasSuffix(path, "/config.json") {
			var m map[string]any
			if err := json.Unmarshal(f.Content, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatal("no config.json")
	return nil
}

func tpkFile(p SidePlan, suffix string) []byte {
	for path, f := range p.Files {
		if strings.HasSuffix(path, suffix) {
			return f.Content
		}
	}
	return nil
}

// TP Tunnel: Iran serves the users' ports with the certificate whose key the foreign side
// pins, the two ends share the PSK and the ed25519 pair, and the keys survive a rebuild.
func TestTPKBuild(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "81.12.35.113", IPv6: "2a05:9080::1"}
	fsrv := &Server{ID: "kh", IPv4: "51.68.197.222", IPv6: "2001:41d0::1", Role: "foreign"}
	tn := &Tunnel{ID: "t1", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443,8080=80", Index: 2}

	ir, kh, err := buildPlans(methodTPK, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	s, c := tpkConf(t, ir), tpkConf(t, kh)
	if s["role"] != "server" || c["role"] != "client" || s["transport"] != "tls" {
		t.Fatalf("roles/transport: %v %v %v", s["role"], c["role"], s["transport"])
	}
	if s["psk"] != c["psk"] || len(s["psk"].(string)) != 64 {
		t.Error("both ends need the same 32-byte PSK")
	}
	if pub, priv := s["pub"].(string), c["priv"].(string); len(priv) != 128 || !strings.HasSuffix(priv, pub) {
		t.Error("client priv must be seed+pub of the server's pub key")
	}
	if c["remote"] != "81.12.35.113:"+strings.TrimPrefix(s["listen"].(string), "0.0.0.0:") {
		t.Errorf("client dials %v, server listens %v", c["remote"], s["listen"])
	}
	ports := strings.Join(toStrings(s["ports"]), ",")
	if !strings.Contains(ports, "443") || !strings.Contains(ports, "8080=80") {
		t.Errorf("server ports %q", ports)
	}
	if allow := strings.Join(toStrings(c["allow"]), ","); !strings.Contains(allow, "127.0.0.1:80") || !strings.Contains(allow, "127.0.0.1:443") {
		t.Errorf("client allow %q", allow)
	}
	// the pin is sha256 of the certificate's public key
	b, _ := pem.Decode(tpkFile(ir, "/server.crt"))
	if b == nil {
		t.Fatal("no server.crt")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if c["pin"] != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Error("client pin doesn't match the server certificate")
	}
	if len(tpkFile(kh, "/server.key")) != 0 {
		t.Error("the server key must stay on Iran")
	}
	if !strings.Contains(ir.Unit.ExecStart, tpkBin+" tunnel ") || len(ir.Artifacts) != 1 || ir.Artifacts[0].Asset != "tpk-agent" {
		t.Errorf("unit/artifact: %q %v", ir.Unit.ExecStart, ir.Artifacts)
	}
	// stable across applies
	ir2, _, _ := buildPlans(methodTPK, tn, srv, fsrv, Settings{})
	if string(tpkFile(ir2, "/server.crt")) != string(tpkFile(ir, "/server.crt")) || tpkConf(t, ir2)["psk"] != s["psk"] {
		t.Error("keys changed on rebuild")
	}

	// IPv6: listen on all v6 addresses, dial Iran's v6 in brackets
	tn6 := &Tunnel{ID: "t2", Name: "uk6", ServerID: "ir", ForeignID: "kh", Family: "v6", Ports: "443", Index: 3}
	ir6, kh6, err := buildPlans(methodTPK, tn6, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tpkConf(t, ir6)["listen"].(string), "[::]:") || !strings.HasPrefix(tpkConf(t, kh6)["remote"].(string), "[2a05:9080::1]:") {
		t.Errorf("v6 listen/remote: %v %v", tpkConf(t, ir6)["listen"], tpkConf(t, kh6)["remote"])
	}
}

// TP Reverse: one CA per tunnel signs Iran's server certificate (for Iran's address) and
// the foreign client certificate (clientAuth); both verify against it.
func TestTPKReverseBuild(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "81.12.35.127"}
	fsrv := &Server{ID: "kh", IPv4: "57.128.183.71", Role: "foreign"}
	tn := &Tunnel{ID: "t1", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "43913", Index: 4}
	ir, kh, err := buildPlans(methodTPKReverse, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	s, c := tpkConf(t, ir), tpkConf(t, kh)
	if s["mode"] != "server" || c["mode"] != "client" || c["server_name"] != "81.12.35.127" {
		t.Fatalf("conf: %v %v", s, c)
	}
	// the probe port is forwarded too, so there are several forwards
	if !strings.Contains(strings.Join(toStrings(s["forwards"]), ","), ":43913") || !strings.Contains(strings.Join(toStrings(c["targets"]), ","), "127.0.0.1:43913") {
		t.Errorf("forwards %v targets %v", s["forwards"], c["targets"])
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(tpkFile(ir, "/ca.pem")) || string(tpkFile(ir, "/ca.pem")) != string(tpkFile(kh, "/ca.pem")) {
		t.Fatal("both ends need the same CA")
	}
	parse := func(b []byte) *x509.Certificate {
		p, _ := pem.Decode(b)
		if p == nil {
			t.Fatal("bad pem")
		}
		x, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	if _, err := parse(tpkFile(ir, "/identity.pem")).Verify(x509.VerifyOptions{Roots: pool, DNSName: "81.12.35.127"}); err != nil {
		t.Errorf("server cert: %v", err)
	}
	cc := parse(tpkFile(kh, "/identity.pem"))
	if _, err := cc.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || cc.Subject.CommonName != "tp-reverse" {
		t.Errorf("client cert: %v %q", err, cc.Subject.CommonName)
	}
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// On an ARM server the core runs under qemu-x86_64, which rejects TCP_CONGESTION: that
// side's config leaves "cc" out, the native side keeps it.
func TestTPKNoCCOnEmulatedSide(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "81.12.35.113", Arch: "x86_64"}
	fsrv := &Server{ID: "kh", IPv4: "159.195.238.75", Role: "foreign", Arch: "aarch64"}
	for _, m := range []*Method{methodTPK, methodTPKReverse} {
		tn := &Tunnel{ID: "t" + m.ID, Name: "us", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 5}
		ir, kh, err := buildPlans(m, tn, srv, fsrv, Settings{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := tpkConf(t, kh)["cc"]; ok {
			t.Errorf("%s: emulated foreign side still sets cc", m.ID)
		}
		if tpkConf(t, ir)["cc"] != "bbr" {
			t.Errorf("%s: native Iran side lost cc", m.ID)
		}
		if !strings.Contains(kh.Setup, "net.ipv4.tcp_congestion_control=bbr") || ir.Setup != "" {
			t.Errorf("%s: bbr should become the default on the emulated side only:\nkh %q\nir %q", m.ID, kh.Setup, ir.Setup)
		}
	}
}
