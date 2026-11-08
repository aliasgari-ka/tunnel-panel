package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"
)

func init() {
	register(methodTPK)
	register(methodTPKReverse)
}

// TP Tunnel / TP Reverse: the tunnel core of the botping panel ("tunpanel" tp-agent 1.20.9,
// closed source, linux amd64 only; ARM servers run it under qemu-x86_64). Iran is the server: it listens on the tunnel port and on
// the users' ports; the foreign server dials it and opens the users' connections locally.
// The binary isn't in this (public) repository: it is uploaded as the helper tpk-agent-amd64
// (Settings → Helper binaries, or /etc/tunnel-panel/helpers on the panel host). It is named
// tpk-agent because the panel's own helper is already called tp-agent.
const (
	tpkBin          = "/opt/tpk/tpk-agent"
	tpkMaxForwarded = 400
)

var tpkArt = Artifact{Name: "tpk-agent", Asset: "tpk-agent", Dest: tpkBin, Mode: 0o755}

var methodTPK = &Method{
	ID:         "tpk",
	Title:      "TP Tunnel",
	Desc:       "botping's TP Tunnel (tp-agent 1.20.9; amd64 build, run under qemu on ARM servers): TLS / raw / WebSocket / HTTP/2 / UDP carrier with an ed25519 key, a pinned certificate and padding. Iran listens on the tunnel port and the users' ports, the foreign server dials Iran.",
	Families:   []string{"v4", "v6"},
	Encrypt:    "chacha20/aes + ed25519",
	Helper:     "tpk-agent",
	HelperArch: "amd64",
	Fields: []Field{
		{Key: "transport", Label: "Transport", Type: "select", Default: "tls", Options: []string{"tls", "raw", "wss", "h2", "udp"}},
		{Key: "port", Label: "Tunnel port", Type: "number", Default: "", Help: "port Iran listens on for the foreign server (blank = auto, unique per tunnel)"},
		{Key: "cipher", Label: "Cipher", Type: "select", Default: "chacha", Options: []string{"chacha", "aes"}},
		{Key: "cc", Label: "Congestion control", Type: "select", Default: "bbr", Options: []string{"bbr", "cubic"}},
		{Key: "procs", Label: "Processes", Type: "number", Default: "2"},
		{Key: "sessions", Label: "Sessions", Type: "number", Default: "6", Help: "parallel connections the foreign server keeps to Iran"},
		{Key: "pad_max", Label: "Max padding (bytes)", Type: "number", Default: "256", Advanced: true},
		{Key: "rotate_min", Label: "Rotate sessions every (min)", Type: "number", Default: "30", Help: "0 = never", Advanced: true},
		{Key: "path", Label: "Path (wss/h2)", Type: "text", Default: "/tp", Advanced: true},
		{Key: "sni", Label: "SNI / Host", Type: "text", Default: "", Help: "blank = Iran's address", Advanced: true},
	},
	// Iran's IPv4 filtering often drops the TLS look on new ports; raw and wss look different
	Alts: func(fam string) []map[string]string {
		return []map[string]string{{"transport": "raw"}, {"transport": "wss"}, {"transport": "h2"}}
	},
	Build: buildTPK,
}

var methodTPKReverse = &Method{
	ID:         "tpk_rev",
	Title:      "TP Reverse (mTLS)",
	Desc:       "botping's TP Reverse (tp-agent 1.20.9; amd64 build, run under qemu on ARM servers): the foreign server keeps ready mutual-TLS connections to Iran, with a certificate authority made for this tunnel alone.",
	Families:   []string{"v4", "v6"},
	Encrypt:    "mTLS",
	Helper:     "tpk-agent",
	HelperArch: "amd64",
	Fields: []Field{
		{Key: "port", Label: "Tunnel port", Type: "number", Default: "", Help: "blank = auto, unique per tunnel"},
		{Key: "workers", Label: "Ready connections", Type: "number", Default: "128"},
		{Key: "cc", Label: "Congestion control", Type: "select", Default: "bbr", Options: []string{"bbr", "cubic", ""}, Advanced: true},
	},
	Build: buildTPKReverse,
}

func tpkPairs(c *buildCtx) ([]portPair, error) {
	pairs, err := expandPortPairs(c.T.Ports, tpkMaxForwarded)
	if err != nil {
		return nil, fmt.Errorf("ports: %v (TP forwards at most %d)", err, tpkMaxForwarded)
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("TP needs at least one port")
	}
	return pairs, nil
}

func tpkPlan(c *buildCtx, title, cmd string, files map[string]FileSpec) SidePlan {
	return SidePlan{
		Files:     files,
		Artifacts: []Artifact{tpkArt},
		Unit:      Unit{Desc: title + " " + c.T.Name, ExecStart: tpkBin + " " + cmd + " " + tunnelDir(c.T) + "/config.json"},
	}
}

func tpkJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", " ")
	return b
}

func buildTPK(c *buildCtx) (ir, kh SidePlan, err error) {
	d := c.D
	pairs, err := tpkPairs(c)
	if err != nil {
		return ir, kh, err
	}
	tr := c.Opt("transport")
	if tr == "" {
		tr = "tls"
	}
	sec, err := tpkTLSSecrets(c.T)
	if err != nil {
		return ir, kh, err
	}
	dir := tunnelDir(c.T)
	port := portOr(c.Opt("port"), d.BasePort)
	var ports []string
	allow := map[string]bool{}
	for _, p := range pairs {
		if p.host == "127.0.0.1" && p.dst == p.listen {
			ports = append(ports, p.listen)
		} else if p.host == "127.0.0.1" {
			ports = append(ports, p.listen+"="+p.dst)
		} else {
			ports = append(ports, p.listen+"="+bracket(p.host)+":"+p.dst)
		}
		allow[bracket(p.host)+":"+p.dst] = true
	}
	var allowL []string
	for a := range allow {
		allowL = append(allowL, a)
	}
	sort.Strings(allowL)
	num := func(k string) int {
		var n int
		fmt.Sscan(c.Opt(k), &n)
		return n
	}
	path := c.Opt("path")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	sni := strings.TrimSpace(c.Opt("sni"))
	if sni == "" {
		sni = d.IRPub
	}
	common := map[string]any{"cc": c.Opt("cc"), "cipher": c.Opt("cipher"), "jitter_ms": 0, "name": "tp-" + c.T.ID,
		"pad_max": num("pad_max"), "path": path, "procs": num("procs"), "proxy_protocol": "", "psk": sec.PSK,
		"rotate_min": num("rotate_min"), "stats": dir + "/stats.json", "stream_mb": 0, "transport": tr}
	srv := map[string]any{"role": "server", "cert": dir + "/server.crt", "key": dir + "/server.key",
		"listen": bracket(ipAny(c.T.Family)) + ":" + port, "ports": ports, "pub": sec.Pub}
	cli := map[string]any{"role": "client", "allow": allowL, "host": sni, "sni": sni, "pin": sec.Pin, "priv": sec.Priv,
		"proxy": "", "remote": bracket(d.IRPub) + ":" + port, "sessions": num("sessions")}
	for k, v := range common {
		srv[k], cli[k] = v, v
	}
	irCC, khCC := tpkNoCCIfEmulated(c, srv, cli)
	ir = tpkPlan(c, "TP Tunnel", "tunnel", map[string]FileSpec{
		dir + "/server.crt":  {Content: []byte(sec.Cert), Mode: 0o600},
		dir + "/server.key":  {Content: []byte(sec.Key), Mode: 0o600},
		dir + "/config.json": {Content: tpkJSON(srv), Mode: 0o600},
	})
	kh = tpkPlan(c, "TP Tunnel", "tunnel", map[string]FileSpec{
		dir + "/config.json": {Content: tpkJSON(cli), Mode: 0o600},
	})
	ir.Setup, kh.Setup = defaultCCSetup(irCC), defaultCCSetup(khCC)
	return ir, kh, nil
}

// tpkTLS is one tunnel's TP Tunnel keys: the server's self-signed certificate (the client
// pins its key) and the ed25519 pair (Iran holds the public half, foreign the private).
type tpkTLS struct {
	Cert, Key, Pin, Priv, Pub, PSK string
}

func tpkTLSSecrets(t *Tunnel) (tpkTLS, error) {
	var s tpkTLS
	var gerr error
	raw := t.secretGen("tpk-tls", func() string {
		s, gerr = newTPKTLS()
		return string(tpkJSON(s))
	})
	if gerr != nil {
		return s, gerr
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil || s.Pin == "" {
		return s, fmt.Errorf("TP Tunnel keys of this tunnel are unreadable: %v", err)
	}
	return s, nil
}

func newTPKTLS() (tpkTLS, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tpkTLS{}, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tpkTLS{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: tpkSerial(), Subject: pkix.Name{CommonName: "tp.local"}, DNSNames: []string{"tp.local"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return tpkTLS{}, err
	}
	keyPEM, err := tpkKeyPEM(k)
	if err != nil {
		return tpkTLS{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return tpkTLS{}, err
	}
	pin := sha256.Sum256(spki)
	return tpkTLS{
		Cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Key:  keyPEM, Pin: base64.StdEncoding.EncodeToString(pin[:]),
		Priv: hex.EncodeToString(priv), // seed + public key, as tp-agent wants it
		Pub:  hex.EncodeToString(pub), PSK: randHex(32),
	}, nil
}

func tpkSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func tpkKeyPEM(k *ecdsa.PrivateKey) (string, error) {
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})), nil
}

// ---- TP Reverse: a CA made for the tunnel signs Iran's server certificate (for Iran's
// address) and the foreign server's client certificate (CN tp-reverse, clientAuth).

type tpkRevCA struct {
	CA, CAKey, Cli, CliKey string
}

func buildTPKReverse(c *buildCtx) (ir, kh SidePlan, err error) {
	d := c.D
	pairs, err := tpkPairs(c)
	if err != nil {
		return ir, kh, err
	}
	var ca tpkRevCA
	var gerr error
	raw := c.T.secretGen("tpkr-ca", func() string {
		ca, gerr = newTPKRevCA()
		return string(tpkJSON(ca))
	})
	if gerr != nil {
		return ir, kh, gerr
	}
	if err := json.Unmarshal([]byte(raw), &ca); err != nil || ca.CA == "" {
		return ir, kh, fmt.Errorf("TP Reverse certificates of this tunnel are unreadable: %v", err)
	}
	// the server certificate names Iran's address, so it is kept per address
	var leaf [2]string
	raw = c.T.secretGen("tpkr-srv-"+d.IRPub, func() string {
		var cert, key string
		cert, key, gerr = tpkRevLeaf(ca, true, d.IRPub)
		return string(tpkJSON([2]string{cert, key}))
	})
	if gerr != nil {
		return ir, kh, gerr
	}
	if err := json.Unmarshal([]byte(raw), &leaf); err != nil || leaf[0] == "" {
		return ir, kh, fmt.Errorf("TP Reverse server certificate is unreadable: %v", err)
	}
	dir := tunnelDir(c.T)
	port := portOr(c.Opt("port"), d.BasePort)
	var fwd, tgt []string
	for _, p := range pairs {
		fwd = append(fwd, ":"+p.listen)
		tgt = append(tgt, bracket(p.host)+":"+p.dst)
	}
	base := func() map[string]any {
		m := map[string]any{"cert": dir + "/identity.pem", "key": dir + "/identity-key.pem", "ca": dir + "/ca.pem", "server_name": d.IRPub}
		if cc := c.Opt("cc"); cc != "" {
			m["cc"] = cc
		}
		return m
	}
	srv, cli := base(), base()
	srv["mode"], srv["listen"], srv["max_links"] = "server", bracket(ipAny(c.T.Family))+":"+port, 4096
	var workers int
	fmt.Sscan(c.Opt("workers"), &workers)
	if workers <= 0 {
		workers = 128
	}
	cli["mode"], cli["remote"], cli["workers"] = "client", bracket(d.IRPub)+":"+port, workers
	irCC, khCC := tpkNoCCIfEmulated(c, srv, cli)
	if len(fwd) == 1 {
		srv["forward"], cli["target"] = fwd[0], tgt[0]
	} else {
		srv["forwards"], cli["targets"] = fwd, tgt
	}
	ir = tpkPlan(c, "TP Reverse", "reverse", map[string]FileSpec{
		dir + "/ca.pem":           {Content: []byte(ca.CA), Mode: 0o600},
		dir + "/identity.pem":     {Content: []byte(leaf[0]), Mode: 0o600},
		dir + "/identity-key.pem": {Content: []byte(leaf[1]), Mode: 0o600},
		dir + "/config.json":      {Content: tpkJSON(srv), Mode: 0o600},
	})
	kh = tpkPlan(c, "TP Reverse", "reverse", map[string]FileSpec{
		dir + "/ca.pem":           {Content: []byte(ca.CA), Mode: 0o600},
		dir + "/identity.pem":     {Content: []byte(ca.Cli), Mode: 0o600},
		dir + "/identity-key.pem": {Content: []byte(ca.CliKey), Mode: 0o600},
		dir + "/config.json":      {Content: tpkJSON(cli), Mode: 0o600},
	})
	ir.Setup, kh.Setup = defaultCCSetup(irCC), defaultCCSetup(khCC)
	return ir, kh, nil
}

func newTPKRevCA() (tpkRevCA, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tpkRevCA{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: tpkSerial(), Subject: pkix.Name{CommonName: "TP Reverse dedicated CA"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return tpkRevCA{}, err
	}
	keyPEM, err := tpkKeyPEM(k)
	if err != nil {
		return tpkRevCA{}, err
	}
	ca := tpkRevCA{CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CAKey: keyPEM}
	ca.Cli, ca.CliKey, err = tpkRevLeaf(ca, false, "tp-reverse")
	return ca, err
}

// tpkRevLeaf signs a server (name = Iran's IP or domain) or client certificate with the CA.
func tpkRevLeaf(ca tpkRevCA, server bool, name string) (cert, key string, err error) {
	cb, _ := pem.Decode([]byte(ca.CA))
	kb, _ := pem.Decode([]byte(ca.CAKey))
	if cb == nil || kb == nil {
		return "", "", fmt.Errorf("TP Reverse CA is unreadable")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return "", "", err
	}
	caKey, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return "", "", err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: tpkSerial(), Subject: pkix.Name{CommonName: "tp-reverse"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{name}
		}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	key, err = tpkKeyPEM(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key, err
}

// tpkNoCCIfEmulated leaves "cc" out on a side whose server runs the amd64 core under
// qemu-x86_64 (an ARM server): qemu-user rejects the TCP_CONGESTION socket option with
// EINVAL, and TP Reverse then never connects ("reverse reconnect: invalid argument", seen
// live on usa-kharej). It returns the congestion control each side dropped ("" = none), which
// defaultCCSetup then makes that server's default, so the agent's sockets get it anyway.
func tpkNoCCIfEmulated(c *buildCtx, srv, cli map[string]any) (srvCC, cliCC string) {
	if emulatedAmd64(c.Srv) {
		srvCC, _ = srv["cc"].(string)
		delete(srv, "cc")
	}
	if emulatedAmd64(c.FSrv) {
		cliCC, _ = cli["cc"].(string)
		delete(cli, "cc")
	}
	return srvCC, cliCC
}

// defaultCCSetup makes cc the server's default TCP congestion control (when its kernel has
// it), for an agent that can't set it per socket. Without it the emulated foreign side of
// usa-kharej sent with cubic and TP's download over the 190 ms path fell to 0.2 Mbps; with
// bbr as the default it was 2-6 Mbps. Only this one setting: the server's buffer sizes and
// qdisc stay as they are.
func defaultCCSetup(cc string) string {
	if cc == "" || strings.Trim(cc, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return "" // (a select option, but it lands in a shell script)
	}
	return fmt.Sprintf(`modprobe tcp_%[1]s 2>/dev/null || true
if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw %[1]s; then
  echo net.ipv4.tcp_congestion_control=%[1]s >/etc/sysctl.d/99-tunnel-panel-cc.conf
  sysctl -q -w net.ipv4.tcp_congestion_control=%[1]s || true
fi
`, cc)
}

// emulatedAmd64 reports whether an amd64-only core runs emulated on s (nil = this panel
// host). An arch not detected yet counts as native.
func emulatedAmd64(s *Server) bool {
	arch := runtime.GOARCH
	if s != nil {
		arch = goArch(s.Arch)
	}
	return arch != "" && arch != "amd64"
}
