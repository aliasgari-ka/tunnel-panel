package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"tunnelpanel/internal/agent"
	"tunnelpanel/internal/agentproto"
)

// AgentHub accepts outbound connections from Iran agents and maps them to servers by token.
type AgentHub struct {
	mu     sync.Mutex
	conns  map[string]*agentConn // serverID -> live connection
	tokens map[string]string     // token -> serverID
	pin    string                // our TLS public-key pin, handed to agents
	// onChange is called when an agent connects (true) or disconnects (false).
	onChange func(serverID string, online bool)
}

type agentConn struct {
	sess     *yamux.Session
	hostname string
	arch     string
	os       string
	since    time.Time
}

func newAgentHub() *AgentHub {
	return &AgentHub{conns: map[string]*agentConn{}, tokens: map[string]string{}}
}

func (hub *AgentHub) setTokens(servers []*Server) {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	hub.tokens = map[string]string{}
	for _, s := range servers {
		if s.AgentToken != "" {
			hub.tokens[s.AgentToken] = s.ID
		}
	}
}

func (hub *AgentHub) online(serverID string) *agentConn {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	return hub.conns[serverID]
}

// Listen serves the agent port over HTTPS with its own self-signed cert. It serves:
//
//	GET /agent/install?t=TOKEN   bootstrap script for the Iran server
//	GET /agent/bin/<arch>?t=...  the tp-agent binary
//	GET /agent/connect           agent upgrade → yamux session
func (hub *AgentHub) Listen(addr, dir string, settings func() Settings) error {
	cert, pin, err := loadOrMakeCert(dir)
	if err != nil {
		return err
	}
	hub.pin = pin
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/install", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		if !hub.validToken(tok) {
			http.Error(w, "unknown token", 403)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript")
		fmt.Fprint(w, agentInstallScript(hub.connectAddr(settings(), r), tok, pin))
	})
	mux.HandleFunc("/agent/bin/", func(w http.ResponseWriter, r *http.Request) {
		if !hub.validToken(r.URL.Query().Get("t")) {
			http.Error(w, "unknown token", 403)
			return
		}
		arch := strings.TrimPrefix(r.URL.Path, "/agent/bin/")
		b, err := assetBytes("tp-agent-" + arch)
		if err != nil {
			http.Error(w, "no agent build for "+arch, 404)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	})
	mux.HandleFunc(agentproto.ConnectPath, hub.connect)
	srv := &http.Server{Addr: addr, Handler: mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 20 * time.Second}
	fmt.Printf("Agent hub listening on %s (pin %s)\n", addr, pin)
	return srv.ListenAndServeTLS("", "")
}

// connectAddr is what agents dial: the configured value, else the Host the request came in on.
func (hub *AgentHub) connectAddr(set Settings, r *http.Request) string {
	if set.AgentConnect != "" {
		return set.AgentConnect
	}
	return r.Host
}

func (hub *AgentHub) validToken(tok string) bool {
	if tok == "" {
		return false
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	return hub.tokens[tok] != ""
}

func (hub *AgentHub) connect(w http.ResponseWriter, r *http.Request) {
	hub.mu.Lock()
	serverID := hub.tokens[r.Header.Get(agentproto.TokenHeader)]
	hub.mu.Unlock()
	if serverID == "" {
		http.Error(w, "unknown agent token", 403)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tp-agent\r\nConnection: Upgrade\r\n\r\n")
	_ = c.SetDeadline(time.Time{})
	conn := agent.PreBuffered(c, brw.Reader)
	sess, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		c.Close()
		return
	}
	ac := &agentConn{sess: sess, since: time.Now()}
	if st, err := sess.AcceptStream(); err == nil {
		_ = st.SetDeadline(time.Now().Add(10 * time.Second))
		sbr := bufio.NewReader(st)
		if _, err := agentproto.ReadRequest(sbr); err == nil {
			if _, p, err := agentproto.ReadFrame(sbr); err == nil {
				parts := strings.SplitN(string(p), "|", 3)
				ac.hostname, ac.arch, ac.os = get(parts, 0), get(parts, 1), get(parts, 2)
			}
		}
		st.Close()
	}
	hub.mu.Lock()
	if old := hub.conns[serverID]; old != nil {
		old.sess.Close()
	}
	hub.conns[serverID] = ac
	hub.mu.Unlock()
	fmt.Printf("agent online: server=%s host=%s arch=%s\n", serverID, ac.hostname, ac.arch)
	if hub.onChange != nil {
		hub.onChange(serverID, true)
	}
	<-sess.CloseChan()
	hub.mu.Lock()
	if hub.conns[serverID] == ac {
		delete(hub.conns, serverID)
	}
	hub.mu.Unlock()
	if hub.onChange != nil {
		hub.onChange(serverID, false)
	}
}

// agentInstallScript is what `curl … /agent/install | bash` runs on the Iran server.
func agentInstallScript(connect, token, pin string) string {
	return fmt.Sprintf(`#!/bin/bash
set -e
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
A=amd64; case "$(uname -m)" in aarch64|arm64) A=arm64;; esac
PIN='sha256//%[3]s'
echo "downloading tp-agent ($A) from the panel"
curl -fsSk --pinnedpubkey "$PIN" -o /usr/local/bin/tp-agent.new "https://%[1]s/agent/bin/$A?t=%[2]s"
chmod 0755 /usr/local/bin/tp-agent.new && mv -f /usr/local/bin/tp-agent.new /usr/local/bin/tp-agent
cat >/etc/systemd/system/tp-agent.service <<'UNIT'
[Unit]
Description=Tunnel Panel agent (dials back to the panel)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tp-agent --connect %[1]s --token %[2]s --pin %[3]s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now tp-agent
sleep 2
systemctl --no-pager --lines=5 status tp-agent || true
echo "tp-agent installed — it should show as online in the panel within a few seconds."
`, connect, token, pin)
}

// openStream opens a new request stream to the agent for a server.
func (hub *AgentHub) openStream(serverID string) (net.Conn, error) {
	ac := hub.online(serverID)
	if ac == nil {
		return nil, fmt.Errorf("no agent connected for this server")
	}
	return ac.sess.OpenStream()
}

// ---- cert ----

func loadOrMakeCert(dir string) (tls.Certificate, string, error) {
	cp, kp := filepath.Join(dir, "agent-cert.pem"), filepath.Join(dir, "agent-key.pem")
	if cb, err := os.ReadFile(cp); err == nil {
		if kb, err := os.ReadFile(kp); err == nil {
			cert, err := tls.X509KeyPair(cb, kb)
			if err == nil {
				return cert, agent.KeyPin(cert.Certificate[0]), nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "tunnel-panel-agent"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = os.WriteFile(cp, certPEM, 0o600)
	_ = os.WriteFile(kp, keyPEM, 0o600)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, agent.KeyPin(cert.Certificate[0]), nil
}

// ---- AgentHost: a Host that runs via the dialed-back agent ----

type AgentHost struct {
	hub      *AgentHub
	serverID string
}

func (h AgentHost) Label() string { return "IR" }

func (h AgentHost) Run(ctx context.Context, script string, log func(string)) (string, error) {
	st, err := h.hub.openStream(h.serverID)
	if err != nil {
		return "", err
	}
	defer st.Close()
	if err := agentproto.WriteRequest(st, agentproto.Request{Op: "exec", Script: script}); err != nil {
		return "", err
	}
	var out lineSink
	out.log = log
	done := make(chan error, 1)
	go func() {
		_, err := agentproto.ReadResult(st, out.write)
		done <- err
	}()
	select {
	case err := <-done:
		return out.buf.String(), err
	case <-ctx.Done():
		st.Close()
		return out.buf.String(), ctx.Err()
	}
}

func (h AgentHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	st, err := h.hub.openStream(h.serverID)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := agentproto.WriteRequest(st, agentproto.Request{Op: "write", Path: path, Mode: uint32(mode), Size: int64(len(data))}); err != nil {
		return err
	}
	if _, err := st.Write(data); err != nil {
		return err
	}
	_, err = agentproto.ReadResult(st, nil)
	return err
}

// Dial opens a TCP connection from the agent's vantage point (used for SSH-via-agent and jump).
func (h AgentHost) Dial(addr string) (net.Conn, error) {
	st, err := h.hub.openStream(h.serverID)
	if err != nil {
		return nil, err
	}
	if err := agentproto.WriteRequest(st, agentproto.Request{Op: "dial", Addr: addr}); err != nil {
		st.Close()
		return nil, err
	}
	// wait for the 'x0' ack
	typ, p, err := agentproto.ReadFrame(st)
	if err != nil {
		st.Close()
		return nil, err
	}
	if typ == 'e' {
		st.Close()
		return nil, fmt.Errorf("agent dial %s: %s", addr, string(p))
	}
	return st, nil
}

type lineSink struct {
	buf     strings.Builder
	log     func(string)
	partial []byte
}

func (s *lineSink) write(p []byte) {
	s.buf.Write(p)
	if s.log == nil {
		return
	}
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			break
		}
		s.log(string(s.partial[:i]))
		s.partial = s.partial[i+1:]
	}
}

func trimHeader(s string) string { return strings.TrimSpace(strings.TrimPrefix(s, ":")) }

func splitN(s, sep string, n int) []string { return strings.SplitN(s, sep, n) }

func get(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}
