package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// serve runs the panel over HTTP, self-signed HTTPS, or Let's Encrypt HTTPS.
//
//	tlsMode == ""      → plain HTTP on addr
//	tlsMode == "self"  → self-signed HTTPS on addr (browser warning, but encrypted)
//	tlsMode == domains → Let's Encrypt certs for those domains (comma-separated, e.g. the
//	                     panel's own domain plus its <ip>.sslip.io), HTTPS on :443 + :80
//	                     redirect; autocert renews each cert well before it expires
func serve(addr, tlsMode, dir string, handler http.Handler) error {
	switch tlsMode {
	case "":
		fmt.Printf("Panel: http://%s\n", addr)
		return (&http.Server{Addr: addr, Handler: handler}).ListenAndServe()
	case "self":
		cert, err := selfSignedServerCert(dir)
		if err != nil {
			return err
		}
		fmt.Printf("Panel: https://%s  (self-signed — your browser will warn once)\n", addr)
		srv := &http.Server{Addr: addr, Handler: handler, ErrorLog: quietTLSLog, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		return srv.ListenAndServeTLS("", "")
	default:
		domains := splitDomains(tlsMode)
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(filepath.Join(dir, "acme")),
		}
		// :80 serves the ACME http-01 challenge and redirects everything else to https.
		go func() {
			log.Printf("ACME/redirect listener on :80: %v",
				http.ListenAndServe(":80", m.HTTPHandler(redirectHTTPS(domains))))
		}()
		for _, d := range domains {
			fmt.Printf("Panel: https://%s/  (Let's Encrypt; needs ports 80 and 443 open and DNS pointing here)\n", d)
		}
		srv := &http.Server{Addr: ":443", Handler: handler, ErrorLog: quietTLSLog, TLSConfig: m.TLSConfig()}
		return srv.ListenAndServeTLS("", "")
	}
}

// quietTLSLog drops "TLS handshake error" lines: internet scanners hit the panel's port all
// day (no SNI, old TLS versions, plain HTTP) and they buried the panel's own log lines.
var quietTLSLog = log.New(quietTLSWriter{}, "", log.LstdFlags)

type quietTLSWriter struct{}

func (quietTLSWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

// redirectHTTPS sends plain HTTP to the same panel domain over HTTPS (the first one for a
// request that names none of them).
func redirectHTTPS(domains []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := domains[0]
		h := strings.ToLower(r.Host)
		if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		for _, d := range domains {
			if d == h {
				host = d
			}
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

// splitDomains turns "a.example.com, b.sslip.io" into its domains.
func splitDomains(v string) []string {
	var out []string
	for _, d := range strings.Split(v, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// selfSignedServerCert loads or creates a self-signed serverAuth cert valid for any host/IP.
func selfSignedServerCert(dir string) (tls.Certificate, error) {
	cp, kp := filepath.Join(dir, "panel-cert.pem"), filepath.Join(dir, "panel-key.pem")
	if cb, err := os.ReadFile(cp); err == nil {
		if kb, err := os.ReadFile(kp); err == nil {
			if cert, err := tls.X509KeyPair(cb, kb); err == nil {
				return cert, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "tunnel-panel"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"tunnel-panel", "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = os.WriteFile(cp, certPEM, 0o600)
	_ = os.WriteFile(kp, keyPEM, 0o600)
	return tls.X509KeyPair(certPEM, keyPEM)
}
