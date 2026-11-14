package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// HSTS only with a trusted certificate (Let's Encrypt mode) over TLS: with a self-signed
// panel it would lock the browser out after a certificate change.
func TestHSTS(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	get := func(secure, overTLS bool) string {
		old := cookieSecure
		cookieSecure = secure
		defer func() { cookieSecure = old }()
		r := httptest.NewRequest("GET", "/", nil)
		if overTLS {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		securityHeaders(ok).ServeHTTP(w, r)
		return w.Header().Get("Strict-Transport-Security")
	}
	if get(true, true) == "" {
		t.Error("no HSTS in Let's Encrypt mode")
	}
	if get(false, true) != "" || get(true, false) != "" {
		t.Error("HSTS sent on a self-signed or plain-HTTP panel")
	}
}
