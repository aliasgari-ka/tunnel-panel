package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// The Google test browser: Chromium on a German server's virtual screen, with a fixed profile,
// where the admin logs in to the test Google account once. Its noVNC listens on that server's
// 127.0.0.1:6077 only; the panel host reaches it over an SSH tunnel (gb-tunnel.service, the
// same port on the panel host's loopback) and shows it to the admin at /gbrowser/.
const gbrowserAddr = "127.0.0.1:6077"

func (s *Server2) gbrowser() http.HandlerFunc {
	up := &url.URL{Scheme: "http", Host: gbrowserAddr}
	rp := httputil.NewSingleHostReverseProxy(up)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		httpErr(w, 502, "the Google test browser does not answer (gb-tunnel / gb-novnc down?): "+err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gbrowser" || r.URL.Path == "/gbrowser/" {
			http.Redirect(w, r, "/gbrowser/vnc.html?path=gbrowser/websockify&autoconnect=1&resize=remote&reconnect=1", http.StatusFound)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/gbrowser")
		r.URL.RawPath = ""
		r.Header.Del("Cookie") // the panel's session is not noVNC's business
		// noVNC's page has an inline module script: only these proxied pages may run one
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		rp.ServeHTTP(w, r)
	}
}
