package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGemCookieCut(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		line string
		name string
		cut  bool
	}{
		{"SID=EXPIRED; Domain=.google.com; Path=/; Expires=Mon, 01-Jan-1990 00:00:00 GMT", "SID", true},
		{"__Secure-1PSID=; Domain=.google.com; Max-Age=0; Secure", "__Secure-1PSID", true},
		{"__Secure-3PSID=abc; Domain=.google.com; Expires=Thu, 01 Jan 1970 00:00:00 GMT", "__Secure-3PSID", true},
		{"SID=abc; Domain=.google.com; Expires=Sat, 18-Dec-2027 10:00:00 GMT", "SID", false},
		{"__Secure-1PSIDTS=sidts-x; Domain=.google.com; Max-Age=0", "", false}, // not a session cookie
		{"NID=1; Max-Age=0", "", false},
	} {
		n, cut := gemCookieCut(c.line, now)
		if cut != c.cut || (cut && n != c.name) {
			t.Errorf("%q: %q %v, want %q %v", c.line, n, cut, c.name, c.cut)
		}
	}
	h := map[string]any{"Set-Cookie": "SIDCC=x; Max-Age=0\nSID=EXPIRED; Expires=Mon, 01-Jan-1990 00:00:00 GMT\n__Secure-1PSID=EXPIRED; Max-Age=0"}
	if got := gemCutsIn(h, now); strings.Join(got, ",") != "SID,__Secure-1PSID" {
		t.Fatalf("cuts %v", got)
	}
	if u := gemBareURL("https://accounts.google.com/RotateCookies?token=secret"); u != "https://accounts.google.com/RotateCookies" {
		t.Fatalf("query kept: %s", u)
	}
}

func TestGemCutWhy(t *testing.T) {
	at := time.Date(2026, 11, 12, 18, 3, 4, 0, time.UTC)
	w := gemCutWhy(gemCut{At: at, URL: "https://accounts.google.com/RotateCookies", Status: 401, Names: []string{"SID"}}, true, true)
	if !strings.Contains(w, "revoked the session on its side") || !strings.Contains(w, "HTTP 401") || !strings.Contains(w, "11-12 18:03:04 UTC") {
		t.Fatalf("rotate: %s", w)
	}
	if w := gemCutWhy(gemCut{At: at, URL: "https://accounts.google.com/Logout"}, true, true); !strings.Contains(w, "by hand") {
		t.Fatalf("logout: %s", w)
	}
	w = gemCutWhy(gemCut{}, false, true)
	if !strings.Contains(w, "outside the pages") {
		t.Fatalf("none seen: %s", w)
	}
	if gemCutWhy(gemCut{}, false, false) != "" {
		t.Fatal("not watched: should say nothing")
	}
	c := gemAcctCause("", 12, "de", w)
	if strings.Contains(c, "itself") || !strings.Contains(c, "outside the pages") {
		t.Fatalf("cause: %s", c)
	}
}

func TestGemHomeGall(t *testing.T) {
	home := &Server{IPv4: gemHomeHost()}
	other := &Server{IPv4: "159.195.78.190"}
	if !gemHomeOptBad(home, "gall", "off") || gemHomeOptBad(home, "gall", "on") || gemHomeOptBad(other, "gall", "off") || gemHomeOptBad(home, "gspread", "off") {
		t.Fatal("gall refusal wrong")
	}
	if r := gemHomeRisk(map[string]string{"google": "warp6", "gall": "OFF"}); !strings.Contains(r, "All of Google") {
		t.Fatalf("gall off not flagged: %q", r)
	}
	if r := gemHomeRisk(map[string]string{"google": "warp6", "gall": "ON"}); r != "" {
		t.Fatalf("flagged: %q", r)
	}
	if r := gemHomeRisk(map[string]string{"google": "warp6"}); r != "" { // an old agent without gall
		t.Fatalf("missing gall flagged: %q", r)
	}
}

// A fake browser: the watcher asks for auto-attach, a page is attached, a RotateCookies answer
// deletes SID; a probe context's page doing the same is left out.
func TestGemWatchSeesCut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	gemProbeCtxs.Store("PROBE", true)
	defer gemProbeCtxs.Delete("PROBE")
	gemWatch.Lock()
	gemWatch.last = gemCut{}
	gemWatch.Unlock()
	start := time.Now()
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					c.Close()
					return
				}
				if req.URL.Path == "/json/version" {
					b := fmt.Sprintf(`{"webSocketDebuggerUrl":"ws://%s/devtools/browser/x"}`, addr)
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(b), b)
					c.Close()
					return
				}
				fmt.Fprint(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				w := &cdpConn{c: c, r: br}
				ev := func(session, method string, params any) {
					m := map[string]any{"method": method, "params": params}
					if session != "" {
						m["sessionId"] = session
					}
					b, _ := json.Marshal(m)
					// server frames are not masked: write the frame by hand
					h := []byte{0x81}
					if len(b) < 126 {
						h = append(h, byte(len(b)))
					} else {
						h = append(h, 126, byte(len(b)>>8), byte(len(b)))
					}
					c.Write(append(h, b...))
				}
				_ = w
				time.Sleep(100 * time.Millisecond)
				for _, s := range []struct{ sess, ctx string }{{"S1", "DEFAULT"}, {"S2", "PROBE"}} {
					ev("", "Target.attachedToTarget", map[string]any{"sessionId": s.sess, "targetInfo": map[string]any{"type": "page", "browserContextId": s.ctx}})
					ev(s.sess, "Network.requestWillBeSent", map[string]any{"requestId": "r1", "request": map[string]any{"url": "https://accounts.google.com/RotateCookies?x=secret"}})
				}
				ev("S2", "Network.responseReceivedExtraInfo", map[string]any{"requestId": "r1", "statusCode": 200, "headers": map[string]any{"set-cookie": "SID=EXPIRED; Expires=Mon, 01-Jan-1990 00:00:00 GMT"}})
				ev("S1", "Network.responseReceivedExtraInfo", map[string]any{"requestId": "r1", "statusCode": 401, "headers": map[string]any{"set-cookie": "SID=EXPIRED; Expires=Mon, 01-Jan-1990 00:00:00 GMT\n__Secure-1PSID=EXPIRED; Max-Age=0"}})
				time.Sleep(200 * time.Millisecond)
				c.Close()
				close(done)
			}(c)
		}
	}()
	gemWatchOnce(addr)
	<-done
	c, ok, _ := gemCutSince(start)
	if !ok || c.URL != "https://accounts.google.com/RotateCookies" || c.Status != 401 || strings.Join(c.Names, ",") != "SID,__Secure-1PSID" {
		t.Fatalf("cut %+v ok=%v", c, ok)
	}
	if _, ok, _ := gemCutSince(time.Now().Add(time.Second)); ok {
		t.Fatal("an older cut counted")
	}
}
