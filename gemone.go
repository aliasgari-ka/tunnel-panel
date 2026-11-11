package main

// The Google One check. Gemini can open on a server while Google One's plan page (the
// "Upgrade to Gemini Advanced" link) answers "403. That's an error. Your client does not have
// permission…": one.google.com and the payment pages went out through the server's own IP,
// which Google refuses for purchases, instead of Gemini's route (fixed in the agent's Google
// list, 2026-11-12). This loop asks for the plan page through every server's users' relay and
// tells the admin (and the server's owner) when Google refuses it again.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	gemOneURL   = "https://one.google.com/explore-plan/gemini-advanced?utm_source=gemini&utm_medium=web"
	gemOneTick  = 20 * time.Minute
	gemOneAlert = 6 * time.Hour // the same server is reported at most this often
	gemOneBad   = 2             // refusals in a row before it is reported (one can be a blip)
)

// gemSocksGet fetches url through a socks5 exit ("ip:port"), following redirects only when
// follow is set: the status code and up to 4 MB of the body.
func gemSocksGet(ctx context.Context, socks, url string, follow bool) (int, []byte, error) {
	d, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return 0, nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return 0, nil, fmt.Errorf("socks dialer without context")
	}
	tr := &http.Transport{DialContext: cd.DialContext, TLSHandshakeTimeout: 15 * time.Second}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	cl := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	if !follow {
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

// gemOneVerdict: "refused" for Google's 403 page, "ok" for the page or its sign-in redirect
// (signed out, Google sends the plan page to accounts.google.com — it only does that where it
// serves the page), "" when it says nothing (an error, a 5xx).
func gemOneVerdict(code int, body []byte) string {
	s := string(body)
	switch {
	case code == 403, strings.Contains(s, "does not have permission to get URL"):
		return "refused"
	case code >= 200 && code < 400:
		return "ok"
	}
	return ""
}

type gemOneState struct {
	bad  int
	sent time.Time
}

// gemOneCheck: the plan page through srv's users' relay.
func gemOneCheck(ctx context.Context, srv *Server) (string, int) {
	c, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	code, b, err := gemSocksGet(c, srv.IPv4+":"+strconv.Itoa(gemRelayPort), gemOneURL, false)
	if err != nil {
		return "", 0
	}
	return gemOneVerdict(code, b), code
}

// gemOneStep folds one verdict into a server's state; true = report it now.
func gemOneStep(st *gemOneState, v string, now time.Time) bool {
	switch v {
	case "ok":
		st.bad = 0
	case "refused":
		st.bad++
		if st.bad >= gemOneBad && now.Sub(st.sent) >= gemOneAlert {
			st.sent = now
			return true
		}
	}
	return false
}

func (a *App) gemOneLoop() {
	states := map[string]*gemOneState{}
	time.Sleep(4 * time.Minute)
	for ; ; time.Sleep(gemOneTick) {
		var list []*Server
		a.store.View(func(s *State) {
			for _, x := range s.Servers {
				if x.Igproxy && x.IPv4 != "" {
					list = append(list, x)
				}
			}
		})
		type res struct {
			v    string
			code int
		}
		out := make([]res, len(list))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		for i, s := range list {
			wg.Add(1)
			go func(i int, s *Server) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				v, code := gemOneCheck(context.Background(), s)
				out[i] = res{v, code}
			}(i, s)
		}
		wg.Wait()
		now := time.Now()
		for i, s := range list {
			st := states[s.ID]
			if st == nil {
				st = &gemOneState{}
				states[s.ID] = st
			}
			if gemOneStep(st, out[i].v, now) {
				a.pushTo(s.Owner, fmt.Sprintf("💳 Google One refuses the users of %s (http %d on one.google.com — \"Your client does not have permission\"): the Gemini Advanced plan page and payments don't open there. Google One should take Gemini's route (agent 0eb7285e or newer) — update the agent, or move Google to an exit Google serves.", igLabel(s), out[i].code))
			}
		}
	}
}
