package main

// DNS in the exit's country. A user who tests the VPN (dnsleaktest.com, ipleak, the client's
// own "check" button) is shown two things: the exit IP's country and the country of the
// resolver that looked the test name up. Names are resolved by the server (the client sends
// the name, the server's Xray resolves it with the system resolver), so the second one is the
// server's own DNS setting. A provider image often carries the provider's resolvers at its
// home site: the USA server (netcup, Manassas) resolved in Germany, so a customer who bought
// USA saw "DNS: Germany - netcup" under a US IP, read it as a leak and left the location
// twice (2026-11-18). It also sends US users to European CDN nodes.
//
// The check asks ip-api through the users' relay for the exit's country and for the resolver
// that reaches its DNS-leak name (three names: resolvers rotate). "Run checks" shows it as the
// DNS line, a loop tells the owner, and the fix puts the anycast resolvers 1.1.1.1 / 8.8.8.8
// on the server (they answer from the nearest site), keeping the old setting to put back.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dnsExitTick  = 12 * time.Hour
	dnsExitAlert = 7 * 24 * time.Hour // the same server is reported at most this often
	dnsExitBad   = 2                  // rounds in a row before it is reported

	// dnsExitProbe prints "D <exit country> <mine> <json> <json> <json>" (tab separated):
	// mine = 1 while the panel's resolver entry is on the server.
	dnsExitProbe = `dnx(){ local e r i o="" m=0
  e=$(curl -s -m 6 -x socks5h://127.0.0.1:12370 'http://ip-api.com/line/?fields=country' 2>/dev/null | head -1 | tr -d '\t\r')
  for i in 1 2 3; do r=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n') # 32 characters, or ip-api answers "Not Found"
    o="$o	$(curl -s -m 6 -x socks5h://127.0.0.1:12370 "http://$r.edns.ip-api.com/json" 2>/dev/null | tr -d '\t\r\n' | head -c 400)"; done
  { [ -f /etc/systemd/resolved.conf.d/90-tp-exit-dns.conf ] || [ -f /etc/resolv.conf.tp-bak ]; } && m=1
  printf 'D\t%s\t%s%s\n' "$e" "$m" "$o"
}
`
	dnsExitScript = "#dnsexit\n" + dnsExitProbe + "ss -ltn 2>/dev/null | grep -q ':12370 ' || { echo __RC=3; exit 0; }\ndnx\necho __RC=0\n"

	// dnsExitFixScript: UNDO=1 puts the old setting back. rc 4 = names stopped resolving and the
	// old setting is back, 5 = resolv.conf can't be written.
	dnsExitFixScript = `#dnsfix
F=/etc/systemd/resolved.conf.d/90-tp-exit-dns.conf; B=/etc/resolv.conf.tp-bak
chk(){ local n=0 h; for h in www.google.com i.instagram.com www.cloudflare.com; do timeout 6 getent ahostsv4 $h >/dev/null 2>&1 && n=$((n+1)); done; [ $n -ge 2 ]; }
if [ "$UNDO" = 1 ]; then
  if [ -f $F ]; then rm -f $F; systemctl restart systemd-resolved
  elif [ -f $B ]; then cat $B > /etc/resolv.conf && rm -f $B; fi
  echo __RC=0; exit 0
fi
if systemctl is-active -q systemd-resolved 2>/dev/null && grep -q '^nameserver 127\.0\.0\.53' /etc/resolv.conf; then
  mkdir -p ${F%/*}
  printf '%s\n' '# tunnel-panel: resolvers that answer from the nearest site, so DNS is seen in the exit'"'"'s country' \
    '# undo: rm this file; systemctl restart systemd-resolved' '[Resolve]' 'DNS=' 'DNS=1.1.1.1 8.8.8.8 1.0.0.1 2606:4700:4700::1111' 'Domains=~.' > $F # ~. : before the link's (DHCP) resolvers too
  systemctl restart systemd-resolved; sleep 1
  chk || { rm -f $F; systemctl restart systemd-resolved; echo __RC=4; exit 0; }
else
  [ -f $B ] || cp -L /etc/resolv.conf $B 2>/dev/null || { echo __RC=5; exit 0; }
  { grep -E '^(options|search|domain) ' $B; printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.0.0.1\n'; } > /etc/resolv.conf.tp-new
  cat /etc/resolv.conf.tp-new > /etc/resolv.conf 2>/dev/null || { rm -f /etc/resolv.conf.tp-new $B; echo __RC=5; exit 0; }
  rm -f /etc/resolv.conf.tp-new
  chk || { cat $B > /etc/resolv.conf; rm -f $B; echo __RC=4; exit 0; }
fi
echo __RC=0
`
)

// DNSExit is one reading: where the exit IP is and where the resolvers users' names go to are.
type DNSExit struct {
	Exit string   `json:"exit"`           // the exit IP's country ("United States")
	DNS  []string `json:"dns"`            // "Germany - netcup GmbH", one per resolver seen
	Mine bool     `json:"mine,omitempty"` // the panel's resolver entry is on the server
}

// dnsExitCountry: "Germany - netcup GmbH" -> "Germany".
func dnsExitCountry(geo string) string {
	c, _, _ := strings.Cut(geo, " - ")
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(c)), "the ") // "The Netherlands" / "Netherlands"
}

// dnsExitParse reads the probe's D line; false when it carries no reading (ip-api did not
// answer: rate limit, no relay).
func dnsExitParse(lines []string) (DNSExit, bool) {
	for _, l := range lines {
		f := strings.Split(strings.TrimRight(l, "\r"), "\t")
		if f[0] != "D" || len(f) < 3 {
			continue
		}
		d := DNSExit{Exit: strings.TrimSpace(f[1]), Mine: f[2] == "1", DNS: []string{}}
		seen := map[string]bool{}
		for _, j := range f[3:] {
			var v struct {
				DNS struct {
					Geo string `json:"geo"`
				} `json:"dns"`
			}
			if json.Unmarshal([]byte(j), &v) != nil {
				continue
			}
			if g := strings.TrimSpace(v.DNS.Geo); g != "" && !seen[g] {
				seen[g] = true
				d.DNS = append(d.DNS, g)
			}
		}
		return d, d.Exit != "" && len(d.DNS) > 0
	}
	return DNSExit{}, false
}

// Verdict: "ok" when a resolver in the exit's country was seen and none elsewhere, "mixed"
// when some are elsewhere, "bad" when none is in the exit's country.
func (d DNSExit) Verdict() string {
	in, out := 0, 0
	for _, g := range d.DNS {
		if dnsExitCountry(g) == dnsExitCountry(d.Exit) {
			in++
		} else {
			out++
		}
	}
	switch {
	case in > 0 && out == 0:
		return "ok"
	case in > 0:
		return "mixed"
	case out > 0:
		return "bad"
	}
	return ""
}

func (d DNSExit) why() string {
	return fmt.Sprintf("a DNS-leak test shows the resolver in %s while the exit IP is in %s: users who test the VPN read that as a leak or a wrong country", strings.Join(d.DNS, ", "), d.Exit)
}

// dnsExitCheck is the DNS line of "Run checks".
func dnsExitCheck(d DNSExit) IgHCheck {
	c := IgHCheck{K: "DNS", OK: true, Loc: strings.Join(d.DNS, ", "), IP: d.Exit, Mine: d.Mine}
	switch d.Verdict() {
	case "bad":
		c.Warn, c.Why = true, d.why()
	case "mixed":
		c.Why = "some resolvers are outside " + d.Exit
	}
	return c
}

func (a *App) dnsExitRead(ctx context.Context, srv *Server) (DNSExit, error) {
	rc, lines, err := a.igShell(ctx, srv, dnsExitScript, 45*time.Second)
	if rc == 3 {
		return DNSExit{}, errors.New("the users'-route relay isn't running on this server")
	}
	if rc != 0 {
		if err == nil {
			err = errors.New("the server answered with code " + strconv.Itoa(rc))
		}
		return DNSExit{}, err
	}
	d, ok := dnsExitParse(lines)
	if !ok {
		return d, errors.New("no reading (ip-api did not answer through the users' route)")
	}
	return d, nil
}

// dnsExitFix sets (or with undo, puts back) the server's resolvers and reads the result.
func (a *App) dnsExitFix(ctx context.Context, srv *Server, undo bool) (DNSExit, error) {
	pre := "UNDO=0\n"
	if undo {
		pre = "UNDO=1\n"
	}
	rc, _, err := a.igShell(ctx, srv, pre+dnsExitFixScript, 60*time.Second)
	switch {
	case rc == 4:
		return DNSExit{}, errors.New("names stopped resolving with the public resolvers, so the old DNS setting was put back")
	case rc == 5:
		return DNSExit{}, errors.New("/etc/resolv.conf can't be written on this server (it is locked or managed by something else)")
	case rc != 0:
		if err == nil {
			err = errors.New("the server answered with code " + strconv.Itoa(rc))
		}
		return DNSExit{}, err
	}
	return a.dnsExitRead(ctx, srv)
}

type dnsExitState struct {
	bad  int
	sent time.Time
}

// dnsExitStep folds one verdict into a server's state; true = report it now.
func dnsExitStep(st *dnsExitState, v string, now time.Time) bool {
	switch v {
	case "ok", "mixed":
		st.bad = 0
	case "bad":
		st.bad++
		if st.bad >= dnsExitBad && now.Sub(st.sent) >= dnsExitAlert {
			st.sent = now
			return true
		}
	}
	return false
}

func (a *App) dnsExitLoop() {
	states := map[string]*dnsExitState{}
	time.Sleep(9 * time.Minute)
	for ; ; time.Sleep(dnsExitTick) {
		var list []*Server
		a.store.View(func(s *State) {
			for _, x := range s.Servers {
				if x.Igproxy && x.IPv4 != "" {
					list = append(list, x)
				}
			}
		})
		out := make([]DNSExit, len(list))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 3)
		for i, s := range list {
			wg.Add(1)
			go func(i int, s *Server) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				out[i], _ = a.dnsExitRead(context.Background(), s)
			}(i, s)
		}
		wg.Wait()
		now := time.Now()
		seen := map[string]bool{} // one machine can be on the page twice
		for i, s := range list {
			if seen[s.IPv4] {
				continue
			}
			seen[s.IPv4] = true
			st := states[s.IPv4]
			if st == nil {
				st = &dnsExitState{}
				states[s.IPv4] = st
			}
			if dnsExitStep(st, out[i].Verdict(), now) {
				a.pushTo(s.Owner, fmt.Sprintf("🧭 DNS of %s is not in its exit's country: %s. Fix: IG Routing → %s → Tests → Run checks → DNS → \"Use public DNS\" (it can be put back).", igLabel(s), out[i].why(), s.Name))
			}
		}
	}
}

// POST /api/igproxy/dns {id, fix, undo} : read the server's DNS place; fix sets the public
// resolvers, undo puts the old setting back.
func (s *Server2) igDNS(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	var in struct {
		ID        string
		Fix, Undo bool
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	x, err := s.igServer(user, admin, in.ID)
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 110*time.Second)
	defer cancel()
	var d DNSExit
	if in.Fix || in.Undo {
		d, err = s.app.dnsExitFix(ctx, x, in.Undo)
	} else {
		d, err = s.app.dnsExitRead(ctx, x)
	}
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	// the kept "Run checks" result follows, so the page shows the new line without a re-run
	c := dnsExitCheck(d)
	igHLast.Lock()
	if h, ok := igHLast.m[x.ID]; ok {
		svcs := make([]IgHCheck, 0, len(h.Svcs)+1)
		for _, o := range h.Svcs {
			if o.K != "DNS" {
				svcs = append(svcs, o)
			}
		}
		h.Svcs = append(svcs, c)
		igHLast.m[x.ID] = h
	}
	igHLast.Unlock()
	writeJSON(w, map[string]any{"dns": d, "verdict": d.Verdict(), "check": c})
}
