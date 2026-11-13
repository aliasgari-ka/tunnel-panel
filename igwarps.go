package main

// WARP tab of IG Routing: one row per WARP account with what matters (state, exit IP and
// country, last music / speed test, what it serves now, WARP+ or free). The agent's own
// "warp ls" prints only the endpoint (the same for every account) and "warp list" tests every
// WARP one after another, so the panel reads the agent's state files instead and asks
// Cloudflare's trace page once per WARP, all at the same time (a few hundred bytes each).
// The WARP private keys and WARP+ licence keys are never read out: only whether a key exists.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// igWarpScript prints one "W\tk=v\t…" line per WARP and one "S\t…" line for the server.
// Ports and paths are the agent's: WARP n is tested on 127.0.0.1:12350+n (WARP_TEST_BASE).
const igWarpScript = `D=/etc/igproxy R=/run/igproxy
[ -s "$D/warps" ] || { printf 'S\tnone=1\n'; exit 0; }
now=$(date +%s); i=0
f(){ [ -s "$1" ] && head -c 120 "$1" | tr '\t\n\r' '   ' | sed 's/ *$//'; }
ag(){ [ -e "$1" ] && echo $((now - $(stat -c %Y "$1"))); }
while read -r k a ep id; do
  [ -z "$k" ] && continue; i=$((i+1))
  ( t=$(curl -s -m 6 -x "socks5h://127.0.0.1:$((12350+i))" https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
    tk=$id; [ "$id" = none ] && tk=n$i
    printf 'W\tn=%s\tep=%s\told=%s\tkey=%s\tip=%s\tloc=%s\twarp=%s\tsel=%s\tselage=%s\tout=%s\tnew=%s\tfail=%s\tgcc=%s\tgccage=%s\tid=%s\tage=%s\ttst=%s\n' \
      "$i" "$ep" "$([ "$id" = none ] && echo 1)" "$([ -s "$D/warp-acc/$id/key" ] && echo 1)" \
      "$(sed -n 's/^ip=//p' <<<"$t")" "$(sed -n 's/^loc=//p' <<<"$t")" "$(sed -n 's/^warp=//p' <<<"$t")" \
      "$(f "$R/wsel_$i")" "$(ag "$R/wsel_$i")" "$(f "$R/wout_$i")" "$(f "$R/wnew_$i")" "$(f "$R/wfail_$i")" "$(f "$R/gcc_$i")" "$(ag "$R/gcc_$i")" \
      "$(tr -cd 'A-Za-z0-9' <<<"$id")" "$([ "$id" != none ] && ag "$D/warp-acc/$id")" "$(f "$R/wtest_$tk")" ) &
done < "$D/warps"
wait
st=$(cat "$R/igcc_stop" 2>/dev/null || echo 0); fn=$(cat "$R/fill_next" 2>/dev/null || echo 0)
printf 'S\tactive=%s\tgact=%s\tsel=%s\tpoolip=%s\tselago=%s\tccstop=%s\tfnext=%s\trejcc=%s\thour=%s\tvia=%s\n' "$(f $R/warp_active)" "$(f $R/gwarp_active)" "$(f $R/sel_state)" "$(f $R/pool_ip)" "$(ag $R/last_sel)" \
  "$(( ${st:-0} > now ? ${st:-0} - now : 0 ))" "$(( ${fn:-0} > now ? ${fn:-0} - now : 0 ))" "$(tail -n 1 "$R/igcc_rej" 2>/dev/null | grep -oE '[A-Z]{2}' | tail -n 1)" "$(date +%-H)" "$([ -s "$D/warp_via" ] && echo 1)"
`

// IgWarp is one WARP account as the WARP tab shows it.
type IgWarp struct {
	N        int    `json:"n"`
	State    string `json:"state"`         // ok | down | repair | out
	Why      string `json:"why,omitempty"` // out: ip | ipnew | music | down | …; repair/down: the agent's reason
	Plus     bool   `json:"plus"`          // WARP+ (Cloudflare says warp=plus)
	Key      bool   `json:"key"`           // a WARP+ licence key is saved for it
	Old      bool   `json:"old,omitempty"` // an account from before auto keys (remove + add again)
	IP       string `json:"ip,omitempty"`  // exit IP Cloudflare sees through it now
	Loc      string `json:"loc,omitempty"` // that exit's country (Cloudflare)
	GCC      string `json:"gcc,omitempty"` // the country Google places it in (cached ≤ 30 min by the agent)
	GCCAge   int    `json:"gccAge,omitempty"`
	Music    string `json:"music,omitempty"` // last test: ok | no | down | ? (not tested)
	MusicWhy string `json:"musicWhy,omitempty"`
	Mbps     int    `json:"mbps,omitempty"`
	TestAge  int    `json:"testAge"` // seconds since the last music / speed test (-1 = never)
	Fails    int    `json:"fails,omitempty"`
	Next     string `json:"next,omitempty"` // why the agent wants a new account for it ("no Instagram music", "only 12 Mbps")
	Endpoint string `json:"endpoint,omitempty"`
	ID       string `json:"-"`             // the account's folder name (the panel's trims check it; never shown)
	Age      int    `json:"age,omitempty"` // seconds since the account was made (0 = unknown)
	// the panel's own test of a standby (warppool.go): ok | no (no-music country) | down, its exit, Instagram's country
	Test    string `json:"test,omitempty"`
	TestIP  string `json:"testIP,omitempty"`
	TestCC  string `json:"testCC,omitempty"`
	TestLoc string `json:"testLoc,omitempty"`
	TestAt  int64  `json:"testAt,omitempty"`
}

// IgWarps is the whole tab.
type IgWarps struct {
	Warps  []IgWarp `json:"warps"`
	Active int      `json:"active"` // FAILOVER: the WARP Instagram uses (0 = none / BALANCE)
	GAct   int      `json:"gact"`   // the WARP Google is pinned to (0 = none)
	Sel    string   `json:"sel"`    // the last automatic choice: ok | none (nothing good enough)
	PoolIP string   `json:"poolIP"` // BALANCE: the exit IP the pool shares
	SelAgo int      `json:"selAgo"` // seconds since the last automatic choice (-1 = unknown)
	At     int64    `json:"at"`
	CCStop int      `json:"ccStop,omitempty"` // the agent stopped making accounts for this long: each new one read a no-music country
	RejCC  string   `json:"rejCC,omitempty"`  // … that country
	FNext  int      `json:"fNext,omitempty"`  // the agent's next try to make missing accounts (seconds)
	Hour   int      `json:"hour"`             // the server's local hour (trims run at night)
	Via    bool     `json:"via,omitempty"`    // warp-via: Instagram's WARPs enter Cloudflare through other servers
}

func igAtoi(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func igKV(line string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Split(line, "\t")[1:] {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// igParseWarps turns igWarpScript's output into the tab's rows.
func igParseWarps(out string) IgWarps {
	r := IgWarps{Warps: []IgWarp{}, SelAgo: -1, At: time.Now().Unix()}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case strings.HasPrefix(l, "S\t"):
			m := igKV(l)
			r.Active, r.GAct, r.Sel, r.PoolIP = igAtoi(m["active"], 0), igAtoi(m["gact"], 0), m["sel"], m["poolip"]
			r.SelAgo = igAtoi(m["selago"], -1)
			r.CCStop, r.FNext, r.RejCC, r.Hour, r.Via = igAtoi(m["ccstop"], 0), igAtoi(m["fnext"], 0), m["rejcc"], igAtoi(m["hour"], -1), m["via"] == "1"
		case strings.HasPrefix(l, "W\t"):
			m := igKV(l)
			w := IgWarp{N: igAtoi(m["n"], 0), Endpoint: m["ep"], Key: m["key"] == "1", Old: m["old"] == "1",
				IP: m["ip"], Loc: m["loc"], GCC: m["gcc"], GCCAge: igAtoi(m["gccage"], 0),
				TestAge: igAtoi(m["selage"], -1), Fails: igAtoi(m["fail"], 0), Next: m["new"], ID: m["id"], Age: igAtoi(m["age"], 0)}
			w.setTest(m["tst"])
			if w.N < 1 {
				continue
			}
			w.Plus = m["warp"] == "plus"
			// wsel_n: "<ok|no|down|?> <Mbps> [why]"
			if s := strings.Fields(m["sel"]); len(s) > 0 {
				w.Music = s[0]
				if len(s) > 1 {
					w.Mbps = igAtoi(s[1], 0)
				}
				if len(s) > 2 {
					w.MusicWhy = strings.Join(s[2:], " ")
				}
			}
			up := m["warp"] == "on" || m["warp"] == "plus"
			switch {
			case m["out"] != "":
				w.State, w.Why = "out", strings.Fields(m["out"])[0]
			case up:
				w.State = "ok"
			case m["new"] != "" || w.Fails > 0:
				w.State, w.Why = "repair", m["new"]
			default:
				w.State = "down"
			}
			r.Warps = append(r.Warps, w)
		}
	}
	sort.Slice(r.Warps, func(i, j int) bool { return r.Warps[i].N < r.Warps[j].N })
	return r
}

func (a *App) igWarps(ctx context.Context, srv *Server) (IgWarps, error) {
	h, err := a.igHost(ctx, srv)
	if err != nil {
		return IgWarps{}, err
	}
	out, err := h.Run(ctx, igWarpScript, nil)
	if err != nil && !strings.Contains(out, "S\t") {
		return IgWarps{}, err
	}
	if !strings.Contains(out, "S\t") {
		return IgWarps{}, errors.New("no answer from the server")
	}
	return igParseWarps(out), nil
}

func (s *Server2) igWarpsGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	x, err := s.igServer(user, admin, r.URL.Query().Get("id"))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	res, err := s.app.igWarps(ctx, x)
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, res)
}
