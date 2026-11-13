package main

// The Settings tab of IG Routing: the agent's settings as data, with each one's default, and
// saving several of them at once on one server or on every server in view.
//
// The agent's "info" line never had two of them: "WARPs only for Google" (gwarps_n) and the
// allowed countries for Google (gcountries). The page showed the count of Google's WARPs in
// use instead (0 or "-" when Google wasn't on WARP, 2 on a server set to 3) and an empty
// country box with the default list as its grey placeholder, so a save could quietly write a
// value nobody chose. The panel now reads the setting files themselves (no keys among them)
// and the defaults from the installed agent.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// igOptsScript prints "F\t<file>\t<value>" for each value file, "E\t<file>" for each flag file
// that exists, "C\t<name>\t<value>" for the agent's defaults and "K\t<key>" for each set key the
// installed agent knows.
const igOptsScript = `D=/etc/igproxy B=/usr/local/bin/igproxy
[ -d "$D" ] && [ -f "$B" ] || { printf 'N\t1\n'; exit 0; }
for f in min_mbps min_warps grot_min music_min gwarps_n gcountries; do
  [ -s "$D/$f" ] && printf 'F\t%s\t%s\n' "$f" "$(head -c 200 "$D/$f" | tr '\t\r\n' '   ' | sed 's/  */ /g; s/^ //; s/ $//')"
done
for f in autokey warp_spread geo_off gspread warp_auto gall guard_off kwg; do [ -e "$D/$f" ] && printf 'E\t%s\n' "$f"; done
c(){ sed -n "s/^$1=\"\{0,1\}\([^\";#]*\).*/\1/p" "$B" | head -1 | sed 's/ *$//'; }
printf 'C\tminspeed\t%s\nC\tgrotate\t%s\nC\tmusiccheck\t%s\nC\tgcountries\t%s\n' "$(c MIN_WARP_MBPS)" "$(c GROT_MIN)" "$(c MUSIC_MIN)" "$(c GCOUNTRIES)"
printf 'C\tminwarps\t%s\nC\tgwarps\t%s\n' "$(sed -n 's/^min_warps().*|| echo \([0-9]*\).*/\1/p' "$B" | head -1)" "$(sed -n 's/^gw_n().*|| echo \([0-9]*\).*/\1/p' "$B" | head -1)"
for k in minspeed minwarps grotate musiccheck gwarps gcountries mode guard autokey geosite gspread gall warpauto kwg; do
  grep -qE "^ +$k\)" "$B" && printf 'K\t%s\n' "$k"
done
`

// igOptKeys are the settings in the order they are saved (the router reloads last).
var igOptKeys = []string{"minspeed", "minwarps", "warpauto", "autokey", "musiccheck", "guard", "grotate", "gcountries", "gwarps", "gspread", "gall", "geosite", "mode", "kwg"}

// the agent's own defaults, for an agent too old to say them
var igOptDefaults = map[string]string{
	"minspeed": "200", "minwarps": "3", "grotate": "20", "musiccheck": "5", "gwarps": "2",
	"gcountries": "US GB DE FR NL FI SE CH AT BE IT ES PL CA JP SG AU",
	"mode": "failover", "guard": "on", "autokey": "off", "geosite": "on", "gspread": "off", "gall": "off", "warpauto": "off", "kwg": "off",
}

// the settings that are a switch (on / off, or the mode: balance / failover; the agent also takes "toggle")
var igOptSwitch = map[string]bool{"mode": true, "guard": true, "autokey": true, "geosite": true, "gspread": true, "gall": true, "warpauto": true, "kwg": true}

// IgOpts is the Settings tab of one server.
type IgOpts struct {
	Val  map[string]string `json:"val"`  // the value in use (a missing file = the default)
	Def  map[string]string `json:"def"`  // the agent's default
	Own  map[string]bool   `json:"own"`  // a value was saved (not the default by absence)
	Keys []string          `json:"keys"` // the settings this agent knows (an old agent lacks some)
	None bool              `json:"none,omitempty"`
}

func igParseOpts(out string) IgOpts {
	r := IgOpts{Val: map[string]string{}, Def: map[string]string{}, Own: map[string]bool{}}
	for k, v := range igOptDefaults {
		r.Def[k] = v
	}
	file := map[string]string{"min_mbps": "minspeed", "min_warps": "minwarps", "grot_min": "grotate", "music_min": "musiccheck", "gwarps_n": "gwarps", "gcountries": "gcountries"}
	vals, flags := map[string]string{}, map[string]bool{}
	known := map[string]bool{}
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		f := strings.Split(l, "\t")
		switch {
		case f[0] == "N":
			r.None = true
		case f[0] == "F" && len(f) == 3:
			if k, ok := file[f[1]]; ok {
				vals[k] = strings.TrimSpace(f[2])
			}
		case f[0] == "E" && len(f) == 2:
			flags[f[1]] = true
		case f[0] == "C" && len(f) == 3:
			if v := strings.TrimSpace(f[2]); v != "" {
				if _, ok := igOptDefaults[f[1]]; ok {
					r.Def[f[1]] = v
				}
			}
		case f[0] == "K" && len(f) == 2:
			known[f[1]] = true
		}
	}
	for _, k := range igOptKeys {
		if known[k] {
			r.Keys = append(r.Keys, k)
		}
	}
	onoff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	for _, k := range []string{"minspeed", "minwarps", "grotate", "musiccheck", "gwarps", "gcountries"} {
		if v, ok := vals[k]; ok && v != "" {
			r.Val[k], r.Own[k] = v, true
		} else {
			r.Val[k] = r.Def[k]
		}
	}
	r.Val["mode"] = map[bool]string{true: "balance", false: "failover"}[flags["warp_spread"]]
	r.Val["guard"] = onoff(!flags["guard_off"])
	r.Val["geosite"] = onoff(!flags["geo_off"])
	r.Val["autokey"] = onoff(flags["autokey"])
	r.Val["gspread"] = onoff(flags["gspread"])
	r.Val["gall"] = onoff(flags["gall"])
	r.Val["warpauto"] = onoff(flags["warp_auto"])
	r.Val["kwg"] = onoff(flags["kwg"])
	for _, k := range []string{"mode", "guard", "geosite", "autokey", "gspread", "gall", "warpauto", "kwg"} {
		r.Own[k] = r.Val[k] != r.Def[k]
	}
	return r
}

func (a *App) igOpts(ctx context.Context, srv *Server) (IgOpts, error) {
	h, err := a.igHost(ctx, srv)
	if err != nil {
		return IgOpts{}, err
	}
	out, err := h.Run(ctx, igOptsScript, nil)
	if err != nil && !strings.Contains(out, "C\t") && !strings.Contains(out, "N\t") {
		return IgOpts{}, err
	}
	if !strings.Contains(out, "C\t") && !strings.Contains(out, "N\t") {
		return IgOpts{}, errors.New("no answer from the server")
	}
	return igParseOpts(out), nil
}

func (s *Server2) igOptsGet(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	x, err := s.igServer(user, admin, r.URL.Query().Get("id"))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.app.igOpts(ctx, x)
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, res)
}

// igOptVal checks one setting the way the agent does (its own limits, so a bad value is refused
// here with the reason rather than as a usage line from the server). Persian digits are taken.
func igOptVal(k, v string) (string, error) {
	v = strings.TrimSpace(igDigits(v))
	num := func(lo, hi int, what string) (string, error) {
		n, err := strconv.Atoi(v)
		if err != nil || !regexp.MustCompile(`^[0-9]{1,5}$`).MatchString(v) || n < lo || n > hi {
			return "", fmt.Errorf("%s: a number from %d to %d", what, lo, hi)
		}
		return strconv.Itoa(n), nil
	}
	switch k {
	case "minspeed":
		return num(0, 10000, "minimum WARP speed")
	case "minwarps":
		return num(0, 20, "minimum number of WARPs")
	case "gwarps":
		return num(0, 9, "WARPs only for Google")
	case "musiccheck":
		return num(0, 60, "music check")
	case "grotate":
		s, err := num(0, 1440, "fresh IP for Google")
		if n, _ := strconv.Atoi(s); err != nil || n != 0 && n < 10 {
			return "", errors.New("fresh IP for Google: 0, or 10 to 1440 minutes")
		}
		return s, nil
	case "gcountries":
		c := strings.ToUpper(strings.Join(strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '،' }), " "))
		if !igCC.MatchString(c) {
			return "", errors.New("countries for Google: two-letter codes with spaces, like US GB DE")
		}
		return c, nil
	case "mode":
		if v = strings.ToLower(v); v == "balance" || v == "failover" {
			return v, nil
		}
		return "", errors.New("WARP mode: balance or failover")
	case "guard", "autokey", "geosite", "gspread", "gall", "warpauto", "kwg":
		if v = strings.ToLower(v); v == "on" || v == "off" {
			return v, nil
		}
		return "", fmt.Errorf("%s: on or off", k)
	}
	return "", errors.New("unknown setting: " + k)
}

// igOptsSave writes the changed settings on one server or on every server in view, one job,
// and ends with one line per server: what was saved and what was refused.
func (s *Server2) igOptsSave(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	p, err := igBody(r)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	in, _ := p["set"].(map[string]any)
	if len(in) == 0 {
		httpErr(w, 400, "nothing to save")
		return
	}
	set := map[string]string{}
	for k, v := range in {
		val, err := igOptVal(k, igStr(v))
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		set[k] = val
	}
	tl, err := s.igTargets(user, admin, p["srv"], igStr(p["view"]))
	if err == nil && len(tl) == 0 {
		err = errors.New("no servers")
	}
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if _, a := set["minwarps"]; a {
		for _, x := range tl {
			s.app.wpHold(x.ID) // sized by hand: the automatic pool (warppool.go) waits a day
		}
	} else if _, b := set["warpauto"]; b {
		for _, x := range tl {
			s.app.wpHold(x.ID)
		}
	}
	var keys []string
	for _, k := range igOptKeys {
		if _, ok := set[k]; ok {
			keys = append(keys, k)
		}
	}
	title := "Settings - " + igLabel(tl[0])
	if len(tl) > 1 {
		title = fmt.Sprintf("Settings - %d servers", len(tl))
	}
	id, err := s.app.igJob(user, title, time.Duration(len(tl)*len(keys))*220*time.Second, func(ctx context.Context, out func(string)) bool {
		var sum []string
		allOK := true
		for _, x := range tl {
			if ctx.Err() != nil {
				break
			}
			out("== " + igLabel(x))
			var bad []string
			n := 0
			for _, k := range keys {
				if ctx.Err() != nil {
					break
				}
				if gemHomeOptBad(x, k, set[k]) {
					out("!! " + gemHomeOptRefusal)
					bad = append(bad, k+" ("+gemHomeOptRefusal+")")
					continue
				}
				rc, said := s.app.igRun(ctx, x, []string{"set", k, set[k]}, "", 180, out)
				if rc == 0 {
					n++
				} else {
					bad = append(bad, k+" ("+igLastWords(said)+")")
				}
			}
			s.app.igForget(x.ID)
			out("")
			if len(bad) == 0 {
				sum = append(sum, fmt.Sprintf("✓ %s: %d saved", igLabel(x), n))
			} else {
				allOK = false
				sum = append(sum, fmt.Sprintf("✕ %s: %d saved, not saved: %s", igLabel(x), n, strings.Join(bad, ", ")))
			}
		}
		out("== result")
		for _, l := range sum {
			out(l)
		}
		return allOK
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"job": id})
}

// igLastWords is the agent's last line, short (its reason for a refusal).
func igLastWords(s string) string {
	l := strings.TrimSpace(lastLineOf(s))
	l = strings.TrimPrefix(strings.TrimPrefix(l, "!! "), "igproxy: ")
	if l == "" {
		return "no answer"
	}
	if len(l) > 90 {
		l = l[:90] + "…"
	}
	return l
}
