package main

// IG Routing · WARP through another server ("warp-via"), set up by the panel itself.
//
// Cloudflare lets a WARP out in the datacenter where its WireGuard enters. A server whose own
// WARPs Instagram places in IR (NL via Amsterdam, Ger-hertzener's IPv6) gets a music country when
// the same accounts enter Cloudflare through another server: a UDP forward there (kernel DNAT, no
// process) and the agent's "warp-via set ip:port". On NL this was done by hand on 2026-11-13
// (xe108 / xe107: igwarp-fwd.service); here the Instagram ladder does it when both WARP families
// fail, before it gives Instagram to a proxy:
//
//   - donors: other foreign servers of the same owner (never the panel host), Germany first, then
//     Europe, then the rest of the music countries;
//   - the forward on the donor accepts only this server's IPv4 (/etc/igwarp-fwd.srcs, one per
//     line; a hand-made script's SRCS move into it);
//   - the server's WARPs (not Google's own) then enter through donor:24080, and the users' route
//     is read again: kept only when Instagram reads a music country there, else both are undone.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	igViaPort    = 24080
	igViaDonors  = 2 // donors tried per fix
	igViaCFAddr  = "162.159.192.1"
	igViaCFPort  = 2408
	igViaScriptF = "/usr/local/sbin/igwarp-fwd.sh"
)

var igViaIPRe = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`)

// igViaFwd is the forward script installed on a donor (start | stop). The sources are read from
// /etc/igwarp-fwd.srcs, so one forward serves several servers.
const igViaFwd = `#!/bin/bash
# UDP forward for other servers' WARPs (igproxy "warp-via" on those servers): their WireGuard enters
# Cloudflare here, so Cloudflare lets those WARPs out in this server's datacenter. Only the sources in
# /etc/igwarp-fwd.srcs may use it. Kernel NAT, no process. Managed by the tunnel panel (IG Routing).
SRCS=$(grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' /etc/igwarp-fwd.srcs 2>/dev/null)
PORT=24080
DST=162.159.192.1
DPORT=2408
C=(-m comment --comment igwarp-fwd)
del_all() { # every rule with our comment (also of sources no longer listed)
  local t ch
  for t in nat filter; do
    for ch in PREROUTING POSTROUTING FORWARD; do
      iptables -w -t $t -S $ch 2>/dev/null | grep -- '--comment igwarp-fwd' | sed 's/^-A /-D /' | while read -r r; do
        eval iptables -w -t $t $r 2>/dev/null; done
    done
  done; }
case "$1" in
  stop) del_all; true ;;
  *)
    del_all
    sysctl -qw net.ipv4.ip_forward=1
    for s in $SRCS; do
      iptables -w -t nat -I PREROUTING 1 -s "$s/32" -p udp --dport $PORT "${C[@]}" -j DNAT --to-destination $DST:$DPORT
      iptables -w -t nat -I POSTROUTING 1 -s "$s/32" -d $DST/32 -p udp --dport $DPORT "${C[@]}" -j MASQUERADE
      iptables -w -I FORWARD 1 -s "$s/32" -d $DST/32 -p udp --dport $DPORT "${C[@]}" -j ACCEPT
      iptables -w -I FORWARD 1 -s $DST/32 -d "$s/32" -p udp --sport $DPORT "${C[@]}" -j ACCEPT
    done ;;
esac
`

// igViaFwdScript adds or removes ip as a source of the donor's forward. It prints "FWD <n>" (the
// number of sources) when done.
func igViaFwdScript(op, ip string) string {
	if !igViaIPRe.MatchString(ip) || (op != "add" && op != "del") {
		return "echo __RC=2\n"
	}
	return fmt.Sprintf(`#igviafwd
ulimit -u 200 2>/dev/null
command -v iptables >/dev/null || { echo "no iptables"; echo __RC=3; exit 0; }
S=/etc/igwarp-fwd.srcs F=%[1]s IP=%[2]s
touch $S
# a hand-made forward (2026-11-13) kept its sources in the script: they move into the list
if [ -f $F ] && ! grep -q 'igwarp-fwd.srcs' $F; then
  for s in $(sed -n 's/^SRCS=//p' $F | tr -d '"'"'"); do grep -qx "$s" $S || echo "$s" >> $S; done
fi
if [ %[3]q = add ]; then grep -qx "$IP" $S || echo "$IP" >> $S; else grep -vx "$IP" $S > $S.tmp; mv $S.tmp $S; fi
cat > $F.tmp <<'IGVIAEOF'
%[4]sIGVIAEOF
chmod 755 $F.tmp; mv $F.tmp $F
if [ ! -f /etc/systemd/system/igwarp-fwd.service ]; then
  printf '%%s\n' '[Unit]' 'Description=UDP forward for other servers WARPs (igproxy warp-via)' 'After=network-online.target' 'Wants=network-online.target' '' '[Service]' 'Type=oneshot' 'RemainAfterExit=yes' 'ExecStart=%[1]s start' 'ExecStop=%[1]s stop' '' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/igwarp-fwd.service
  systemctl daemon-reload
fi
if [ -s $S ]; then systemctl enable -q igwarp-fwd 2>/dev/null; $F start; else $F stop; systemctl disable -q igwarp-fwd 2>/dev/null; fi
echo "FWD $(grep -c . $S)"
echo __RC=0
`, igViaScriptF, ip, op, igViaFwd)
}

// igViaRank orders donors: Germany, then Europe, then other countries; never a no-music one.
// Lower = better; -1 = not a donor.
func igViaRank(country string) int {
	cc := strings.ToUpper(strings.TrimSpace(country))
	switch {
	case cc == "" || igNoMusic(cc) || cc == "RU":
		return -1
	case cc == "DE":
		return 0
	case igEurope[cc]:
		return 1
	}
	return 2
}

// igViaDonors: the servers srv's WARPs may enter Cloudflare through, best first.
func (a *App) igViaDonors(srv *Server) []*Server {
	var out []*Server
	hub := gemHomeHost()
	a.store.View(func(st *State) {
		for _, x := range st.Servers {
			if x.ID == srv.ID || x.Owner != srv.Owner || x.Role != "foreign" || !igViaIPRe.MatchString(x.IPv4) || x.IPv4 == hub || x.IPv4 == srv.IPv4 {
				continue
			}
			if igViaRank(x.Country) < 0 {
				continue
			}
			c := *x
			out = append(out, &c)
		}
	})
	for i := len(out) - 1; i >= 0; i-- {
		if a.isPanelHost(out[i]) {
			out = append(out[:i], out[i+1:]...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := igViaRank(out[i].Country), igViaRank(out[j].Country)
		if ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// igViaOn: the agent's warp-via list says a forward is set.
func igViaOn(out string) bool {
	return strings.Contains(out, "warp-via:") && !strings.Contains(out, "warp-via: off")
}

// igInsertVia puts "via" (WARP through another server) right after the WARP candidates.
func igInsertVia(cands []string) []string {
	at := -1
	for i, c := range cands {
		if igIsWarp(c) {
			at = i
		}
	}
	if at < 0 {
		return cands
	}
	out := append([]string{}, cands[:at+1]...)
	out = append(out, "via")
	return append(out, cands[at+1:]...)
}

// igWarpVia sets srv's WARPs to enter Cloudflare through a donor and puts Instagram on route (a
// WARP route). It returns the country Instagram reads on the users' route and the donor, or
// ok=false (everything undone).
func (a *App) igWarpVia(ctx context.Context, srv *Server, route string) (cc string, donor *Server, ok bool) {
	if !igViaIPRe.MatchString(srv.IPv4) || !igIsWarp(route) {
		return "", nil, false
	}
	if rc, out := a.igRun(ctx, srv, []string{"warp-via", "list"}, "", 60, nil); rc != 0 || igViaOn(out) {
		return "", nil, false // an old agent, or a forward somebody set: not ours to change
	}
	tried := 0
	for _, d := range a.igViaDonors(srv) {
		if tried >= igViaDonors || ctx.Err() != nil {
			break
		}
		tried++
		rc, lines, err := a.igShell(ctx, d, igViaFwdScript("add", srv.IPv4), 60*time.Second)
		if err != nil || rc != 0 {
			a.igAutoLog(srv, "IG", "info", fmt.Sprintf("WARP through %s: forward not set (%s)", d.Name, clipTo(strings.Join(append(lines, errStr(err)), " "), 120)))
			continue
		}
		ep := fmt.Sprintf("%s:%d", d.IPv4, igViaPort)
		if rc, out := a.igRun(ctx, srv, []string{"warp-via", "set", ep}, "", 120, nil); rc != 0 {
			a.igAutoLog(srv, "IG", "info", "WARP through "+d.Name+": "+clipTo(strings.TrimSpace(out), 120))
			a.igShell(ctx, d, igViaFwdScript("del", srv.IPv4), 60*time.Second)
			continue
		}
		a.igForget(srv.ID)
		// the WARPs reconnect through the forward: a few seconds more than a plain route change
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		got, err := a.igAutoRoute(ctx, srv, route)
		if err == nil && got != "" && !igNoMusic(got) {
			return got, d, true
		}
		a.igAutoLog(srv, "IG", "info", fmt.Sprintf("tried WARP through %s: %s", d.Name, igWhyBad(got)))
		a.igRun(ctx, srv, []string{"warp-via", "off"}, "", 120, nil)
		a.igShell(ctx, d, igViaFwdScript("del", srv.IPv4), 60*time.Second)
		a.igForget(srv.ID)
	}
	return "", nil, false
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
