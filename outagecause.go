package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// What counts as a tunnel outage, and why it happened.
//
// A hot-standby tunnel's users are cut only when the switcher has nowhere to put them: every
// path down, or the users' path down well past the switcher's grace while another works (the
// switcher failed to move them). One failed probe of the users' path is not an outage — the
// switcher checks every 2 s and moves them after hsGrace s; the panel reads it once a minute.
// The log of 2026-11-11..13 was full of ~2-minute "tunnel dropped" entries that were exactly
// that: the users' path flapping (or failing for its 30 s grace) while the switcher kept them
// up, read by two one-minute checks in a row. The traffic proof (data still reaching the
// users) only worked while someone had the panel open, so the false ones bunched at night;
// the monitor now reads the users' counters itself before it calls the tunnel down.

// hsMoveWait: how long the users' path may be down, with another path working, before the
// switcher counts as having failed them (its grace + a few rounds of checks).
const hsMoveWait = hsGrace + 60

// hsUsersCut judges the switcher's view: cut = the users may have no service; code says why
// (all_down, not_moved, no_path; "" or moving when they have service).
func hsUsersCut(v *hsView) (bool, string) {
	if v == nil || v.Active < 0 || v.Active >= len(v.OK) {
		return true, "no_path"
	}
	if v.OK[v.Active] {
		return false, ""
	}
	others := 0
	for k, ok := range v.OK {
		if ok && k != v.Active {
			others++
		}
	}
	if others == 0 {
		return true, "all_down"
	}
	// down since when, on the switcher's own clock (no clock line, no "since": the old rule)
	if v.Active < len(v.Changed) && v.Changed[v.Active] > 0 {
		now := v.Clock
		if now == 0 {
			now = time.Now().Unix()
		}
		if now-v.Changed[v.Active] < hsMoveWait {
			return false, "moving"
		}
	}
	return true, "not_moved"
}

// hsUsersFlowNow reads the users' counters of a hot-standby tunnel twice, 4 s apart (the
// chains hsAcct made; nothing is created here): data reaching the users at hsUsersRate or
// more, and some coming from them, proves their path works whatever the probe says.
func hsUsersFlowNow(ctx context.Context, h Host, t *Tunnel) bool {
	in, out := "TPHA_"+t.ID, "TPHB_"+t.ID
	script := fmt.Sprintf(`r() { iptables -w -t mangle -nvxL $1 2>/dev/null | awk 'NR>2{s+=$2}END{if(NR<2)print "-";else printf "%%.0f", s+0}'; }
d1=$(r %[2]s); u1=$(r %[1]s); sleep 4; d2=$(r %[2]s); u2=$(r %[1]s)
echo "U $d1 $u1 $d2 $u2"`, in, out)
	res, _ := h.Run(ctx, script, nil)
	for _, l := range strings.Split(res, "\n") {
		f := strings.Fields(l)
		if len(f) != 5 || f[0] != "U" {
			continue
		}
		var n [4]float64
		for i := range n {
			x, err := strconv.ParseFloat(f[i+1], 64)
			if err != nil {
				return false
			}
			n[i] = x
		}
		down, up := (n[2]-n[0])*8/4, (n[3]-n[1])*8/4
		return down >= hsUsersRate && up > 2000
	}
	return false
}

// OutageWhy is a tunnel outage's cause in plain words, in both languages.
type OutageWhy struct {
	Code string // see tunnelWhy
	En   string
	Fa   string
}

// tunnelWhy says, for a tunnel that just went down, why: the panel host or its servers not
// answering, the service on a server, every hot-standby path down (with the cause finder's
// verdict for the users' path, see outageRefine), the switcher not moving the users, or the
// link of a single-method tunnel.
func (a *App) tunnelWhy(t *Tunnel, reason string, v *hsView) OutageWhy {
	if !a.serverReachable("panel") {
		return OutageWhy{"panel", "The panel host itself was offline — it could not see the tunnel", "خود سرور پنل آفلاین بود — تانل را نمی‌دید"}
	}
	ir, kh := a.serverReachable(t.ServerID), t.ForeignID == "" || a.serverReachable(t.ForeignID)
	var irN, khN string
	if !ir || !kh {
		irN, khN = serverName(a, t.ServerID), serverName(a, t.ForeignID)
	}
	switch {
	case !ir && !kh:
		return OutageWhy{"servers", fmt.Sprintf("Both servers stopped answering (%s, %s) — their networks dropped", irN, khN),
			fmt.Sprintf("هر دو سرور جواب نمی‌دادند (%s، %s) — شبکه‌شان قطع شد", irN, khN)}
	case !ir:
		return OutageWhy{"iran_down", fmt.Sprintf("The Iran server %s stopped answering — the server or its network", irN),
			fmt.Sprintf("سرور ایران %s جواب نمی‌داد — خود سرور یا شبکه‌اش", irN)}
	case !kh:
		return OutageWhy{"foreign_down", fmt.Sprintf("The foreign server %s stopped answering — the server or its network", khN),
			fmt.Sprintf("سرور خارج %s جواب نمی‌داد — خود سرور یا شبکه‌اش", khN)}
	}
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "switcher"):
		return OutageWhy{"switcher", "The path switcher on the Iran server wasn't running", "سوییچر مسیرها روی سرور ایران اجرا نمی‌شد"}
	case strings.HasPrefix(r, "iran service"):
		return OutageWhy{"iran_service", "The tunnel's service on the Iran server stopped (" + strings.TrimPrefix(reason, "Iran service ") + ")",
			"سرویس تانل روی سرور ایران متوقف شد (" + strings.TrimPrefix(reason, "Iran service ") + ")"}
	case strings.HasPrefix(r, "foreign service"):
		return OutageWhy{"foreign_service", "The tunnel's service on the foreign server stopped (" + strings.TrimPrefix(reason, "foreign service ") + ")",
			"سرویس تانل روی سرور خارج متوقف شد (" + strings.TrimPrefix(reason, "foreign service ") + ")"}
	}
	if t.HotStandby && v != nil {
		_, code := hsUsersCut(v)
		path := ""
		if v.Active >= 0 && v.Active < len(v.Paths) {
			path = v.Paths[v.Active]
		}
		switch code {
		case "all_down":
			return OutageWhy{"all_down", fmt.Sprintf("All %d paths were down at once — no data passed between the servers", len(v.OK)),
				fmt.Sprintf("هر %d مسیر هم‌زمان قطع بودند — هیچ داده‌ای بین دو سرور رد نمی‌شد", len(v.OK))}
		case "not_moved":
			return OutageWhy{"not_moved", fmt.Sprintf("The users' path %s was down and the switcher didn't move them, though another path worked", path),
				fmt.Sprintf("مسیر کاربران (%s) قطع بود و سوییچر آن‌ها را جابه‌جا نکرد، با اینکه مسیر دیگری کار می‌کرد", path)}
		case "no_path":
			return OutageWhy{"no_path", "The switcher had no path for the users", "سوییچر هیچ مسیری برای کاربران نداشت"}
		}
	}
	return OutageWhy{"link", "No data passed between the servers, though both answered — the tunnel or its route dropped",
		"بین دو سرور داده‌ای رد نمی‌شد، با اینکه هر دو جواب می‌دادند — خود تانل یا مسیرش قطع شد"}
}

// outageRefine adds the cause finder's verdict (downcause.go) for the users' path to an open
// hot-standby outage once it has one: "All 10 paths were down at once — BackPack (v4): the
// route blocks TCP …". Called each monitor round while the outage lasts.
func (a *App) outageRefine(oid string, t *Tunnel, base OutageWhy) {
	v := a.hsViewOf(t.ID)
	if v == nil || v.Active < 0 || v.Active >= len(v.Keys) {
		return
	}
	a.healthMu.Lock()
	c := a.dc.cache[t.ID+"|"+v.Keys[v.Active]]
	a.healthMu.Unlock()
	if c == nil || c.Text == "" {
		return
	}
	path := v.Paths[v.Active]
	w := OutageWhy{Code: base.Code + "/" + c.Code, En: base.En + " · " + path + ": " + c.Text, Fa: base.Fa + " · " + path + ": " + orStr(c.TextFa, c.Text)}
	a.setOutageWhy(oid, w)
}

// setOutageWhy writes a tunnel outage's cause.
func (a *App) setOutageWhy(oid string, w OutageWhy) {
	_ = a.store.Update(func(st *State) error {
		for i := range st.Outages {
			if o := &st.Outages[i]; o.ID == oid && (o.Code != w.Code || o.Why != w.En) {
				o.Code, o.Why, o.WhyFa = w.Code, w.En, w.Fa
			}
		}
		return nil
	})
}

// markProbeOnly flags the hot-standby tunnel outages logged before the rule above: they were
// one probe of the users' path failing at two reads a minute apart, not proof the users were
// cut. They stay in the log (folded, "not confirmed") and leave the uptime alone.
func (a *App) markProbeOnly() {
	_ = a.store.Update(func(st *State) error {
		hs := map[string]bool{}
		for _, t := range st.Tunnels {
			if t.HotStandby {
				hs[t.ID] = true
			}
		}
		for i := range st.Outages {
			o := &st.Outages[i]
			if o.Kind == "tunnel" && o.Code == "" && o.Old == "" && o.End != 0 && hs[o.Target] && strings.HasPrefix(o.Cause, "both servers answer") {
				o.Old = "probe"
			}
		}
		return nil
	})
}

// hsDownSince: when the users' path really went down (the switcher's "since", moved to the
// panel's clock), not the panel's first failed read up to a minute later; first = that read.
func hsDownSince(v *hsView, first time.Time) time.Time {
	if v == nil || v.Clock == 0 || v.Active < 0 || v.Active >= len(v.Changed) || v.Changed[v.Active] == 0 {
		return first
	}
	ago := v.Clock - v.Changed[v.Active]
	if ago <= 0 || ago > 3600 {
		return first
	}
	at := time.Now().Add(-time.Duration(ago) * time.Second)
	if at.After(first) {
		return first
	}
	return at
}
