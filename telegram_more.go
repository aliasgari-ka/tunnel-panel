package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// More of the panel in the bot: a page per server (test the connection, kernel tuning,
// packages), a route benchmark from a tunnel's page, a button that opens the panel, and a
// daily report at the hour set in Settings (Telegram section).

// panelURL is the panel's first HTTPS domain ("" when it runs without one).
func panelURL() string {
	if panelTLS == "" || panelTLS == "self" {
		return ""
	}
	if ds := splitDomains(panelTLS); len(ds) > 0 {
		return "https://" + ds[0] + "/"
	}
	return ""
}

// serverPicker lists every server as a button.
func (b *Bot) serverPicker() (string, string) {
	var rows [][]ikey
	var row []ikey
	b.app.store.View(func(st *State) {
		for _, s := range st.Servers {
			icon := "🇮🇷"
			if s.Role == "foreign" {
				icon = flagEmoji(s.Country)
			}
			row = append(row, ikey{Text: icon + " " + s.Name, Data: "sv:" + s.ID})
			if len(row) == 2 {
				rows, row = append(rows, row), nil
			}
		}
	})
	if len(row) > 0 {
		rows = append(rows, row)
	}
	rows = append(rows, []ikey{{Text: "📊 Live resources", Data: "home:res"}, {Text: "« Tunnels", Data: "home"}})
	return "<b>🖥 Servers</b>\n<i>tap a server: test it, tune its kernel, install packages</i>", b.keyboard(rows)
}

// serverPage is one server's card.
func (b *Bot) serverPage(srv *Server) (string, string) {
	var c Server
	var tunnels []string
	b.app.store.View(func(st *State) {
		c = *srv
		for _, t := range st.Tunnels {
			if t.ServerID == srv.ID || t.ForeignID == srv.ID {
				tunnels = append(tunnels, b.tunnelIcon(t)+" "+t.Name)
			}
		}
	})
	var sb strings.Builder
	role := "🇮🇷 Iran · entry"
	if c.Role == "foreign" {
		role = flagEmoji(c.Country) + " foreign · exit"
	}
	fmt.Fprintf(&sb, "<b>%s</b>  %s\n", esc(c.Name), role)
	fmt.Fprintf(&sb, "IPv4 <code>%s</code>", esc(orStr(c.IPv4, "—")))
	if c.IPv6 != "" {
		fmt.Fprintf(&sb, " · IPv6 <code>%s</code>", esc(c.IPv6))
	}
	sb.WriteString("\n")
	if c.Arch != "" {
		fmt.Fprintf(&sb, "%s %s\n", esc(c.OS), esc(c.Arch))
	}
	reach := orStr(c.LastPath, "not tested yet")
	if b.app.agents != nil && b.app.agents.online(c.ID) != nil {
		reach = "agent online"
	}
	fmt.Fprintf(&sb, "reached via: %s\n", esc(reach))
	if c.Owner != "" {
		fmt.Fprintf(&sb, "account: 👤 %s\n", esc(c.Owner))
	}
	if len(tunnels) > 0 {
		fmt.Fprintf(&sb, "\n<b>Tunnels</b>\n%s\n", esc(strings.Join(tunnels, "\n")))
	}
	rows := [][]ikey{
		{{Text: "🔌 Test connection", Data: "svt:" + c.ID}, {Text: "⚡ Kernel tuning", Data: "svo:" + c.ID}},
		{{Text: "📦 Install / update packages", Data: "svp:" + c.ID}},
		{{Text: "« Servers", Data: "home:sv"}},
	}
	return sb.String(), b.keyboard(rows)
}

// serverAction handles the sv* buttons.
func (b *Bot) serverAction(chat string, msg int64, kind, id string) {
	srv := b.app.store.Server(id)
	if srv == nil {
		text, kb := b.serverPicker()
		b.edit(chat, msg, "That server no longer exists.\n\n"+text, kb)
		return
	}
	back := b.keyboard([][]ikey{{{Text: "« " + srv.Name, Data: "sv:" + id}}})
	switch kind {
	case "sv":
		text, kb := b.serverPage(srv)
		b.edit(chat, msg, text, kb)
	case "svt":
		b.slow(chat, "testing every path to "+srv.Name+"…", func() (string, string) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			r := b.app.TestServer(ctx, srv)
			var sb strings.Builder
			icon := "❌"
			if r.OK {
				icon = "✅"
			}
			fmt.Fprintf(&sb, "%s <b>%s</b> — connection test\n", icon, esc(srv.Name))
			for _, p := range r.Paths {
				m := "✕"
				if p.OK {
					m = "✓"
				}
				fmt.Fprintf(&sb, "%s %s — %s\n", m, esc(p.Path), esc(p.Info))
			}
			if r.OK {
				fmt.Fprintf(&sb, "best: %s · %s %s", esc(r.Best), esc(r.OS), esc(r.Arch))
			}
			return sb.String(), back
		})
	case "svo", "svoa":
		apply := kind == "svoa"
		wait := "reading the kernel of " + srv.Name + "…"
		if apply {
			wait = "applying the kernel tuning on " + srv.Name + "…"
		}
		b.slow(chat, wait, func() (string, string) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			r := b.app.Optimize(ctx, srv, apply)
			var sb strings.Builder
			fmt.Fprintf(&sb, "<b>⚡ Kernel tuning · %s</b>\n", esc(srv.Name))
			if r.Error != "" {
				fmt.Fprintf(&sb, "⚠ %s", esc(r.Error))
				return sb.String(), back
			}
			fmt.Fprintf(&sb, "kernel %s · %s · %d MB RAM · %d CPU\nnow: %s / %s\n", esc(r.Kernel), esc(r.Virt), r.RAMMB, r.CPUs, esc(r.CC), esc(r.Qdisc))
			for _, n := range r.Notes {
				fmt.Fprintf(&sb, "• %s\n", esc(n))
			}
			if apply {
				if r.Applied {
					sb.WriteString("\n✅ applied — takes effect at once and survives reboots; running tunnels aren't touched")
				} else {
					fmt.Fprintf(&sb, "\n❌ not applied\n<pre>%s</pre>", esc(lastLines(r.Output, 6)))
				}
				return sb.String(), back
			}
			return sb.String(), b.keyboard([][]ikey{{{Text: "✅ Apply this tuning", Data: "svoa:" + id}}, {{Text: "« " + srv.Name, Data: "sv:" + id}}})
		})
	case "svp":
		j, err := b.app.Prepare(srv)
		if err != nil {
			b.sendMsg(chat, "⚠ "+esc(err.Error()), "")
			return
		}
		b.watchJob(chat, j, "Packages on "+srv.Name)
	}
}

// lastLines keeps the last n lines of s.
func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, "\n")
}

// startRouteBench measures every method between the tunnel's two servers over its family
// (on the spare slot: running tunnels aren't touched) and reports the ranking in msg, the
// confirm message, so its button can't start a second run.
func (b *Bot) startRouteBench(chat string, msg int64, t *Tunnel) {
	var iran, foreign, fam, name string
	b.app.store.View(func(*State) { iran, foreign, fam, name = t.ServerID, t.ForeignID, t.Family, t.Name })
	back := b.keyboard([][]ikey{{{Text: "« " + name, Data: "t:" + t.ID}}})
	j, err := b.app.Bench(BenchRequest{IranID: iran, ForeignID: foreign, Family: fam, Seconds: 3, MaxMB: 8})
	if err != nil {
		b.edit(chat, msg, "⚠ "+esc(err.Error()), back)
		return
	}
	b.edit(chat, msg, "⏳ 📊 Benchmarking the route of <b>"+esc(name)+"</b> ("+famName(fam)+") — a few minutes; live tunnels are not touched…", "")
	go func() {
		deadline := time.Now().Add(90 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(5 * time.Second)
			if j.snapshot().Status == "running" {
				continue
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "<b>📊 Route benchmark · %s</b> (%s)\n", esc(name), famName(fam))
			pos := 0
			for _, r := range b.app.benchResults(iran, foreign, fam) {
				switch {
				case r.OK:
					pos++
					rank := fmt.Sprintf("%d.", pos)
					if r.Recommended {
						rank = "★"
					}
					fmt.Fprintf(&sb, "%s %s — ↓%.0f ↑%.0f Mbps · %.0f ms\n", rank, esc(r.Title), r.DownMbps, r.UpMbps, r.RTTms)
				case r.Skipped:
				default:
					fmt.Fprintf(&sb, "✕ %s — %s\n", esc(r.Title), esc(shortReason(r.Error)))
				}
			}
			b.edit(chat, msg, sb.String(), back)
			return
		}
	}()
}

// shortReason is the gist of a benchmark error for one line.
func shortReason(e string) string {
	switch {
	case strings.Contains(e, "excluded on this route"):
		return "left out on this route"
	case strings.Contains(e, "no bulk data passes"):
		return "pings pass, data stalls (MTU?)"
	case strings.Contains(e, "no traffic passes"):
		return "no traffic passes"
	}
	if len(e) > 70 {
		e = e[:70] + "…"
	}
	return e
}

// dailyReport is the morning summary: tunnels, where their users are, the last day's
// outages, and the panel's address.
func (b *Bot) dailyReport() string {
	var sb strings.Builder
	sb.WriteString("<b>☀️ Daily report</b>\n")
	sb.WriteString(strings.TrimSuffix(b.dashboard(), "\n<i>tap a tunnel</i>"))
	sb.WriteString("\n\n")
	var tunnels []*Tunnel
	var outages []Outage
	b.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			c := t.clone()
			tunnels = append(tunnels, &c)
		}
		outages = append(outages, st.Outages...)
	})
	for _, t := range tunnels {
		line := b.tunnelIcon(t) + " " + esc(t.Name)
		if t.Active == "" {
			line += " — stopped"
		} else if v := b.app.hsViewOf(t.ID); v != nil && v.Active >= 0 && v.Active < len(v.Paths) {
			n := 0
			for _, ok := range v.OK {
				if ok {
					n++
				}
			}
			line += fmt.Sprintf(" — on %s · %d/%d paths", esc(v.Paths[v.Active]), n, len(v.Paths))
		} else {
			line += " — " + esc(methodTitle(t.Active)) + " " + t.Family
		}
		sb.WriteString(line + "\n")
	}
	// outages of the last day by kind, each with its longest; ssh-v4/ssh-v6 (the panel
	// losing SSH to a server) count together
	since := time.Now().Add(-24 * time.Hour).Unix()
	count, longest := map[string]int{}, map[string]int64{}
	for _, o := range outages {
		if o.Start < since {
			continue
		}
		k := o.Kind
		if strings.HasPrefix(k, "ssh") {
			k = "ssh"
		}
		count[k]++
		end := o.End
		if end == 0 {
			end = time.Now().Unix()
		}
		if d := end - o.Start; d > longest[k] {
			longest[k] = d
		}
	}
	if len(count) == 0 {
		sb.WriteString("\n✅ no outage in the last 24 h")
	} else {
		sb.WriteString("\n📉 <b>Last 24 h</b>")
		kinds := []struct{ k, title string }{{"tunnel", "tunnel outages"}, {"server", "server outages"}, {"ssh", "panel lost SSH to a server"}, {"panel", "panel outages"}}
		for _, x := range kinds {
			if count[x.k] > 0 {
				fmt.Fprintf(&sb, "\n• %s: %d, the longest %s", x.title, count[x.k], (time.Duration(longest[x.k]) * time.Second).String())
				delete(count, x.k)
			}
		}
		for k, n := range count {
			fmt.Fprintf(&sb, "\n• %s: %d, the longest %s", esc(k), n, (time.Duration(longest[k]) * time.Second).String())
		}
	}
	if u := panelURL(); u != "" {
		fmt.Fprintf(&sb, "\n🌐 %s", esc(u))
	}
	return sb.String()
}

// reportLoop sends dailyReport once a day at Settings.TelegramReport ("HH:MM", Tehran time).
func (b *Bot) reportLoop() {
	tehran, err := time.LoadLocation("Asia/Tehran")
	if err != nil {
		tehran = time.FixedZone("IRST", 3*3600+1800)
	}
	sent := ""
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-tick.C:
		}
		at := strings.TrimSpace(b.app.settings().TelegramReport)
		if at == "" {
			continue
		}
		now := time.Now().In(tehran)
		if now.Format("15:04") != at || sent == now.Format("2006-01-02") {
			continue
		}
		sent = now.Format("2006-01-02")
		for a := range b.admins {
			b.sendMsg(a, b.dailyReport(), "")
		}
	}
}
