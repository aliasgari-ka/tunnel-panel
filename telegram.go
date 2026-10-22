package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Bot is a long-polling Telegram bot that drives the panel. No inbound webhook is
// needed, so it works on a server with no public HTTP. Only admin chat ids may command it.
type Bot struct {
	app    *App
	token  string
	admins map[string]bool
	client *http.Client
	stop   chan struct{}
	once   sync.Once
	sel    sync.Map // chatID -> selected tunnel id
	await  sync.Map // chatID -> optWait: the option a typed reply sets
	base   string   // API base (tests point it at a fake server)
}

func newBot(app *App, token, admins string) *Bot {
	m := map[string]bool{}
	for _, a := range strings.Split(admins, ",") {
		if a = strings.TrimSpace(a); a != "" {
			m[a] = true
		}
	}
	return &Bot{app: app, token: token, admins: m, base: "https://api.telegram.org",
		client: &http.Client{Timeout: 70 * time.Second}, stop: make(chan struct{})}
}

func (b *Bot) Stop() { b.once.Do(func() { close(b.stop) }) }

func (b *Bot) api(method string, params url.Values) (json.RawMessage, error) {
	u := b.base + "/bot" + b.token + "/" + method
	resp, err := b.client.PostForm(u, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("telegram: %s", out.Description)
	}
	return out.Result, nil
}

func (b *Bot) send(chat, text string) {
	_, _ = b.api("sendMessage", url.Values{"chat_id": {chat}, "text": {text},
		"parse_mode": {"HTML"}, "disable_web_page_preview": {"true"}})
}

// push broadcasts a status line to every admin (used for job notifications).
func (b *Bot) push(text string) {
	for a := range b.admins {
		b.send(a, text)
	}
}

func (b *Bot) Run() {
	me, err := b.api("getMe", nil)
	if err != nil {
		fmt.Printf("telegram bot: %v\n", err)
		return
	}
	var who struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(me, &who)
	fmt.Printf("telegram bot @%s started\n", who.Username)
	// the command list Telegram shows next to the input box
	cmds, _ := json.Marshal([]map[string]string{
		{"command": "menu", "description": "main menu"},
		{"command": "status", "description": "all tunnels, health included"},
		{"command": "traffic", "description": "live traffic"},
		{"command": "servers", "description": "servers and reachability"},
	})
	_, _ = b.api("setMyCommands", url.Values{"commands": {string(cmds)}})
	offset := 0
	for {
		select {
		case <-b.stop:
			return
		default:
		}
		res, err := b.api("getUpdates", url.Values{"offset": {fmt.Sprint(offset)}, "timeout": {"50"},
			"allowed_updates": {`["message","callback_query"]`}})
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		var updates []struct {
			UpdateID int `json:"update_id"`
			Message  *struct {
				Text string `json:"text"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			} `json:"message"`
			Callback *struct {
				ID   string `json:"id"`
				Data string `json:"data"`
				Msg  struct {
					ID   int64 `json:"message_id"`
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
				} `json:"message"`
			} `json:"callback_query"`
		}
		if err := json.Unmarshal(res, &updates); err != nil {
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			// handle each update on its own goroutine: a slow status check must not
			// hold up every other command
			switch {
			case u.Message != nil:
				go b.onText(fmt.Sprint(u.Message.Chat.ID), strings.TrimSpace(u.Message.Text))
			case u.Callback != nil:
				go b.onCallback(fmt.Sprint(u.Callback.Msg.Chat.ID), u.Callback.Msg.ID, u.Callback.ID, u.Callback.Data)
			}
		}
	}
}

func (b *Bot) authed(chat string) bool {
	if len(b.admins) == 0 {
		return false // require an explicit admin id
	}
	return b.admins[chat]
}

// main-menu buttons, pinned under the input box
const (
	btnStatus  = "📋 Status"
	btnTunnels = "🛰 Tunnels"
	btnTraffic = "📈 Traffic"
	btnServers = "🖥 Servers"
)

func (b *Bot) replyKeyboard() string {
	m, _ := json.Marshal(map[string]any{"keyboard": [][]map[string]string{
		{{"text": btnStatus}, {"text": btnTunnels}},
		{{"text": btnTraffic}, {"text": btnServers}},
	}, "resize_keyboard": true, "is_persistent": true})
	return string(m)
}

// sendMsg sends a message and returns its id (for later edits).
func (b *Bot) sendMsg(chat, text, markup string) int64 {
	v := url.Values{"chat_id": {chat}, "text": {clip(text)}, "parse_mode": {"HTML"}, "disable_web_page_preview": {"true"}}
	if markup != "" {
		v.Set("reply_markup", markup)
	}
	res, err := b.api("sendMessage", v)
	if err != nil {
		return 0
	}
	var m struct {
		ID int64 `json:"message_id"`
	}
	_ = json.Unmarshal(res, &m)
	return m.ID
}

// edit replaces a message's text (and inline keyboard), falling back to a new message.
func (b *Bot) edit(chat string, msg int64, text, markup string) {
	if msg == 0 {
		b.sendMsg(chat, text, markup)
		return
	}
	v := url.Values{"chat_id": {chat}, "message_id": {fmt.Sprint(msg)}, "text": {clip(text)}, "parse_mode": {"HTML"}, "disable_web_page_preview": {"true"}}
	if markup != "" {
		v.Set("reply_markup", markup)
	}
	if _, err := b.api("editMessageText", v); err != nil && !strings.Contains(err.Error(), "not modified") {
		b.sendMsg(chat, text, markup)
	}
}

// clip keeps a message under Telegram's 4096-character limit.
func clip(s string) string {
	if len(s) <= 4000 {
		return s
	}
	cut := strings.LastIndex(s[:3900], "\n") // a newline is never inside a UTF-8 rune or a tag here
	if cut < 0 {
		cut = 3900
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
	}
	out := s[:cut]
	if strings.Count(out, "<pre>") > strings.Count(out, "</pre>") {
		out += "</pre>"
	}
	return out + "\n…"
}

// slow runs fn while showing a placeholder, then edits the placeholder with the result.
func (b *Bot) slow(chat, wait string, fn func() (string, string)) {
	id := b.sendMsg(chat, "⏳ "+wait, "")
	text, markup := fn()
	b.edit(chat, id, text, markup)
}

func (b *Bot) onText(chat, text string) {
	if !b.authed(chat) {
		b.send(chat, "Not authorized. Add this chat id in the panel settings:\n<code>"+chat+"</code>")
		return
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	if w, ok := b.await.LoadAndDelete(chat); ok && !strings.HasPrefix(text, "/") && !isMenuButton(text) {
		b.typedOption(chat, w.(optWait), strings.TrimSpace(text))
		return
	}
	switch strings.ToLower(strings.TrimPrefix(fields[0], "/")) {
	case "start", "help", "menu":
		b.sendMsg(chat, b.helpText(), b.replyKeyboard())
		b.sendMsg(chat, b.dashboard(), b.tunnelList())
		return
	}
	switch {
	case text == btnStatus || strings.EqualFold(text, "/status"):
		b.slow(chat, "checking every tunnel…", func() (string, string) { return b.statusText(), "" })
	case text == btnTunnels || strings.EqualFold(text, "/tunnels"):
		b.sendMsg(chat, b.dashboard(), b.tunnelList())
	case text == btnTraffic || strings.EqualFold(text, "/traffic") || strings.EqualFold(text, "/speed"):
		b.slow(chat, "measuring traffic…", func() (string, string) { return b.trafficText(), "" })
	case text == btnServers || strings.EqualFold(text, "/servers"):
		b.sendMsg(chat, b.serversText(), "")
	default:
		b.sendMsg(chat, "Use the buttons below, or /menu.", b.replyKeyboard())
	}
}

func (b *Bot) helpText() string {
	return strings.Join([]string{
		"<b>Tunnel Panel bot</b>",
		"📋 Status — every tunnel with its health",
		"🛰 Tunnels — start, stop, switch method, speed test, diagnose, trace",
		"📈 Traffic — live traffic",
		"🖥 Servers — servers and how they are reached",
		"",
		"🔔 You get a message when a tunnel goes down, when it is failed over and when it comes back.",
	}, "\n")
}

// health checks every running tunnel in parallel.
func (b *Bot) health(ts []*Tunnel) map[string][3]string {
	out := map[string][3]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range ts {
		if t.Active == "" {
			continue
		}
		wg.Add(1)
		go func(t *Tunnel) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			ir, kh, link := b.app.Health(ctx, t)
			mu.Lock()
			out[t.ID] = [3]string{ir, kh, link}
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return out
}

func healthIcon(h [3]string) string {
	switch {
	case h[0] != "active" || h[1] != "active":
		return "🔴"
	case h[2] == "down":
		return "🟠"
	}
	return "🟢"
}

func (b *Bot) statusText() string {
	var ts []*Tunnel
	b.app.store.View(func(st *State) { ts = append(ts, st.Tunnels...) })
	if len(ts) == 0 {
		return "No tunnels yet."
	}
	hs := b.health(ts)
	var sb strings.Builder
	for _, t := range ts {
		m := methodByID[t.Active]
		if m == nil {
			fmt.Fprintf(&sb, "⏹ <b>%s</b> — stopped\n", esc(t.Name))
			continue
		}
		h := hs[t.ID]
		link := map[string]string{"up": "link up", "down": "LINK DOWN", "": "link n/a"}[h[2]]
		fmt.Fprintf(&sb, "%s <b>%s</b> — %s (%s)\n    IR %s · KH %s · %s\n", healthIcon(h), esc(t.Name), esc(m.Title), t.Family, h[0], h[1], link)
		if t.Failover != nil {
			fmt.Fprintf(&sb, "    🔁 failover from %s (%s)\n", esc(methodTitle(t.Failover.Method)), t.Failover.Family)
		}
	}
	return sb.String()
}

func (b *Bot) trafficText() string {
	b.app.Traffic()
	time.Sleep(3 * trafficTick) // two samples are needed for a rate
	snap := b.app.Traffic()
	var ts []*Tunnel
	b.app.store.View(func(st *State) { ts = append(ts, st.Tunnels...) })
	var sb strings.Builder
	for _, t := range ts {
		if t.Active == "" {
			continue
		}
		st := snap.Tunnels[t.ID]
		switch {
		case st == nil:
			fmt.Fprintf(&sb, "<b>%s</b> — no data yet\n", esc(t.Name))
		case st.Error != "":
			fmt.Fprintf(&sb, "<b>%s</b> — %s\n", esc(t.Name), esc(st.Error))
		default:
			fmt.Fprintf(&sb, "<b>%s</b>\n  ↓ %s  ↑ %s\n  total ↓ %s  ↑ %s\n", esc(t.Name),
				fmtRate(st.Down), fmtRate(st.Up), fmtBytes(st.TotalDown), fmtBytes(st.TotalUp))
		}
		if sp := b.app.speedResult(t.ID); sp != nil && sp.OK {
			fmt.Fprintf(&sb, "  last speed test: ↓ %.1f / ↑ %.1f Mbps, %.0f ms\n", sp.DownMbps, sp.UpMbps, sp.RTTms)
		}
	}
	if sb.Len() == 0 {
		return "No running tunnels."
	}
	return sb.String()
}

func (b *Bot) serversText() string {
	var sb strings.Builder
	b.app.store.View(func(st *State) {
		for _, s := range st.Servers {
			online := ""
			if b.app.agents != nil && b.app.agents.online(s.ID) != nil {
				online = " · agent online"
			}
			addr := orStr(s.IPv4, s.IPv6)
			fmt.Fprintf(&sb, "%s <b>%s</b> (%s) <code>%s</code>%s\n    %s\n", flagEmoji(s.Country), esc(s.Name), s.Role, esc(addr), online, esc(orStr(s.LastPath, "not tested")))
		}
	})
	if sb.Len() == 0 {
		return "No servers yet."
	}
	return sb.String()
}

func flagEmoji(cc string) string {
	if len(cc) != 2 {
		return "🖥"
	}
	cc = strings.ToUpper(cc)
	return string(rune(0x1F1E6+int(cc[0])-'A')) + string(rune(0x1F1E6+int(cc[1])-'A'))
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// ---- inline keyboards ----

type ikey struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func (b *Bot) keyboard(rows [][]ikey) string {
	m, _ := json.Marshal(map[string]any{"inline_keyboard": rows})
	return string(m)
}

// tunnelIcon: ⏹ stopped, 🟢 healthy, 🔴 down (per the monitor), 🔁 on a backup path, ⚪ not checked yet.
func (b *Bot) tunnelIcon(t *Tunnel) string {
	if t.Active == "" {
		return "⏹"
	}
	r, ok := b.app.cachedHealth(t.ID)
	switch {
	case ok && r != "":
		return "🔴"
	case t.Failover != nil:
		return "🔁"
	case ok:
		return "🟢"
	}
	return "⚪"
}

func shortMethod(id string) string {
	return map[string]string{"golden": "Golden", "premium": "Premium", "backhaul": "Backhaul", "frp": "FRP",
		"bp_reverse": "BackPack", "bp_l3": "BackPack L3", "direct6": "ip6gre", "ipsec6": "IPsec", "gre": "GRE", "spoof": "Spoof"}[id]
}

func (b *Bot) tunnelList() string {
	var rows [][]ikey
	b.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			label := b.tunnelIcon(t) + " " + t.Name
			if t.Active != "" {
				label += " · " + shortMethod(t.Active) + " " + t.Family
			}
			rows = append(rows, []ikey{{Text: label, Data: "t:" + t.ID}})
		}
	})
	if len(rows) == 0 {
		rows = [][]ikey{{{Text: "no tunnels yet — create one in the panel", Data: "noop"}}}
	}
	rows = append(rows, []ikey{{Text: "📋 Status", Data: "home:st"}, {Text: "📊 Bench history", Data: "home:bh"}, {Text: "🔄", Data: "home"}})
	return b.keyboard(rows)
}

// dashboard is the header shown above the tunnel list.
func (b *Bot) dashboard() string {
	var run, down, fo, all int
	b.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			all++
			if t.Active == "" {
				continue
			}
			run++
			if r, ok := b.app.cachedHealth(t.ID); ok && r != "" {
				down++
			}
			if t.Failover != nil {
				fo++
			}
		}
	})
	s := fmt.Sprintf("<b>🛰 Tunnels</b>  ▶ %d/%d running", run, all)
	if down > 0 {
		s += fmt.Sprintf("  ·  🔴 %d down", down)
	}
	if fo > 0 {
		s += fmt.Sprintf("  ·  🔁 %d on backup", fo)
	}
	return s + "\n<i>tap a tunnel</i>"
}

func (b *Bot) benchHistoryText() string {
	var hs []BenchRecord
	b.app.store.View(func(st *State) { hs = append(hs, st.BenchHistory...) })
	if len(hs) == 0 {
		return "No benchmarks yet — run one in the panel (Benchmark page)."
	}
	var sb strings.Builder
	sb.WriteString("<b>📊 Benchmark history</b>\n")
	for i := len(hs) - 1; i >= 0 && i >= len(hs)-10; i-- {
		h := hs[i]
		best := "no method worked"
		for _, r := range h.Results {
			if r.Recommended {
				best = fmt.Sprintf("★ %s ↓%.0f/↑%.0f Mbps %.0f ms", r.Title, r.DownMbps, r.UpMbps, r.RTTms)
			}
		}
		fmt.Fprintf(&sb, "\n<b>%s → %s</b> (%s) · %s\n  %s\n", esc(h.IranName), esc(h.ForeignName), h.Family,
			time.Unix(h.At, 0).Format("Jan 2 15:04"), esc(best))
	}
	return sb.String()
}

// tunnelPage is one tunnel's card with its actions.
func (b *Bot) tunnelPage(t *Tunnel) (string, string) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>%s</b>\n%s → %s · ports <code>%s</code> · %s\n", b.tunnelIcon(t), esc(t.Name), esc(serverName(b.app, t.ServerID)), esc(foreignName(b.app, t)), esc(t.Ports), t.Family)
	if r, ok := b.app.cachedHealth(t.ID); ok && r != "" && t.Active != "" {
		fmt.Fprintf(&sb, "⚠ %s\n", esc(r))
	}
	if t.Active != "" {
		fmt.Fprintf(&sb, "▶ running <b>%s</b>\n", esc(methodTitle(t.Active)))
	} else {
		sb.WriteString("⏹ stopped\n")
	}
	if t.Failover != nil {
		fmt.Fprintf(&sb, "🔁 failover — original %s (%s) is down\n", esc(methodTitle(t.Failover.Method)), t.Failover.Family)
	}
	if sp := b.app.speedResult(t.ID); sp != nil && sp.OK {
		fmt.Fprintf(&sb, "🚀 last speed test: ↓ %.1f / ↑ %.1f Mbps, %.0f ms\n", sp.DownMbps, sp.UpMbps, sp.RTTms)
	}
	rows := [][]ikey{}
	if t.Active != "" {
		rows = append(rows, []ikey{{Text: "⏹ Stop", Data: "sq:" + t.ID}, {Text: "↻ Re-apply", Data: "a:" + t.ID + ":" + t.Active + ":" + t.Family}})
		rows = append(rows, []ikey{{Text: "🩺 Diagnose", Data: "dg:" + t.ID}, {Text: "🚀 Speed test", Data: "sp:" + t.ID}})
		rows = append(rows, []ikey{{Text: "🔎 Trace 30 s", Data: "tr:" + t.ID}, {Text: "📊 Health", Data: "st:" + t.ID}})
	} else if t.Selected != "" {
		rows = append(rows, []ikey{{Text: "▶ Start " + methodTitle(t.Selected) + " · " + famName(t.Family), Data: "a:" + t.ID + ":" + t.Selected + ":" + t.Family}})
	}
	rows = append(rows, []ikey{{Text: "⇄ Method / IPv4·IPv6", Data: "m:" + t.ID}, {Text: "⚙ Settings", Data: "o:" + t.ID}})
	rows = append(rows, []ikey{{Text: "📜 Last log", Data: "lg:" + t.ID}})
	rows = append(rows, []ikey{{Text: "« Tunnels", Data: "home"}})
	return sb.String(), b.keyboard(rows)
}

// optWait is an option the next typed message sets.
type optWait struct {
	tid, mid, key string
	msg           int64
}

func isMenuButton(s string) bool {
	return s == btnStatus || s == btnTunnels || s == btnTraffic || s == btnServers
}

// optionsPage lists a method's settings with their current values.
func (b *Bot) optionsPage(t *Tunnel, mid string) (string, string) {
	m := methodByID[mid]
	get, _ := resolveOptions(m, t.Options[m.ID])
	var rows [][]ikey
	for i, f := range m.Fields {
		v := get(f.Key)
		switch {
		case f.Type == "password" && v != "":
			v = "••••"
		case f.Type == "bool":
			v = map[bool]string{true: "✅", false: "⬜"}[v == "true"]
		case v == "":
			v = "auto"
		}
		label := f.Label
		if i := strings.Index(label, " ("); i > 0 {
			label = label[:i] // the long hints stay in the field's own page
		}
		if len([]rune(label)) > 30 {
			label = string([]rune(label)[:29]) + "…"
		}
		rows = append(rows, []ikey{{Text: label + ": " + v, Data: fmt.Sprintf("of:%s:%s:%d", t.ID, m.ID, i)}})
	}
	if t.Active == mid {
		rows = append(rows, []ikey{{Text: "↻ Apply changes (re-apply)", Data: "a:" + t.ID + ":" + mid + ":" + t.Family}})
	} else {
		rows = append(rows, []ikey{{Text: "▶ Start " + m.Title, Data: "a:" + t.ID + ":" + mid + ":" + t.Family}})
	}
	rows = append(rows, []ikey{{Text: "« Back", Data: "t:" + t.ID}})
	note := "changes are saved at once and take effect on the next apply"
	return fmt.Sprintf("⚙ <b>%s</b> — %s settings\n<i>%s</i>", esc(t.Name), esc(m.Title), note), b.keyboard(rows)
}

// saveOption validates and stores one option ("" = back to the default).
func (b *Bot) saveOption(t *Tunnel, m *Method, key, val string) error {
	if err := validateOptions(map[string]map[string]string{m.ID: {key: val}}); err != nil {
		return err
	}
	return b.app.store.Update(func(st *State) error {
		cand := *t
		cand.setOption(m.ID, key, val)
		if err := portClash(st, &cand, m.ID); err != nil {
			return err
		}
		t.setOption(m.ID, key, val)
		return nil
	})
}

func (b *Bot) setOptionMsg(chat string, msg int64, t *Tunnel, m *Method, f Field, val string) {
	if err := b.saveOption(t, m, f.Key, val); err != nil {
		b.sendMsg(chat, "⚠ "+esc(err.Error()), "")
		return
	}
	text, kb := b.optionsPage(t, m.ID)
	b.edit(chat, msg, text, kb)
}

func (b *Bot) typedOption(chat string, w optWait, val string) {
	t, m := b.app.store.Tunnel(w.tid), methodByID[w.mid]
	if t == nil || m == nil {
		return
	}
	if val == "-" {
		val = ""
	}
	if err := b.saveOption(t, m, w.key, val); err != nil {
		b.sendMsg(chat, "⚠ "+esc(err.Error()), "")
		return
	}
	text, kb := b.optionsPage(t, m.ID)
	b.sendMsg(chat, "✅ saved\n\n"+text, kb)
}

func famName(f string) string {
	return map[string]string{"v4": "IPv4", "v6": "IPv6"}[f]
}

// methodPicker lists the methods that work over fam, L3 tunnels and port forwarders apart,
// with a row on top to switch between the route's families.
func (b *Bot) methodPicker(t *Tunnel, fam string, fams []string) (string, string) {
	best := ""
	for _, r := range b.app.benchResults(t.ServerID, t.ForeignID, fam) {
		if r.Recommended {
			best = r.Method
		}
	}
	var rows [][]ikey
	if len(fams) > 1 {
		var fr []ikey
		for _, f := range fams {
			label := famName(f)
			if f == fam {
				label = "● " + label
			} else {
				label = "○ " + label
			}
			fr = append(fr, ikey{Text: label, Data: "m:" + t.ID + ":" + f})
		}
		rows = append(rows, fr)
	}
	group := func(l3 bool) [][]ikey {
		var rows [][]ikey
		var cur []ikey
		for _, m := range methods {
			if !supportsFamily(m, fam) || m.ID == "spoof" || benchIsL3(m, t.Options[m.ID]) != l3 {
				continue
			}
			label := m.Title
			switch {
			case m.ID == t.Active && fam == t.Family:
				label = "✓ " + label
			case m.ID == best:
				label = "★ " + label
			}
			cur = append(cur, ikey{Text: label, Data: "a:" + t.ID + ":" + m.ID + ":" + fam})
			if len(cur) == 2 {
				rows = append(rows, cur)
				cur = nil
			}
		}
		if len(cur) > 0 {
			rows = append(rows, cur)
		}
		return rows
	}
	if l3 := group(true); len(l3) > 0 {
		rows = append(rows, []ikey{{Text: "── L3 tunnels ──", Data: "noop"}})
		rows = append(rows, l3...)
	}
	if fw := group(false); len(fw) > 0 {
		rows = append(rows, []ikey{{Text: "── port forwarders ──", Data: "noop"}})
		rows = append(rows, fw...)
	}
	rows = append(rows, []ikey{{Text: "« Back", Data: "t:" + t.ID}})
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b> — choose a method over <b>%s</b>", esc(t.Name), famName(fam))
	if t.Active != "" {
		fmt.Fprintf(&sb, "\nnow running: %s over %s", esc(methodTitle(t.Active)), famName(t.Family))
	}
	switch {
	case len(fams) == 0:
		sb.WriteString("\n⚠ a server has no public IP saved — open Servers in the panel and run Test connection")
	case len(fams) == 1:
		other := map[string]string{"v4": "IPv6", "v6": "IPv4"}[fams[0]]
		fmt.Fprintf(&sb, "\n%s isn't offered: one of the two servers has no public %s address (it is detected on Test connection)", other, other)
	}
	if best != "" {
		sb.WriteString("\n★ = best in this route's last benchmark")
	}
	return sb.String(), b.keyboard(rows)
}

// watchJob reports a job's outcome to the chat when it ends (the important lines only).
func (b *Bot) watchJob(chat string, j *Job, title string) {
	msg := b.sendMsg(chat, "⏳ "+title+"…", "")
	go func() {
		deadline := time.Now().Add(30 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(3 * time.Second)
			s := j.snapshot()
			if s.Status == "running" {
				continue
			}
			var keep []string
			for _, l := range s.Lines {
				if strings.Contains(l, "✓") || strings.Contains(l, "✕") || strings.Contains(l, "→") || strings.Contains(l, "ERROR") ||
					strings.Contains(l, "DONE") || strings.Contains(l, "WARNING") || strings.Contains(l, "clients →") || strings.Contains(l, "Mbps") {
					keep = append(keep, esc(l))
				}
			}
			if len(keep) > 30 {
				keep = keep[len(keep)-30:]
			}
			icon := map[string]string{"ok": "✅", "error": "❌", "cancelled": "⏹"}[s.Status]
			b.edit(chat, msg, fmt.Sprintf("%s <b>%s</b>\n%s", icon, esc(title), strings.Join(keep, "\n")), "")
			return
		}
	}()
}

func (b *Bot) onCallback(chat string, msg int64, cbID, data string) {
	_, _ = b.api("answerCallbackQuery", url.Values{"callback_query_id": {cbID}})
	if !b.authed(chat) || data == "noop" {
		return
	}
	switch data {
	case "home":
		b.edit(chat, msg, b.dashboard(), b.tunnelList())
		return
	case "home:st":
		b.slow(chat, "checking every tunnel…", func() (string, string) { return b.statusText(), "" })
		return
	case "home:bh":
		b.sendMsg(chat, b.benchHistoryText(), "")
		return
	}
	parts := strings.SplitN(data, ":", 4)
	if len(parts) < 2 {
		return
	}
	t := b.app.store.Tunnel(parts[1])
	if t == nil {
		b.edit(chat, msg, "That tunnel no longer exists.\n\n"+b.dashboard(), b.tunnelList())
		return
	}
	job := func(j *Job, err error, title string) {
		if err != nil {
			b.sendMsg(chat, "⚠ "+esc(err.Error()), "")
			return
		}
		b.watchJob(chat, j, title)
	}
	switch parts[0] {
	case "t":
		text, kb := b.tunnelPage(t)
		b.edit(chat, msg, text, kb)
	case "m": // method picker: pick the address family on top, then a method (★ = benchmark winner)
		fams := b.app.routeFamilies(t)
		fam := t.Family
		if len(parts) > 2 && contains(fams, parts[2]) {
			fam = parts[2]
		} else if !contains(fams, fam) && len(fams) > 0 {
			fam = fams[0]
		}
		text, kb := b.methodPicker(t, fam, fams)
		b.edit(chat, msg, text, kb)
	case "a":
		if len(parts) < 3 {
			return
		}
		fam := ""
		if len(parts) > 3 {
			fam = parts[3]
		}
		if fam == "" {
			fam = t.Family
		}
		j, err := b.app.ApplyRoute(t, parts[2], fam)
		job(j, err, "Applying "+methodTitle(parts[2])+" over "+famName(fam)+" to "+t.Name)
	case "o": // the method's settings
		mid := t.Active
		if mid == "" {
			mid = t.Selected
		}
		if methodByID[mid] == nil {
			b.sendMsg(chat, "Pick a method first (⇄ Method).", "")
			return
		}
		text, kb := b.optionsPage(t, mid)
		b.edit(chat, msg, text, kb)
	case "of", "ov": // one option: choices / toggle / ask for a typed value
		f := strings.Split(data, ":")
		if len(f) < 4 {
			return
		}
		m := methodByID[f[2]]
		fi, _ := strconv.Atoi(f[3])
		if m == nil || fi < 0 || fi >= len(m.Fields) {
			return
		}
		fd := m.Fields[fi]
		get, _ := resolveOptions(m, t.Options[m.ID])
		switch {
		case parts[0] == "ov" && len(f) == 5:
			oi, _ := strconv.Atoi(f[4])
			if oi >= 0 && oi < len(fd.Options) {
				b.setOptionMsg(chat, msg, t, m, fd, fd.Options[oi])
			}
		case fd.Type == "bool":
			b.setOptionMsg(chat, msg, t, m, fd, strconv.FormatBool(get(fd.Key) != "true"))
		case fd.Type == "select":
			var rows [][]ikey
			for i, o := range fd.Options {
				label := o
				if o == get(fd.Key) {
					label = "● " + o
				}
				rows = append(rows, []ikey{{Text: label, Data: fmt.Sprintf("ov:%s:%s:%d:%d", t.ID, m.ID, fi, i)}})
			}
			rows = append(rows, []ikey{{Text: "« Settings", Data: "o:" + t.ID}})
			b.edit(chat, msg, fmt.Sprintf("<b>%s</b> · %s\n%s", esc(m.Title), esc(fd.Label), esc(fd.Help)), b.keyboard(rows))
		default:
			b.await.Store(chat, optWait{t.ID, m.ID, fd.Key, msg})
			cur := get(fd.Key)
			if fd.Type == "password" && cur != "" {
				cur = "••••"
			}
			b.sendMsg(chat, fmt.Sprintf("Send the new value for <b>%s</b> (%s)\nnow: <code>%s</code>\nsend <code>-</code> for the default (%s)", esc(fd.Label), esc(m.Title), esc(orStr(cur, "default")), esc(orStr(fd.Default, "auto"))), "")
		}
	case "sq": // confirm before stopping
		b.edit(chat, msg, "Stop <b>"+esc(t.Name)+"</b>? Users on its ports lose the connection.",
			b.keyboard([][]ikey{{{Text: "⏹ Yes, stop it", Data: "s:" + t.ID}, {Text: "Cancel", Data: "t:" + t.ID}}}))
	case "s":
		if id := b.app.jobs.running(t.ID); id != "" {
			_, _ = b.app.jobs.cancel(id)
		}
		if id := b.app.jobs.running(failoverJobKey + t.ID); id != "" {
			_, _ = b.app.jobs.cancel(id)
		}
		b.app.clearFailover(t)
		j, err := b.app.Stop(t)
		job(j, err, "Stopping "+t.Name)
	case "dg":
		j, err := b.app.Diagnose(t)
		job(j, err, "Diagnose "+t.Name)
	case "sp":
		j, err := b.app.SpeedTest(t, 5)
		job(j, err, "Speed test "+t.Name)
	case "tr":
		j, err := b.app.Trace(t, 30)
		if err == nil {
			b.sendMsg(chat, "🔎 Tracing <b>"+esc(t.Name)+"</b> for 30 s — connect your client now.", "")
		}
		job(j, err, "Trace "+t.Name)
	case "st":
		b.slow(chat, "checking "+t.Name+"…", func() (string, string) {
			h := b.health([]*Tunnel{t})[t.ID]
			return fmt.Sprintf("%s <b>%s</b>: IR %s · KH %s · link %s", healthIcon(h), esc(t.Name), h[0], h[1], orStr(h[2], "n/a")), ""
		})
	case "lg":
		j := b.app.jobs.latestFor(t.ID)
		if j == nil {
			b.sendMsg(chat, "No job has run on this tunnel yet.", "")
			return
		}
		s := j.snapshot()
		lines := s.Lines
		if len(lines) > 25 {
			lines = lines[len(lines)-25:]
		}
		for i := range lines {
			lines[i] = esc(lines[i])
		}
		b.sendMsg(chat, fmt.Sprintf("📜 <b>%s</b> — last job (%s, %s)\n<pre>%s</pre>", esc(t.Name), s.Kind, s.Status, strings.Join(lines, "\n")), "")
	}
}

func methodTitle(id string) string {
	if m := methodByID[id]; m != nil {
		return m.Title
	}
	return id
}

// sortedMethodIDs is used by tests/help to list methods deterministically.
func sortedMethodIDs() []string {
	var ids []string
	for _, m := range methods {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return ids
}
