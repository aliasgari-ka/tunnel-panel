package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
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
}

func newBot(app *App, token, admins string) *Bot {
	m := map[string]bool{}
	for _, a := range strings.Split(admins, ",") {
		if a = strings.TrimSpace(a); a != "" {
			m[a] = true
		}
	}
	return &Bot{app: app, token: token, admins: m,
		client: &http.Client{Timeout: 70 * time.Second}, stop: make(chan struct{})}
}

func (b *Bot) Stop() { b.once.Do(func() { close(b.stop) }) }

func (b *Bot) api(method string, params url.Values) (json.RawMessage, error) {
	u := "https://api.telegram.org/bot" + b.token + "/" + method
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
	var who struct{ Username string `json:"username"` }
	_ = json.Unmarshal(me, &who)
	fmt.Printf("telegram bot @%s started\n", who.Username)
	offset := 0
	for {
		select {
		case <-b.stop:
			return
		default:
		}
		res, err := b.api("getUpdates", url.Values{"offset": {fmt.Sprint(offset)}, "timeout": {"50"}})
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		var updates []struct {
			UpdateID int `json:"update_id"`
			Message  *struct {
				Text string `json:"text"`
				Chat struct{ ID int64 `json:"id"` } `json:"chat"`
			} `json:"message"`
			Callback *struct {
				ID   string `json:"id"`
				Data string `json:"data"`
				Msg  struct{ Chat struct{ ID int64 `json:"id"` } `json:"chat"` } `json:"message"`
			} `json:"callback_query"`
		}
		if err := json.Unmarshal(res, &updates); err != nil {
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			switch {
			case u.Message != nil:
				b.onText(fmt.Sprint(u.Message.Chat.ID), strings.TrimSpace(u.Message.Text))
			case u.Callback != nil:
				b.onCallback(fmt.Sprint(u.Callback.Msg.Chat.ID), u.Callback.ID, u.Callback.Data)
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

func (b *Bot) onText(chat, text string) {
	if !b.authed(chat) {
		b.send(chat, "Not authorized. Add this chat id in the panel settings:\n<code>"+chat+"</code>")
		return
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	switch strings.ToLower(strings.TrimPrefix(fields[0], "/")) {
	case "start", "help", "menu":
		b.send(chat, b.helpText())
	case "status", "list", "ls":
		b.send(chat, b.statusText())
	case "servers":
		b.send(chat, b.serversText())
	default:
		b.send(chat, "Unknown command. Send /menu.")
	}
	// also show the interactive tunnel keyboard
	if low := strings.ToLower(text); low == "/start" || low == "/menu" {
		b.sendTunnelKeyboard(chat)
	}
}

func (b *Bot) helpText() string {
	return strings.Join([]string{
		"<b>Tunnel Panel bot</b>",
		"/status — all tunnels and their state",
		"/servers — servers and reachability",
		"/menu — buttons to start, stop and switch methods",
		"",
		"Tap a tunnel to pick its connection method (Backhaul tcp, ipx, tun, …) and apply it.",
	}, "\n")
}

func (b *Bot) statusText() string {
	var sb strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var ts []*Tunnel
	b.app.store.View(func(st *State) { ts = append(ts, st.Tunnels...) })
	if len(ts) == 0 {
		return "No tunnels yet."
	}
	for _, t := range ts {
		m := methodByID[t.Active]
		state := "⏹ stopped"
		if m != nil {
			ir, kh := b.app.Status(ctx, t)
			state = fmt.Sprintf("▶ %s (IR %s / KH %s)", m.Title, ir, kh)
		}
		fmt.Fprintf(&sb, "<b>%s</b> — %s\n", esc(t.Name), state)
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
			fmt.Fprintf(&sb, "<b>%s</b> (%s)%s\n", esc(s.Name), s.Role, online)
		}
	})
	if sb.Len() == 0 {
		return "No servers yet."
	}
	return sb.String()
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

func (b *Bot) sendTunnelKeyboard(chat string) {
	var rows [][]ikey
	b.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			label := "⏹ " + t.Name
			if t.Active != "" {
				label = "▶ " + t.Name
			}
			rows = append(rows, []ikey{{Text: label, Data: "t:" + t.ID}})
		}
	})
	if len(rows) == 0 {
		b.send(chat, "No tunnels yet — create one in the web panel.")
		return
	}
	_, _ = b.api("sendMessage", url.Values{"chat_id": {chat}, "text": {"Pick a tunnel:"},
		"reply_markup": {b.keyboard(rows)}})
}

func (b *Bot) onCallback(chat, cbID, data string) {
	_, _ = b.api("answerCallbackQuery", url.Values{"callback_query_id": {cbID}})
	if !b.authed(chat) {
		return
	}
	parts := strings.SplitN(data, ":", 3)
	switch parts[0] {
	case "t": // tunnel chosen → show method buttons
		t := b.app.store.Tunnel(parts[1])
		if t == nil {
			return
		}
		var rows [][]ikey
		var cur []ikey
		for _, m := range methods {
			if !supportsFamily(m, t.Family) {
				continue
			}
			mark := ""
			if m.ID == t.Active {
				mark = "✓ "
			}
			cur = append(cur, ikey{Text: mark + m.Title, Data: "a:" + t.ID + ":" + m.ID})
			if len(cur) == 2 {
				rows = append(rows, cur)
				cur = nil
			}
		}
		if len(cur) > 0 {
			rows = append(rows, cur)
		}
		rows = append(rows, []ikey{{Text: "⏹ Stop", Data: "s:" + t.ID}, {Text: "📊 Status", Data: "st:" + t.ID}})
		_, _ = b.api("sendMessage", url.Values{"chat_id": {chat},
			"text": {"<b>" + esc(t.Name) + "</b> — choose a method:"}, "parse_mode": {"HTML"},
			"reply_markup": {b.keyboard(rows)}})
	case "a": // apply method
		t := b.app.store.Tunnel(parts[1])
		if t == nil {
			return
		}
		if _, err := b.app.Apply(t, parts[2]); err != nil {
			b.send(chat, "⚠ "+err.Error())
			return
		}
		b.send(chat, fmt.Sprintf("Applying <b>%s</b> to <b>%s</b>…", esc(methodTitle(parts[2])), esc(t.Name)))
	case "s":
		t := b.app.store.Tunnel(parts[1])
		if t == nil {
			return
		}
		if _, err := b.app.Stop(t); err != nil {
			b.send(chat, "⚠ "+err.Error())
			return
		}
		b.send(chat, "Stopping <b>"+esc(t.Name)+"</b>…")
	case "st":
		t := b.app.store.Tunnel(parts[1])
		if t == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		ir, kh := b.app.Status(ctx, t)
		b.send(chat, fmt.Sprintf("<b>%s</b>: IR %s / KH %s", esc(t.Name), ir, kh))
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
