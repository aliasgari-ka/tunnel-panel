package main

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Accounts in Telegram. The admin's bot shows everything, or — after 👤 Accounts — one
// account's services exactly as that user sees them. A user can give the panel their own bot
// token (Account page): that bot shows only their tunnels and servers and gets the alerts
// about those only. The admin's bot still gets every alert.

// scope is the account whose services this chat sees ("" = everything).
func (b *Bot) scope(chat string) string {
	if b.owner != "" {
		return b.owner
	}
	if v, ok := b.asUser.Load(chat); ok {
		return v.(string)
	}
	return ""
}

func tunnelInScope(sc string, t *Tunnel) bool { return sc == "" || t.Owner == sc }

// tunnelsIn returns the tunnels in scope.
func (b *Bot) tunnelsIn(sc string) []*Tunnel {
	var ts []*Tunnel
	b.app.store.View(func(st *State) {
		for _, t := range st.Tunnels {
			if tunnelInScope(sc, t) {
				ts = append(ts, t)
			}
		}
	})
	return ts
}

// outageInScope: tunnel outages of the account's tunnels, server outages of its servers
// (its own and the ones carrying its tunnels); the panel host's are the admin's.
func outageInScope(st *State, sc string, o Outage) bool {
	if sc == "" {
		return true
	}
	switch o.Kind {
	case "tunnel":
		for _, t := range st.Tunnels {
			if t.ID == o.Target {
				return t.Owner == sc
			}
		}
		return false
	case "panel":
		return false
	}
	id, _, _ := strings.Cut(o.Target, "/") // ssh-v4/ssh-v6 targets are "<server id>/v4"
	return ownerOfLocked(st, id) == sc || sharedServersLocked(st, sc)[id]
}

// accountPicker lists the user accounts for the admin's 👤 Accounts.
func (b *Bot) accountPicker(chat string) (string, string) {
	var names []string
	count := map[string]int{}
	b.app.store.View(func(st *State) {
		for _, u := range st.Users {
			if !isAdminRole(u.Role) {
				names = append(names, u.Username)
			}
		}
		for _, t := range st.Tunnels {
			count[t.Owner]++
		}
	})
	sort.Strings(names)
	cur := b.scope(chat)
	var rows [][]ikey
	for _, n := range names {
		label := fmt.Sprintf("👤 %s · %d tunnel(s)", n, count[n])
		if n == cur {
			label = "✓ " + label
		}
		rows = append(rows, []ikey{{Text: label, Data: "acc:" + n}})
	}
	all := "🌐 Everyone (admin view)"
	if cur == "" {
		all = "✓ " + all
	}
	rows = append(rows, []ikey{{Text: all, Data: "acc:"}}, []ikey{{Text: "« Tunnels", Data: "home"}})
	text := "<b>👤 Accounts</b>\npick an account to see its services as that user sees them — the menus, lists and the report then show only those; you keep the admin's actions"
	if len(names) == 0 {
		text = "<b>👤 Accounts</b>\nno user accounts yet — add one in the panel (Users page)"
	}
	return text, b.keyboard(rows)
}

// viewAs switches the admin's chat to one account's services ("" = everyone's).
func (b *Bot) viewAs(chat string, msg int64, name string) {
	if name == "" {
		b.asUser.Delete(chat)
	} else {
		ok := false
		b.app.store.View(func(st *State) { ok = accountExists(st, name) })
		if !ok {
			text, kb := b.accountPicker(chat)
			b.edit(chat, msg, "That account no longer exists.\n\n"+text, kb)
			return
		}
		b.asUser.Store(chat, name)
	}
	sc := b.scope(chat)
	b.edit(chat, msg, b.dashboard(sc), b.tunnelList(sc))
}

// ---- users' own bots ----

var botTokenRe = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)

// startUserBots (re)starts one bot per user account that set a token. a.botMu is held.
func (a *App) startUserBotsLocked(adminTok string) {
	for _, b := range a.userBots {
		b.Stop()
	}
	a.userBots = map[string]*Bot{}
	var users []User
	a.store.View(func(st *State) { users = append(users, st.Users...) })
	for _, u := range users {
		if isAdminRole(u.Role) || u.TelegramTok == "" || u.TelegramTok == adminTok {
			continue
		}
		b := newBot(a, u.TelegramTok, u.TelegramChats)
		b.owner = u.Username
		a.userBots[u.Username] = b
		go b.Run()
	}
}

// pushTo sends an alert to the admin's bot and, when the object belongs to an account with
// its own bot, to that bot too.
func (a *App) pushTo(owner, msg string) {
	a.push(msg)
	if owner == "" {
		return
	}
	a.botMu.Lock()
	b := a.userBots[owner]
	a.botMu.Unlock()
	if b != nil {
		go b.push(msg)
	}
}

// pushT is pushTo for an alert about tunnel t.
func (a *App) pushT(t *Tunnel, msg string) {
	var owner string
	a.store.View(func(*State) { owner = t.Owner })
	a.pushTo(owner, msg)
}

// pushServer is pushTo for an alert about a server: its owner, and every account whose
// tunnel runs on it.
func (a *App) pushServer(id, msg string) {
	owners := map[string]bool{}
	a.store.View(func(st *State) {
		if o := ownerOfLocked(st, id); o != "" {
			owners[o] = true
		}
		for _, t := range st.Tunnels {
			if t.Owner != "" && (t.ServerID == id || t.ForeignID == id) {
				owners[t.Owner] = true
			}
		}
	})
	a.push(msg)
	a.botMu.Lock()
	var bots []*Bot
	for o := range owners {
		if b := a.userBots[o]; b != nil {
			bots = append(bots, b)
		}
	}
	a.botMu.Unlock()
	for _, b := range bots {
		go b.push(msg)
	}
}

var chatIDsRe = regexp.MustCompile(`^-?[0-9]{1,20}(,-?[0-9]{1,20})*$`)

// myBot: a user reads (GET) or sets (POST {Token, Chats, Remove}) their own Telegram bot.
// The token is never sent back; an empty Token keeps the saved one.
func (s *Server2) myBot(w http.ResponseWriter, r *http.Request) {
	user, admin := s.who(r)
	if admin {
		httpErr(w, 400, "the admin's bot is set in Settings → Telegram bot")
		return
	}
	if r.Method == http.MethodPost {
		var in struct {
			Token, Chats string
			Remove       bool
		}
		if err := readJSON(r, &in); err != nil {
			httpErr(w, 400, "bad request")
			return
		}
		in.Token = strings.TrimSpace(in.Token)
		in.Chats = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(in.Chats), " ", ""), "，", ",")
		if in.Token != "" && !botTokenRe.MatchString(in.Token) {
			httpErr(w, 400, "That isn't a bot token — @BotFather gives one like 123456789:AAH…")
			return
		}
		if in.Chats != "" && !chatIDsRe.MatchString(in.Chats) {
			httpErr(w, 400, "Chat ids are numbers, comma-separated (your bot tells you yours when you message it /start).")
			return
		}
		err := s.app.store.Update(func(st *State) error {
			if in.Token != "" {
				// one bot, one poller: Telegram hands each update to only one of them
				if in.Token == st.Settings.TelegramTok {
					return fmt.Errorf("that is the panel admin's bot — create your own with @BotFather")
				}
				for _, u := range st.Users {
					if u.Username != user && u.TelegramTok == in.Token {
						return fmt.Errorf("another account already uses that bot")
					}
				}
			}
			for i := range st.Users {
				if st.Users[i].Username != user {
					continue
				}
				switch {
				case in.Remove:
					st.Users[i].TelegramTok, st.Users[i].TelegramChats = "", ""
				default:
					if in.Token != "" {
						st.Users[i].TelegramTok = in.Token
					}
					st.Users[i].TelegramChats = in.Chats
				}
				return nil
			}
			return fmt.Errorf("account not found")
		})
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		go s.app.restartBot()
	}
	var tok, chats string
	s.app.store.View(func(st *State) {
		for _, u := range st.Users {
			if u.Username == user {
				tok, chats = u.TelegramTok, u.TelegramChats
			}
		}
	})
	state := "" // "" = starting; "@name" = running; "error: …"
	s.app.botMu.Lock()
	if b := s.app.userBots[user]; b != nil && r.Method == http.MethodGet {
		state, _ = b.state.Load().(string)
	}
	s.app.botMu.Unlock()
	writeJSON(w, map[string]any{"set": tok != "", "chats": chats, "state": state})
}
