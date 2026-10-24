package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Accounts: the admin (role "" or "admin" — every account from before roles) sees and runs
// everything; a user (role "user") sees and runs only the servers and tunnels they own
// (Owner = their username). Objects with no owner are the admin's. The panel host itself,
// settings, helpers, backups, repair and the account list are the admin's only.

const roleUser = "user"

func isAdminRole(role string) bool { return role != roleUser }

// who returns the signed-in account and whether it is the admin.
func (s *Server2) who(r *http.Request) (string, bool) {
	name := s.currentUser(r)
	admin := false
	s.app.store.View(func(st *State) {
		for _, u := range st.Users {
			if u.Username == name {
				admin = isAdminRole(u.Role)
			}
		}
	})
	return name, admin
}

// visible: may this account see an object with this owner?
func visible(user string, admin bool, owner string) bool {
	return admin || (owner != "" && owner == user)
}

func (s *Server2) serverVisible(user string, admin bool, id string) bool {
	if admin {
		return true
	}
	srv := s.app.store.Server(id)
	return srv != nil && visible(user, admin, srv.Owner)
}

func (s *Server2) tunnelVisible(user string, admin bool, id string) bool {
	if admin {
		return true
	}
	t := s.app.store.Tunnel(id)
	if t == nil {
		return false
	}
	var owner string
	s.app.store.View(func(*State) { owner = t.Owner })
	return visible(user, admin, owner)
}

// pairVisible: both servers of a route are this account's, or one of its tunnels runs
// between them (a tunnel the admin set up for the user on the admin's servers). A user's
// routes never end on the panel host, which is the admin's.
func (s *Server2) pairVisible(user string, admin bool, iran, foreign string) bool {
	if admin {
		return true
	}
	ok := false
	s.app.store.View(func(st *State) { ok = pairVisibleLocked(st, user, admin, iran, foreign) })
	return ok
}

func pairVisibleLocked(st *State, user string, admin bool, iran, foreign string) bool {
	if admin {
		return true
	}
	if user == "" || iran == "" || foreign == "" {
		return false
	}
	if visible(user, admin, ownerOfLocked(st, iran)) && visible(user, admin, ownerOfLocked(st, foreign)) {
		return true
	}
	for _, t := range st.Tunnels {
		if t.Owner == user && t.ServerID == iran && t.ForeignID == foreign {
			return true
		}
	}
	return false
}

// sharedServersLocked: servers that aren't the user's but carry one of the user's tunnels.
// The user sees them read-only (name, place, addresses — never how the panel logs in) so
// their tunnels show where they run and which address to connect to.
func sharedServersLocked(st *State, user string) map[string]bool {
	out := map[string]bool{}
	for _, t := range st.Tunnels {
		if user == "" || t.Owner != user {
			continue
		}
		for _, id := range []string{t.ServerID, t.ForeignID} {
			if id != "" && ownerOfLocked(st, id) != user {
				out[id] = true
			}
		}
	}
	return out
}

// sharedView is what a user may see of a server that isn't theirs.
func sharedView(x *Server) *Server {
	return &Server{ID: x.ID, Owner: x.Owner, Name: x.Name, IPv4: x.IPv4, IPv6: x.IPv6, Arch: x.Arch, OS: x.OS,
		Prepared: x.Prepared, CreatedAt: x.CreatedAt, Role: x.Role, Country: x.Country, City: x.City}
}

// guard checks the object a request names before the handler runs. kind:
//
//	"admin"  — admin only
//	"server" — body ID / ?id is a server of this account
//	"tunnel" — body ID / ?id is a tunnel of this account
//	"job"    — the job (?id / body ID) runs on a tunnel of this account, or this account started it
//	"pair"   — iranId/foreignId (or Iran/Foreign, ?iran/?foreign) are this account's servers
//	"self"   — the handler filters by itself
func (s *Server2) guard(kind string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, admin := s.who(r)
		if admin || kind == "self" {
			h(w, r)
			return
		}
		if kind == "admin" {
			httpErr(w, 403, "only the panel admin can do this")
			return
		}
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		var f struct {
			ID, IranID, ForeignID, Iran, Foreign string
		}
		if len(body) > 0 {
			_ = json.Unmarshal(body, &f)
		}
		q := r.URL.Query()
		id := f.ID
		if id == "" {
			id = q.Get("id")
		}
		ok := false
		switch kind {
		case "server":
			ok = s.serverVisible(user, admin, id)
		case "tunnel":
			ok = s.tunnelVisible(user, admin, id)
		case "job":
			if j := s.app.jobs.get(id); j != nil {
				ok = (j.Tunnel != "" && s.tunnelVisible(user, admin, j.Tunnel)) || (j.Owner != "" && j.Owner == user)
			}
		case "pair":
			iran, foreign := orStr(f.IranID, f.Iran), orStr(f.ForeignID, f.Foreign)
			if iran == "" && foreign == "" {
				iran, foreign = q.Get("iran"), q.Get("foreign")
			}
			ok = s.pairVisible(user, admin, iran, foreign)
		}
		if !ok {
			httpErr(w, 404, "not found")
			return
		}
		h(w, r)
	}
}

// ---- accounts (admin) ----

type userView struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Servers  int    `json:"servers"`
	Tunnels  int    `json:"tunnels"`
}

// users lists the accounts (GET) or creates / updates one (POST {Username, Password, Role}):
// a new account needs a password; for an existing one an empty password keeps it, and a
// password change ends its sessions.
func (s *Server2) users(w http.ResponseWriter, r *http.Request) {
	me, _ := s.who(r)
	if r.Method == http.MethodPost {
		var in struct{ Username, Password, Role string }
		if err := readJSON(r, &in); err != nil {
			httpErr(w, 400, "bad request")
			return
		}
		in.Username = strings.TrimSpace(in.Username)
		if !usernameRe.MatchString(in.Username) {
			httpErr(w, 400, "A username is 1–32 characters: letters, digits and . _ @ -")
			return
		}
		if in.Role != roleUser {
			in.Role = "admin"
		}
		if in.Password != "" && len(in.Password) < 8 {
			httpErr(w, 400, "The password must be at least 8 characters.")
			return
		}
		var hash string
		if in.Password != "" {
			h, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
			hash = string(h)
		}
		err := s.app.store.Update(func(st *State) error {
			for i := range st.Users {
				if st.Users[i].Username != in.Username {
					continue
				}
				if in.Username == me && in.Role == roleUser {
					return fmt.Errorf("you can't take the admin role from your own account")
				}
				st.Users[i].Role = in.Role
				if hash != "" {
					st.Users[i].Hash = hash
					st.Users[i].Gen++
				}
				return nil
			}
			if hash == "" {
				return fmt.Errorf("a new account needs a password")
			}
			st.Users = append(st.Users, User{Username: in.Username, Hash: hash, Role: in.Role})
			return nil
		})
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		go s.app.restartBot() // a role change starts or stops that account's own bot
	}
	out := []userView{}
	s.app.store.View(func(st *State) {
		for _, u := range st.Users {
			v := userView{Username: u.Username, Role: "admin"}
			if !isAdminRole(u.Role) {
				v.Role = roleUser
			}
			// what has no account is the admins' (shared by every admin account)
			mine := func(owner string) bool { return owner == u.Username || (owner == "" && v.Role == "admin") }
			for _, x := range st.Servers {
				if mine(x.Owner) {
					v.Servers++
				}
			}
			for _, t := range st.Tunnels {
				if mine(t.Owner) {
					v.Tunnels++
				}
			}
			out = append(out, v)
		}
	})
	writeJSON(w, out)
}

// userDelete removes an account that owns nothing (move or delete its servers first).
func (s *Server2) userDelete(w http.ResponseWriter, r *http.Request) {
	me, _ := s.who(r)
	var in struct{ Username string }
	_ = readJSON(r, &in)
	if in.Username == me {
		httpErr(w, 400, "you can't delete your own account")
		return
	}
	err := s.app.store.Update(func(st *State) error {
		for _, x := range st.Servers {
			if x.Owner == in.Username {
				return fmt.Errorf("%s still owns server %q — delete it or give it to another account first", in.Username, x.Name)
			}
		}
		for _, t := range st.Tunnels {
			if t.Owner == in.Username {
				return fmt.Errorf("%s still owns tunnel %q — delete it or give it to another account first", in.Username, t.Name)
			}
		}
		keep := st.Users[:0]
		found := false
		for _, u := range st.Users {
			if u.Username == in.Username {
				found = true
				continue
			}
			keep = append(keep, u)
		}
		if !found {
			return fmt.Errorf("no such account")
		}
		st.Users = keep
		return nil
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	go s.app.restartBot() // the account's own bot goes with it
	writeJSON(w, map[string]string{"ok": "1"})
}

// accountExists: owner names an account (the admin assigning a server or tunnel to it).
func accountExists(st *State, name string) bool {
	for _, u := range st.Users {
		if u.Username == name {
			return true
		}
	}
	return false
}

// owner moves a server or tunnel to another account (admin; POST {Kind, ID, Owner}, "" =
// the admin's). Saves never change the owner, so a form that doesn't send it can't move
// anything by accident.
func (s *Server2) owner(w http.ResponseWriter, r *http.Request) {
	var in struct{ Kind, ID, Owner string }
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, "bad request")
		return
	}
	err := s.app.store.Update(func(st *State) error {
		if in.Owner != "" && !accountExists(st, in.Owner) {
			return fmt.Errorf("no account %q", in.Owner)
		}
		switch in.Kind {
		case "server":
			if x := s.app.store.serverLocked(st, in.ID); x != nil {
				x.Owner = in.Owner
				return nil
			}
		case "tunnel":
			if t := s.app.store.tunnelLocked(st, in.ID); t != nil {
				t.Owner = in.Owner
				return nil
			}
		}
		return fmt.Errorf("not found")
	})
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]string{"ok": "1"})
}

// ownerOfLocked is a server's owner ("" also for an unknown server or the panel host);
// call it under the store lock.
func ownerOfLocked(st *State, serverID string) string {
	for _, x := range st.Servers {
		if x.ID == serverID {
			return x.Owner
		}
	}
	return ""
}

// renameOwnerLocked moves everything owned by from to to (an account renamed itself).
func renameOwnerLocked(st *State, from, to string) {
	if from == "" {
		return
	}
	for _, x := range st.Servers {
		if x.Owner == from {
			x.Owner = to
		}
	}
	for _, t := range st.Tunnels {
		if t.Owner == from {
			t.Owner = to
		}
	}
}
