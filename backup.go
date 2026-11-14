package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Backups: the whole panel state (servers with their SSH credentials, tunnels with their
// secrets, settings, users, history) as one JSON file — downloaded from Settings, sent to
// the Telegram admin chat, and kept daily on the panel host (the newest backupKeep).
const backupKeep = 14

// backupJSON is the current state, as saved on disk.
func (a *App) backupJSON() ([]byte, error) {
	var out []byte
	var err error
	a.store.View(func(st *State) { out, err = json.MarshalIndent(st, "", "  ") })
	return out, err
}

// backupFileJSON is the backup that leaves the panel host (download, Telegram): the state
// plus the helpers nobody can download again (tpk-agent), so a new panel gets them back.
func (a *App) backupFileJSON() ([]byte, error) {
	var out []byte
	var err error
	hs := backupHelpers()
	a.store.View(func(st *State) {
		c := *st
		// the session key signs every login cookie: a copy of it would let the holder of the
		// file sign in as any account without a password. A restore makes a new one anyway.
		c.Secret = backupNoSecret
		out, err = json.MarshalIndent(struct {
			*State
			HelperFiles map[string][]byte `json:"helperFiles,omitempty"`
		}{&c, hs}, "", "  ")
	})
	return out, err
}

// backupNoSecret stands in for the session key in a backup that leaves the panel host.
const backupNoSecret = "not-in-backup"

func backupName(t time.Time) string {
	return "tunnel-panel-backup-" + t.In(tehran).Format("2006-01-02-150405") + ".json"
}

func (a *App) backupDir() string { return filepath.Join(filepath.Dir(a.store.path), "backups") }

// saveLocalBackup writes today's backup next to the state and prunes old ones.
func (a *App) saveLocalBackup() (string, error) { return a.saveLocalBackupAs("") }

// saveLocalBackupAs is saveLocalBackup with tag in the name ("-pre-restore"). It never
// overwrites a file: two restores in one minute replaced the first one's safety copy (the
// state before both) with the state the first restore had just brought in.
func (a *App) saveLocalBackupAs(tag string) (string, error) {
	data, err := a.backupJSON()
	if err != nil {
		return "", err
	}
	dir := a.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	base := strings.TrimSuffix(backupName(time.Now()), ".json") + tag
	var p string
	for n := 1; ; n++ {
		p = filepath.Join(dir, base+".json")
		if n > 1 {
			p = filepath.Join(dir, fmt.Sprintf("%s-%d.json", base, n))
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) && n < 100 {
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(p)
			return "", werr
		}
		break
	}
	ents, _ := filepath.Glob(filepath.Join(dir, "tunnel-panel-backup-*.json"))
	sort.Strings(ents)
	for len(ents) > backupKeep {
		os.Remove(ents[0])
		ents = ents[1:]
	}
	return p, nil
}

// autoBackup keeps a daily backup on disk and, when Settings.TelegramBackup is on, sends
// it to the admin chat as well.
func (a *App) autoBackup() {
	time.Sleep(2 * time.Minute)
	for {
		dir := a.backupDir()
		ents, _ := filepath.Glob(filepath.Join(dir, "tunnel-panel-backup-*.json"))
		newest := time.Time{}
		for _, e := range ents {
			if fi, err := os.Stat(e); err == nil && fi.ModTime().After(newest) {
				newest = fi.ModTime()
			}
		}
		if time.Since(newest) >= 24*time.Hour {
			if p, err := a.saveLocalBackup(); err == nil && a.settings().TelegramBackup == "on" {
				a.botMu.Lock()
				bot := a.bot
				a.botMu.Unlock()
				if data, err := a.backupFileJSON(); err == nil && bot != nil && p != "" {
					bot.sendBackup(data, "💾 daily backup")
				}
			}
		}
		time.Sleep(time.Hour)
	}
}

// restoreBackup replaces the whole state with a backup (refused while jobs run).
func (a *App) restoreBackup(data []byte) (string, error) {
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return "", fmt.Errorf("not a panel backup: %v", err)
	}
	if st.Secret == "" || (len(st.Servers) == 0 && len(st.Tunnels) == 0 && len(st.Users) == 0) {
		return "", fmt.Errorf("this file doesn't look like a Tunnel Panel backup")
	}
	if err := checkBackup(&st); err != nil {
		return "", fmt.Errorf("this backup has invalid data (%v) — not restored", err)
	}
	if a.jobs.anyRunning() {
		return "", fmt.Errorf("a job is still running — wait for it to finish, then restore")
	}
	// keep what is there now, just in case
	if _, err := a.saveLocalBackupAs("-pre-restore"); err != nil {
		return "", fmt.Errorf("could not back up the current state first: %v", err)
	}
	// never take the session key from a file: a fresh one logs out every cookie made
	// before (including any made with a key that was in an old backup)
	st.Secret = randHex(32)
	if err := a.store.replace(st); err != nil {
		return "", err
	}
	a.syncAgentTokens() // the agents' tokens are the restored ones now (the old ones stop working)
	for _, s := range st.Servers {
		dropHost(s.ID)
	}
	a.restartBot()
	var extra struct {
		HelperFiles map[string][]byte `json:"helperFiles"`
	}
	note := ""
	if json.Unmarshal(data, &extra) == nil {
		if got := restoreHelpers(extra.HelperFiles); len(got) > 0 {
			note = "; helpers restored: " + strings.Join(got, ", ")
		}
	}
	return fmt.Sprintf("restored: %d servers, %d tunnels (the state before was saved in %s)%s", len(st.Servers), len(st.Tunnels), a.backupDir(), note), nil
}

// replace swaps the whole state (after a restore) and saves it.
func (s *Store) replace(st State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range st.Tunnels {
		if t.Options == nil {
			t.Options = map[string]map[string]string{}
		}
		if t.Secrets == nil {
			t.Secrets = map[string]string{}
		}
	}
	if len(st.Users) == 0 && st.SetupCode == "" {
		// no account: the first one is made again with a setup code (`tunnel-panel setup-code`),
		// or nobody could sign in until a restart made one
		st.SetupCode = newSetupCode()
	}
	s.S = st
	return s.saveLocked()
}

// ---- HTTP ----

// backupDownload: GET → the backup file. POST {data: "<backup json>"} → restore it.
func (s *Server2) backup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Data string `json:"data"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&in); err != nil || in.Data == "" {
			httpErr(w, 400, "send the backup file's content as data")
			return
		}
		msg, err := s.app.restoreBackup([]byte(in.Data))
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]string{"ok": msg})
		return
	}
	data, err := s.app.backupFileJSON()
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+backupName(time.Now())+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// ---- Telegram ----

// sendBackup sends the backup file to every admin chat.
func (b *Bot) sendBackup(data []byte, caption string) {
	for chat := range b.admins {
		if err := b.sendDocument(chat, backupName(time.Now()), data, caption+" — keep it private: it holds the servers' SSH passwords/keys and the tunnels' secrets"); err != nil {
			b.send(chat, "⚠ backup could not be sent: "+esc(err.Error()))
		}
	}
}

func (b *Bot) sendDocument(chat, name string, data []byte, caption string) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("chat_id", chat)
	_ = mw.WriteField("caption", caption)
	fw, _ := mw.CreateFormFile("document", name)
	_, _ = fw.Write(data)
	mw.Close()
	resp, err := b.client.Post(b.base+"/bot"+b.token+"/sendDocument", mw.FormDataContentType(), &body)
	if err != nil {
		// a network error quotes the URL, which holds the token: callers send it to the chat
		return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), b.token, "<token>"))
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(out), `"ok":true`) {
		return fmt.Errorf("telegram: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

var backupIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// checkBackup refuses a backup whose values the panel would never have written itself: they
// end up in pages, file names and scripts.
// The same checks the forms run (an account's name is its IG backup folder, the shape's
// interface and the GitHub prefix / FRP version go into root shell scripts, a tunnel's
// numbers name its interfaces and subnets), and what only the panel itself sets: one id
// and one number per tunnel and path, method ids it knows.
func checkBackup(st *State) error {
	users := map[string]bool{}
	for _, u := range st.Users {
		if !validUsername(u.Username) || users[u.Username] {
			return fmt.Errorf("account name %q", u.Username)
		}
		users[u.Username] = true
	}
	owner := func(o string) bool { return o == "" || validUsername(o) }
	if v := strings.TrimSpace(st.Settings.FRPVersion); v != "" && !frpVerRe.MatchString(v) {
		return fmt.Errorf("settings: FRP version")
	}
	if v := strings.TrimSpace(st.Settings.GitHubProxy); v != "" && !ghProxyRe.MatchString(v) {
		return fmt.Errorf("settings: GitHub download prefix")
	}
	st.Settings.FRPVersion, st.Settings.GitHubProxy = strings.TrimSpace(st.Settings.FRPVersion), strings.TrimSpace(st.Settings.GitHubProxy)
	servers := map[string]bool{}
	for _, s := range st.Servers {
		if s == nil || !backupIDRe.MatchString(s.ID) || servers[s.ID] {
			return fmt.Errorf("server id")
		}
		servers[s.ID] = true
		if s.Role != "" && s.Role != "iran" && s.Role != "foreign" {
			return fmt.Errorf("server %s role", s.ID)
		}
		if !owner(s.Owner) || (s.Via != "" && !backupIDRe.MatchString(s.Via)) {
			return fmt.Errorf("server %s owner / jump host", s.ID)
		}
	}
	knownMethod := func(id string) bool { return id == "" || methodByID[id] != nil }
	tunnels := map[string]bool{}
	index := map[int]string{} // tunnel and path number -> the tunnel using it
	for _, t := range st.Tunnels {
		if t == nil || !backupIDRe.MatchString(t.ID) || tunnels[t.ID] || (t.ServerID != "" && !backupIDRe.MatchString(t.ServerID)) || (t.ForeignID != "" && !backupIDRe.MatchString(t.ForeignID)) {
			return fmt.Errorf("tunnel id")
		}
		tunnels[t.ID] = true
		if !owner(t.Owner) {
			return fmt.Errorf("tunnel %s owner", t.ID)
		}
		if t.Family == "" {
			t.Family = "v4" // from before tunnels had a family
		}
		if t.Family != "v4" && t.Family != "v6" {
			return fmt.Errorf("tunnel %s family", t.ID)
		}
		// 250 is the speed test's own tunnel (bench.go), torn down on every run
		nums := []int{t.Index}
		pathNum := map[int]bool{}
		for _, p := range t.Paths {
			if !knownMethod(p.Method) || p.Method == "" || (p.Family != "v4" && p.Family != "v6") {
				return fmt.Errorf("tunnel %s: hot-standby path %q", t.ID, p.Method)
			}
			if pathNum[p.Index] {
				return fmt.Errorf("tunnel %s: two hot-standby paths use number %d", t.ID, p.Index)
			}
			pathNum[p.Index] = true
			if p.Index != t.Index {
				nums = append(nums, p.Index)
			}
		}
		for _, n := range nums {
			if n < 1 || n > 249 {
				return fmt.Errorf("tunnel %s index %d: must be 1-249 (250 is reserved for the speed test)", t.ID, n)
			}
			if other, ok := index[n]; ok {
				return fmt.Errorf("tunnels %s and %s both use number %d", other, t.ID, n)
			}
			index[n] = t.ID
		}
		pin, _, _ := strings.Cut(t.HSPin, "|")
		if !knownMethod(t.Active) || !knownMethod(t.Selected) || !knownMethod(t.Applying) || !knownMethod(pin) ||
			(t.Failover != nil && !knownMethod(t.Failover.Method)) {
			return fmt.Errorf("tunnel %s: unknown method", t.ID)
		}
		if err := validatePorts(t.Ports, nil); err != nil {
			return fmt.Errorf("tunnel %s ports: %v", t.ID, err)
		}
		if err := validateOptions(t.Options); err != nil {
			return fmt.Errorf("tunnel %s options: %v", t.ID, err)
		}
		t.Shape = normalizeShape(t.Shape)
	}
	return nil
}
