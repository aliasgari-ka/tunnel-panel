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

func backupName(t time.Time) string {
	return "tunnel-panel-backup-" + t.In(tehran).Format("2006-01-02-1504") + ".json"
}

func (a *App) backupDir() string { return filepath.Join(filepath.Dir(a.store.path), "backups") }

// saveLocalBackup writes today's backup next to the state and prunes old ones.
func (a *App) saveLocalBackup() (string, error) {
	data, err := a.backupJSON()
	if err != nil {
		return "", err
	}
	dir := a.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, backupName(time.Now()))
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", err
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
				if data, err := os.ReadFile(p); err == nil && bot != nil {
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
	if _, err := a.saveLocalBackup(); err != nil {
		return "", fmt.Errorf("could not back up the current state first: %v", err)
	}
	if err := a.store.replace(st); err != nil {
		return "", err
	}
	for _, s := range st.Servers {
		dropHost(s.ID)
	}
	a.restartBot()
	return fmt.Sprintf("restored: %d servers, %d tunnels (the state before was saved in %s)", len(st.Servers), len(st.Tunnels), a.backupDir()), nil
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
	data, err := s.app.backupJSON()
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
		return err
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
func checkBackup(st *State) error {
	for _, s := range st.Servers {
		if s == nil || !backupIDRe.MatchString(s.ID) {
			return fmt.Errorf("server id")
		}
		if s.Role != "" && s.Role != "iran" && s.Role != "foreign" {
			return fmt.Errorf("server %s role", s.ID)
		}
	}
	for _, t := range st.Tunnels {
		if t == nil || !backupIDRe.MatchString(t.ID) || (t.ServerID != "" && !backupIDRe.MatchString(t.ServerID)) || (t.ForeignID != "" && !backupIDRe.MatchString(t.ForeignID)) {
			return fmt.Errorf("tunnel id")
		}
		if t.Family == "" {
			t.Family = "v4" // from before tunnels had a family
		}
		if t.Family != "v4" && t.Family != "v6" {
			return fmt.Errorf("tunnel %s family", t.ID)
		}
		if t.Index < 1 || t.Index > 250 {
			return fmt.Errorf("tunnel %s index", t.ID)
		}
		if err := validatePorts(t.Ports, nil); t.Ports != "" && err != nil {
			return fmt.Errorf("tunnel %s ports: %v", t.ID, err)
		}
		if err := validateOptions(t.Options); err != nil {
			return fmt.Errorf("tunnel %s options: %v", t.ID, err)
		}
	}
	return nil
}
