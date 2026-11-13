package main

// The test account's home exit belongs to the test account alone.
//
// The Google test browser always goes out through gemHome, the panel host's own IP (its relay
// 12371, route "direct"). That holds only while no user's Google leaves from the same IP. On
// 2026-11-11 22:07 UTC the panel host's own users' Google was set to GOOGLE=direct (gemFix's
// "its own IP" candidate picks exactly that). From then on every Iranian user of the panel
// host reached Google, accounts.google.com included, from the account's IP. The user signed in
// at 22:39; by 2026-11-12 morning Google had ended the session again (SID cookies cleared,
// the rest of the profile intact, browser never restarted).
//
// So: gemFix never offers the home server its own IP, the panel refuses that route there (one
// server or many), and gemHomeGuard puts it back within one gemAcctTick if anything else
// (a shell, an agent, the watch job) sets it anyway, and says so.
//
// GOOGLE=warp6 was not enough. The GOOGLE route covers only Gemini's list (gemini, accounts,
// www.google.com, googleapis ...); every other Google address of the users still left from the
// account's IP: mail.google.com, inbox.google.com, www.google.de, accounts.youtube.com, clients*.
// google.com, gstatic ... (about 900 connections in 76 minutes on 2026-11-12, each carrying
// strangers' Google sessions). The account was signed in at 11:39 UTC and out by 23:43 again.
// So the home server also keeps the agent's "gall" on (ALL Google on the GOOGLE route, YouTube
// video stays on its own IPv6): the guard turns it back on, the settings refuse turning it off.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// gemHomeSafeVia: where the home server's users' Google goes instead (the panel host has IPv6
// WARP; that is where it was before 2026-11-11).
const gemHomeSafeVia = "warp6"

// gemHomeHost is the IP the test account lives on.
func gemHomeHost() string {
	h, _, _ := net.SplitHostPort(gemHome)
	return h
}

// gemIsHome: does this server's own IP carry the test account?
func gemIsHome(s *Server) bool {
	return s != nil && s.IPv4 != "" && s.IPv4 == gemHomeHost()
}

// gemHomeRouteBad: a route change that would put users' Google on the test account's IP.
func gemHomeRouteBad(s *Server, svc, via string) bool {
	svc = strings.ToUpper(strings.TrimSpace(svc))
	return gemIsHome(s) && (svc == "GOOGLE" || svc == "ALL") && strings.TrimSpace(via) == "direct"
}

const gemHomeRefusal = "the panel host's own IP is the Google test account's exit: its users' Google may not leave from it (Google signs the account out) — pick warp6, warp, ipv6 or a proxy"

// gemHomeOptBad: a setting that would put users' Google on the test account's IP.
func gemHomeOptBad(s *Server, k, v string) bool {
	return gemIsHome(s) && k == "gall" && strings.EqualFold(strings.TrimSpace(v), "off")
}

const gemHomeOptRefusal = "on the panel host \"All of Google\" stays on: otherwise its users' Gmail, Search and YouTube sign-in leave from the Google test account's own IP and Google signs the account out"

// gemHomeRisk: what the home server's info says is wrong ("" = nothing).
func gemHomeRisk(inf map[string]string) string {
	var why []string
	if inf["google"] == "direct" {
		why = append(why, "the panel host's users' Google went out through the test account's own IP ("+gemHomeHost()+", route GOOGLE=direct): Google saw the account among many strangers' traffic")
	}
	if inf["gall"] == "OFF" {
		why = append(why, "the panel host's users' other Google (Gmail, Search, google.de, YouTube sign-in: everything outside Gemini's list) went out through the test account's own IP ("+gemHomeHost()+", \"All of Google\" off): Google saw the account among strangers' Google sessions")
	}
	return strings.Join(why, "; ")
}

// gemHomeLog keeps the last risk seen, so the sign-out alert can name it.
var gemHomeLog = struct {
	sync.Mutex
	why string
	at  time.Time
}{}

func gemHomeSeen(why string, now time.Time) {
	gemHomeLog.Lock()
	gemHomeLog.why, gemHomeLog.at = why, now
	gemHomeLog.Unlock()
}

// gemHomeRecent: a risk seen within the last two days, with its time ("" = none).
func gemHomeRecent(now time.Time) string {
	gemHomeLog.Lock()
	defer gemHomeLog.Unlock()
	if gemHomeLog.why == "" || now.Sub(gemHomeLog.at) > 48*time.Hour {
		return ""
	}
	return gemHomeLog.why + " (last seen " + gemHomeLog.at.UTC().Format("01-02 15:04") + " UTC)"
}

// gemHomeGuard checks the home server's routes and moves users' Google off the account's IP.
// It returns the message for the admin ("" = all well).
func (a *App) gemHomeGuard(ctx context.Context) string {
	var home *Server
	a.store.View(func(s *State) {
		for _, x := range s.Servers {
			if x.Igproxy && gemIsHome(x) {
				home = x
			}
		}
	})
	if home == nil {
		return ""
	}
	inf := a.igInfo(ctx, home)
	why := gemHomeRisk(inf)
	if why == "" {
		return ""
	}
	gemHomeSeen(why, time.Now())
	var fix [][]string
	if inf["google"] == "direct" {
		fix = append(fix, []string{"route", "GOOGLE", gemHomeSafeVia})
	}
	if inf["gall"] == "OFF" {
		fix = append(fix, []string{"set", "gall", "on"})
	}
	var done, failed []string
	for _, args := range fix {
		rc, out := a.igRun(ctx, home, args, "", 180, nil)
		what := "GOOGLE → " + gemHomeSafeVia
		if args[0] == "set" {
			what = "All of Google → on"
		}
		if rc != 0 {
			failed = append(failed, what+" ("+clipTo(agentLine(home, out), 120)+")")
		} else {
			done = append(done, what)
		}
	}
	a.igForget(home.ID)
	if len(failed) > 0 {
		return fmt.Sprintf("🔑⚠️ %s's users' Google leaves from the Google test account's own IP. Fixing it failed: %s — fix it by hand, or Google signs the test account out.", igLabel(home), strings.Join(failed, "; "))
	}
	return fmt.Sprintf("🔑 Guard: %s's users' Google was leaving from the Google test account's own IP — set %s. That IP is the test account's alone: Google signs the account out when strangers' Google traffic shares it.", igLabel(home), strings.Join(done, ", "))
}
