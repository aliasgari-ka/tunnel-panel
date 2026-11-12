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

// gemHomeRisk: what the home server's info says is wrong ("" = nothing).
func gemHomeRisk(inf map[string]string) string {
	if inf["google"] == "direct" {
		return "the panel host's users' Google went out through the test account's own IP (" + gemHomeHost() + ", route GOOGLE=direct): Google saw the account among many strangers' traffic"
	}
	return ""
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
	rc, out := a.igRun(ctx, home, []string{"route", "GOOGLE", gemHomeSafeVia}, "", 180, nil)
	a.igForget(home.ID)
	if rc != 0 {
		return fmt.Sprintf("🔑⚠️ %s's users' Google leaves from the Google test account's own IP (route GOOGLE=direct). Moving it to %s failed: %s — move it by hand, or Google signs the test account out.", igLabel(home), gemHomeSafeVia, clipTo(agentLine(home, out), 120))
	}
	return fmt.Sprintf("🔑 Guard: %s's users' Google was set to leave from the Google test account's own IP (route GOOGLE=direct) — moved to %s. That IP is the test account's alone: Google signs the account out when strangers' traffic shares it.", igLabel(home), gemHomeSafeVia)
}
