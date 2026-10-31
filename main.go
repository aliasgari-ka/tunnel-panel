package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tunnelpanel/internal/agent"
)

// version is stamped by build.sh (-X main.version=...).
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("tunnel-panel " + version)
		return
	}
	// set-domain: tunnel-panel set-domain panel.example.com[,other] — HTTPS on those domains
	if len(os.Args) > 1 && os.Args[1] == "set-domain" {
		if err := setDomainCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	// agent subcommand: tunnel-panel agent --connect host:port --token T --pin P
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		fs := flag.NewFlagSet("agent", flag.ExitOnError)
		connect := fs.String("connect", "", "panel agent address host:port")
		token := fs.String("token", "", "agent token")
		pin := fs.String("pin", "", "panel cert pin")
		_ = fs.Parse(os.Args[2:])
		log.Fatal(agent.Run(*connect, *token, *pin))
	}

	// reset-password: set or clear the admin login without touching servers/tunnels.
	//   tunnel-panel reset-password [-data DIR] [-user NAME] [-password PASS]
	// With -password it sets that password (creating the account if none exists);
	// without it, it clears all accounts so the next visit shows "Create admin account".
	// setup-code prints the code the first admin account needs (nothing once one exists).
	if len(os.Args) > 1 && os.Args[1] == "setup-code" {
		fs := flag.NewFlagSet("setup-code", flag.ExitOnError)
		d := fs.String("data", envOr("TP_DATA", "/etc/tunnel-panel"), "data directory")
		_ = fs.Parse(os.Args[2:])
		// read only: the running service owns state.json
		var st struct {
			Users     []json.RawMessage `json:"users"`
			SetupCode string            `json:"setupCode"`
		}
		if b, err := os.ReadFile(filepath.Join(*d, "state.json")); err == nil {
			_ = json.Unmarshal(b, &st)
		}
		if len(st.Users) == 0 && st.SetupCode != "" {
			fmt.Println(st.SetupCode)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "reset-password" || os.Args[1] == "passwd") {
		fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
		d := fs.String("data", envOr("TP_DATA", "/etc/tunnel-panel"), "data directory")
		user := fs.String("user", "admin", "username (when setting a password)")
		pass := fs.String("password", "", "new password (min 8 chars); empty = clear all accounts")
		_ = fs.Parse(os.Args[2:])
		if err := resetPassword(*d, *user, *pass); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	addr := flag.String("addr", envOr("TP_ADDR", "0.0.0.0:8088"), "web panel listen address")
	agentAddr := flag.String("agent-addr", envOr("TP_AGENT_ADDR", "0.0.0.0:7020"), "agent dial-back listen address")
	dir := flag.String("data", envOr("TP_DATA", "/etc/tunnel-panel"), "data directory")
	tlsMode := flag.String("tls", envOr("TP_TLS", ""), "TLS: empty=http, 'self'=self-signed https, or a domain for Let's Encrypt")
	dump := flag.Bool("dump-methods", false, "print methods JSON and exit")
	flag.Parse()

	if *dump {
		b, _ := jsonMarshal(methods)
		fmt.Println(string(b))
		return
	}

	dataDir = *dir
	store, err := LoadStore(*dir)
	if err != nil {
		log.Fatalf("load store: %v", err)
	}
	app := &App{store: store, jobs: newJobs(), agents: newAgentHub(), agentPort: portOf(*agentAddr),
		traffic: newTrafficMon(), speedRes: map[string]*SpeedResult{}}
	app.notify = func(msg string) {
		app.botMu.Lock()
		bot := app.bot
		app.botMu.Unlock()
		if bot != nil {
			bot.push(msg)
		}
	}
	app.syncAgentTokens()
	app.agents.onChange = func(serverID string, online bool) {
		if online {
			app.push("🟢 agent online: " + serverName(app, serverID))
			if srv := app.store.Server(serverID); srv != nil {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					app.autoSetup(ctx, srv, AgentHost{hub: app.agents, serverID: serverID})
				}()
			}
		}
	}
	app.restartBot()

	go func() {
		if err := app.agents.Listen(*agentAddr, *dir, app.settings); err != nil {
			log.Printf("agent hub stopped: %v", err)
		}
	}()

	go func() { time.Sleep(10 * time.Second); app.autoSetupLocal() }()
	go app.healthMonitor()
	go app.serverMonitor()
	go app.autoBench()
	go app.autoBackup()
	go app.resWatch()
	go app.resumeInterrupted()
	go app.repairAfterUpdate()
	go app.memNightly()
	go app.igImport()

	fmt.Printf("Tunnel Panel %s (agent %s, data %s, %d methods)\n", version, *agentAddr, *dir, len(methods))
	store.View(func(st *State) {
		if len(st.Users) == 0 && st.SetupCode != "" {
			fmt.Printf("No admin account yet — create it in the panel with the setup code:  %s\n", st.SetupCode)
		}
	})
	cookieSecure = *tlsMode != "" && *tlsMode != "self"
	panelTLS = *tlsMode
	log.Fatal(serve(*addr, *tlsMode, *dir, app.routes()))
}

func serverName(app *App, id string) string {
	if s := app.store.Server(id); s != nil {
		return s.Name
	}
	return id
}

func portOf(addr string) int {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			var p int
			fmt.Sscanf(addr[i+1:], "%d", &p)
			return p
		}
	}
	return 7020
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func jsonMarshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func resetPassword(dir, user, pass string) error {
	store, err := LoadStore(dir)
	if err != nil {
		return fmt.Errorf("open data dir %s: %w", dir, err)
	}
	if pass == "" {
		code := newSetupCode()
		if err := store.Update(func(st *State) error { st.Users, st.SetupCode = nil, code; return nil }); err != nil {
			return err
		}
		fmt.Println("All accounts cleared. Restart the service:  systemctl restart tunnel-panel")
		fmt.Println("Then open the panel and create the admin account with this setup code:  " + code)
		return nil
	}
	if len(pass) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	err = store.Update(func(st *State) error {
		for i := range st.Users {
			if st.Users[i].Username == user {
				st.Users[i].Hash = string(hash)
				st.Users[i].Gen++ // sessions from before the reset end
				return nil
			}
		}
		st.Users = append(st.Users, User{Username: user, Hash: string(hash)})
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("Password for %q set. Restart the service:  systemctl restart tunnel-panel\n", user)
	return nil
}
