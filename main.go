package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"tunnelpanel/internal/agent"
)

func main() {
	// agent subcommand: tunnel-panel agent --connect host:port --token T --pin P
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		fs := flag.NewFlagSet("agent", flag.ExitOnError)
		connect := fs.String("connect", "", "panel agent address host:port")
		token := fs.String("token", "", "agent token")
		pin := fs.String("pin", "", "panel cert pin")
		_ = fs.Parse(os.Args[2:])
		log.Fatal(agent.Run(*connect, *token, *pin))
	}

	addr := flag.String("addr", envOr("TP_ADDR", "0.0.0.0:8088"), "web panel listen address")
	agentAddr := flag.String("agent-addr", envOr("TP_AGENT_ADDR", "0.0.0.0:7020"), "agent dial-back listen address")
	dir := flag.String("data", envOr("TP_DATA", "/etc/tunnel-panel"), "data directory")
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
	app := &App{store: store, jobs: newJobs(), agents: newAgentHub(), agentPort: portOf(*agentAddr)}
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
		}
	}
	app.restartBot()

	go func() {
		if err := app.agents.Listen(*agentAddr, *dir, app.settings); err != nil {
			log.Printf("agent hub stopped: %v", err)
		}
	}()

	fmt.Printf("Tunnel Panel on http://%s  (agent %s, data %s, %d methods)\n", *addr, *agentAddr, *dir, len(methods))
	log.Fatal((&http.Server{Addr: *addr, Handler: app.routes()}).ListenAndServe())
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
