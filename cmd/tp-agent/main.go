// tp-agent runs on an Iran server whose SSH the panel cannot reach. It dials OUT to
// the panel over TLS (pinned certificate), so no inbound port is needed on Iran, and
// executes the panel's operations locally as root.
package main

import (
	"flag"
	"fmt"
	"os"

	"tunnelpanel/internal/agent"
)

func main() {
	connect := flag.String("connect", "", "panel agent address host:port")
	token := flag.String("token", "", "agent token from the panel")
	pin := flag.String("pin", "", "panel certificate pin (base64 sha256)")
	flag.Parse()
	if err := agent.Run(*connect, *token, *pin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
