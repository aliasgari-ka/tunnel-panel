package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"tunnelpanel/internal/agent"
	"tunnelpanel/internal/agentproto"
)

// setTokens closes every session whose token is no longer valid ("server deleted, token
// rotated, a backup restored ... ends now"). connect() looks the token up first and only
// registers the session after the hello (up to 10 s later): a token revoked in between is
// checked by nobody, and the session with the revoked token stays online for good — the
// panel keeps running scripts on whatever holds the old token.
func TestHunt3AgentTokenRevokedDuringHello(t *testing.T) {
	hub := newAgentHub()
	hub.setTokens([]*Server{{ID: "ir1", AgentToken: "oldtoken"}})
	srv := httptest.NewServer(http.HandlerFunc(hub.connect))
	defer srv.Close()

	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\n%s: oldtoken\r\nConnection: Upgrade\r\nUpgrade: tp-agent\r\n\r\n", agentproto.ConnectPath, agentproto.TokenHeader)
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("no upgrade: %q", status)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	sess, err := yamux.Server(agent.PreBuffered(c, br), yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	// the admin rotates the token (or deletes the server) while the hello is on its way
	time.Sleep(300 * time.Millisecond)
	hub.setTokens([]*Server{{ID: "ir1", AgentToken: "newtoken"}})
	_ = agentproto.WriteRequest(st, agentproto.Request{Op: "hello"})
	_ = agentproto.WriteFrame(st, 'o', []byte("h|amd64|debian"))
	st.Close()

	time.Sleep(500 * time.Millisecond)
	if ac := hub.online("ir1"); ac != nil {
		t.Errorf("a session on the revoked token %q is online as ir1 (setTokens ran before it registered)", ac.token)
	}
}
