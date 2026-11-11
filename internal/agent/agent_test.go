package agent

import (
	"bufio"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"tunnelpanel/internal/agentproto"
)

// TestAgentHelperProcess is the "script" the exec tests run: it sleeps (not a test by itself).
func TestAgentHelperProcess(t *testing.T) {
	if os.Getenv("TP_AGENT_HELPER") != "1" {
		return
	}
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

// The panel cancels a run by closing the stream: the script must stop then, not run on.
func TestAgentExecStopsWhenStreamCloses(t *testing.T) {
	old := execShell
	execShell = []string{os.Args[0], "-test.run=^TestAgentHelperProcess$"}
	defer func() { execShell = old }()
	t.Setenv("TP_AGENT_HELPER", "1")
	panel, ag := net.Pipe()
	done := make(chan struct{})
	go func() { serveStream(ag); close(done) }()
	if err := agentproto.WriteRequest(panel, agentproto.Request{Op: "exec", Script: "sleep 60\n"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	panel.Close() // the cancel
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("the script ran on after the stream closed")
	}
}

// A panel that accepts the connection but never answers the upgrade: the agent gives up
// (and retries) instead of waiting forever.
func TestAgentUpgradeTimeout(t *testing.T) {
	old := upgradeTimeout
	upgradeTimeout = 200 * time.Millisecond
	defer func() { upgradeTimeout = old }()
	panel, ag := net.Pipe()
	defer panel.Close()
	go func() { _, _ = bufio.NewReader(panel).ReadString(0) }() // reads, never answers
	errc := make(chan error, 1)
	go func() { up, err := serveConn(ag, "panel:443", "tok"); _ = up; errc <- err }()
	select {
	case err := <-errc:
		if err == nil {
			t.Errorf("no error")
		}
	case <-time.After(5 * time.Second):
		t.Errorf("still waiting for the upgrade answer")
	}
}

// up is true once the session served (so the reconnect backoff starts over at 1 s).
func TestAgentSessionUp(t *testing.T) {
	panel, ag := net.Pipe()
	type res struct {
		up  bool
		err error
	}
	rc := make(chan res, 1)
	go func() { up, err := serveConn(ag, "panel:443", "tok"); rc <- res{up, err} }()
	br := bufio.NewReader(panel)
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	_, _ = panel.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tp-agent\r\n\r\n"))
	sess, err := yamux.Client(PreBuffered(panel, br), yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	st, err := sess.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	sess.Close()
	select {
	case r := <-rc:
		if !r.up {
			t.Errorf("a session that came up reported up=false (%v)", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("serveConn didn't return after the session closed")
	}

	// refused upgrade: not up
	panel2, ag2 := net.Pipe()
	go func() {
		br := bufio.NewReader(panel2)
		for {
			l, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(l) == "" {
				break
			}
		}
		_, _ = panel2.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nunknown agent token"))
		panel2.Close()
	}()
	if up, err := serveConn(ag2, "panel:443", "tok"); up || err == nil {
		t.Errorf("refused: up=%v err=%v", up, err)
	}
}
