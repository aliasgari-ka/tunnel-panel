package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"tunnelpanel/internal/agentproto"
)

// hunt3FakeAgent connects a yamux session to hub as server id, and answers every exec the
// way internal/agent's serveStream does for a script that prints a line and exits with code.
func hunt3FakeAgent(t *testing.T, hub *AgentHub, id string, code int) {
	t.Helper()
	pc, ps := net.Pipe()
	panelSess, err := yamux.Client(pc, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	agentSess, err := yamux.Server(ps, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { panelSess.Close(); agentSess.Close() })
	go func() {
		for {
			st, err := agentSess.AcceptStream()
			if err != nil {
				return
			}
			go func(st net.Conn) {
				defer st.Close()
				br := bufio.NewReader(st)
				req, err := agentproto.ReadRequest(br)
				if err != nil {
					return
				}
				if req.Op == "write" { // a write succeeds, as on the real agent
					_, _ = io.CopyN(io.Discard, br, req.Size)
					_ = agentproto.WriteFrame(st, 'x', []byte("0"))
					return
				}
				// exactly what agent.serveStream writes after cmd.Run() returns an *exec.ExitError
				_ = agentproto.WriteFrame(st, 'o', []byte("systemctl restart failed\n"))
				_ = agentproto.WriteFrame(st, 'x', []byte(fmt.Sprintf("%d", code)))
			}(st)
		}
	}()
	hub.mu.Lock()
	hub.conns[id] = &agentConn{sess: panelSess, token: "tok", since: time.Now()}
	hub.tokens["tok"] = id
	hub.mu.Unlock()
}

// SSHHost.Run and LocalHost.Run return an error when the script exits non-zero (deploy,
// Stop, purge, ... all rely on it: "if ! systemctl restart; then jl; exit 1; fi"). Over the
// agent the exit code is read and thrown away, so a failing script is a success.
func TestHunt3AgentRunNonZeroExitIsError(t *testing.T) {
	hub := newAgentHub()
	hunt3FakeAgent(t, hub, "ir1", 1)
	h := AgentHost{hub: hub, serverID: "ir1"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := h.Run(ctx, "exit 1", nil)
	if err == nil {
		t.Fatalf("a script that exited 1 over the agent returned no error (output %q): deploy/stop see it as success", out)
	}
}

// The same through deploy(): a unit that fails to start on an agent-connected Iran server is
// reported as deployed.
func TestHunt3AgentDeployFailureIgnored(t *testing.T) {
	hub := newAgentHub()
	hunt3FakeAgent(t, hub, "ir1", 1)
	h := AgentHost{hub: hub, serverID: "ir1"}
	j := &Job{ID: "j", Status: "running"}
	a := &App{jobs: newJobs()}
	tun := &Tunnel{ID: "aaaaaaaaaaaa", Index: 3}
	err := a.deploy(context.Background(), j, "IR", h, tun, SidePlan{Unit: Unit{Desc: "x", ExecStart: "/bin/false"}})
	if err == nil {
		t.Fatalf("deploy over the agent of a unit whose restart exits 1 returned nil; log:\n%v", j.Lines)
	}
}
