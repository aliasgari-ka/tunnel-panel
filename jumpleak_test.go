package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// countingSSHD is an in-process SSH server (any password) that forwards direct-tcpip
// channels and counts the sessions open on it, as sshd processes on a real server.
func countingSSHD(t *testing.T) (port int, open *atomic.Int32) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	open = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				open.Add(1)
				defer open.Add(-1)
				go ssh.DiscardRequests(reqs)
				go func() {
					for nc := range chans {
						if nc.ChannelType() != "direct-tcpip" {
							_ = nc.Reject(ssh.UnknownChannelType, "")
							continue
						}
						p := nc.ExtraData()
						hl := binary.BigEndian.Uint32(p)
						host := string(p[4 : 4+hl])
						prt := binary.BigEndian.Uint32(p[4+hl:])
						dst, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(prt))))
						if err != nil {
							_ = nc.Reject(ssh.ConnectionFailed, err.Error())
							continue
						}
						ch, rq, err := nc.Accept()
						if err != nil {
							dst.Close()
							continue
						}
						go ssh.DiscardRequests(rq)
						go func() { _, _ = io.Copy(ch, dst); ch.Close() }()
						go func() { _, _ = io.Copy(dst, ch); dst.Close() }()
					}
				}()
				_ = sc.Wait()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, open
}

// A connection through a jump host must take its session on the jump host with it when it
// closes — and a jump whose onward dial fails must not leave one either.
func TestJumpHostSessionsClosed(t *testing.T) {
	dataDir = t.TempDir()
	st, _ := LoadStore(dataDir)
	viaPort, viaOpen := countingSSHD(t)
	tgtPort, tgtOpen := countingSSHD(t)
	via := &Server{ID: "via", Name: "via", IPv4: "127.0.0.1", SSHPort: viaPort, Password: "x"}
	tgt := &Server{ID: "tgt", Name: "tgt", IPv4: "127.0.0.1", SSHPort: tgtPort, Password: "x"}
	dead := &Server{ID: "dead", Name: "dead", IPv4: "127.0.0.1", SSHPort: 1, Password: "x"}
	_ = st.Update(func(s *State) error { s.Servers = []*Server{via, tgt, dead}; return nil })
	a := &App{store: st, jobs: newJobs()}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		sh := newSSHHost(st, tgt, a.jumpDial(ctx, via))
		if _, err := sh.client(); err != nil {
			t.Fatalf("jump connect: %v", err)
		}
		if viaOpen.Load() == 0 || tgtOpen.Load() == 0 {
			t.Fatalf("no sessions while connected: via %d, target %d", viaOpen.Load(), tgtOpen.Load())
		}
		sh.Close()
		// onward dial to a closed port
		sd := newSSHHost(st, dead, a.jumpDial(ctx, via))
		if _, err := sd.client(); err == nil {
			t.Fatal("connected to a dead target")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (viaOpen.Load() != 0 || tgtOpen.Load() != 0) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := viaOpen.Load(); n != 0 {
		t.Errorf("%d sessions left open on the jump host", n)
	}
	if n := tgtOpen.Load(); n != 0 {
		t.Errorf("%d sessions left open on the target", n)
	}
}
