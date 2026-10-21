package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"tunnelpanel/internal/agentproto"
)

// Run is the tp-agent main loop that runs on the Iran server.
// It dials OUT to the panel (so no inbound SSH/port is needed on Iran), pins the
// panel's TLS key, authenticates with a token, and serves exec/write/dial over yamux.
func Run(connect, token, pin string) error {
	if connect == "" || token == "" {
		return fmt.Errorf("agent needs --connect host:port and --token")
	}
	backoff := time.Second
	for {
		err := agentSession(connect, token, pin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent: %v (retry in %s)\n", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		} else {
			backoff = 30 * time.Second
		}
	}
}

func agentSession(connect, token, pin string) error {
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	if pin != "" {
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("no server cert")
			}
			if KeyPin(raw[0]) != pin {
				return fmt.Errorf("panel key mismatch (possible MITM)")
			}
			return nil
		}
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := tls.DialWithDialer(d, "tcp", connect, tlsCfg)
	if err != nil {
		return err
	}
	// HTTP-ish upgrade so the panel can also sit behind a reverse proxy
	fmt.Fprintf(raw, "GET %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\nConnection: Upgrade\r\nUpgrade: tp-agent\r\n\r\n",
		agentproto.ConnectPath, connect, agentproto.TokenHeader, token)
	br := bufio.NewReader(raw)
	status, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(status, "101") {
		rest, _ := io.ReadAll(io.LimitReader(br, 512))
		return fmt.Errorf("panel refused agent: %s %s", strings.TrimSpace(status), strings.TrimSpace(string(rest)))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	conn := PreBuffered(raw, br)
	sess, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		return err
	}
	defer sess.Close()

	// Hello on the first stream we open back.
	if s, err := sess.OpenStream(); err == nil {
		hn, _ := os.Hostname()
		_ = agentproto.WriteRequest(s, agentproto.Request{Op: "hello"})
		_ = agentproto.WriteFrame(s, 'o', []byte(fmt.Sprintf("%s|%s|%s", hn, runtime.GOARCH, agentOS())))
		s.Close()
	}
	fmt.Fprintln(os.Stderr, "agent: connected to panel")
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go serveStream(st)
	}
}

func serveStream(st net.Conn) {
	defer st.Close()
	br := bufio.NewReader(st)
	req, err := agentproto.ReadRequest(br)
	if err != nil {
		return
	}
	switch req.Op {
	case "ping":
		_ = agentproto.WriteFrame(st, 'x', []byte("0"))
	case "exec":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-s")
		cmd.Stdin = strings.NewReader(prelude + req.Script)
		fw := agentproto.FrameWriter{W: st}
		cmd.Stdout, cmd.Stderr = fw, fw
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				_ = agentproto.WriteFrame(st, 'e', []byte(err.Error()))
				return
			}
		}
		_ = agentproto.WriteFrame(st, 'x', []byte(fmt.Sprintf("%d", code)))
	case "write":
		if err := agentWrite(req, br); err != nil {
			_ = agentproto.WriteFrame(st, 'e', []byte(err.Error()))
			return
		}
		_ = agentproto.WriteFrame(st, 'x', []byte("0"))
	case "dial":
		up, err := net.DialTimeout("tcp", req.Addr, 10*time.Second)
		if err != nil {
			_ = agentproto.WriteFrame(st, 'e', []byte(err.Error()))
			return
		}
		_ = agentproto.WriteFrame(st, 'x', []byte("0"))
		defer up.Close()
		pipe(st, up, br)
	}
}

func agentWrite(req agentproto.Request, br *bufio.Reader) error {
	if req.Path == "" {
		return fmt.Errorf("no path")
	}
	tmp := req.Path + ".tp-tmp"
	if i := strings.LastIndex(req.Path, "/"); i > 0 {
		_ = os.MkdirAll(req.Path[:i], 0o755)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(req.Mode))
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, br, req.Size); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_ = os.Chmod(tmp, os.FileMode(req.Mode))
	return os.Rename(tmp, req.Path)
}

// pipe copies between the yamux stream (with its buffered reader) and the upstream conn.
func pipe(st net.Conn, up net.Conn, br *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, br); done <- struct{}{} }()
	go func() { io.Copy(st, up); done <- struct{}{} }()
	<-done
}

func agentOS() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "ID=") {
				return strings.Trim(strings.TrimPrefix(l, "ID="), "\"")
			}
		}
	}
	return runtime.GOOS
}

// KeyPin is the base64 SHA-256 of a certificate's SubjectPublicKeyInfo — the same
// value curl's --pinnedpubkey sha256//<pin> checks, so the bootstrap and the agent agree.
func KeyPin(der []byte) string {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// PreBuffered wraps a conn so buffered bytes in br are read first.
func PreBuffered(c net.Conn, br *bufio.Reader) net.Conn {
	return &buffConn{Conn: c, r: br}
}

type buffConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *buffConn) Read(p []byte) (int, error) { return b.r.Read(p) }

const prelude = "set -o pipefail\nexport DEBIAN_FRONTEND=noninteractive LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
