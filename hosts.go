package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Host executes scripts and writes files on one side of a tunnel.
type Host interface {
	Label() string
	Run(ctx context.Context, script string, log func(string)) (string, error)
	WriteFile(path string, data []byte, mode os.FileMode) error
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// streamLines copies r to log line by line and into buf.
func streamLines(r io.Reader, buf *safeBuf, log func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		buf.WriteLine(line)
		if log != nil {
			log(line)
		}
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) WriteLine(l string) {
	s.mu.Lock()
	s.b.WriteString(l)
	s.b.WriteByte('\n')
	s.mu.Unlock()
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const scriptPrelude = "set -o pipefail\nexport DEBIAN_FRONTEND=noninteractive LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"

// ---------------- local ----------------

type LocalHost struct{}

func (LocalHost) Label() string { return "KH" }

func (LocalHost) Run(ctx context.Context, script string, log func(string)) (string, error) {
	cmd := exec.CommandContext(ctx, "bash", "-s")
	cmd.Stdin = strings.NewReader(scriptPrelude + script)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	buf := &safeBuf{}
	done := make(chan struct{})
	go func() { streamLines(pr, buf, log); close(done) }()
	err := cmd.Run()
	pw.Close()
	<-done
	return buf.String(), err
}

func (LocalHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tp-tmp.*") // its own name, as over SSH
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// ---------------- ssh ----------------

// uploadCmd stores stdin at path. The temporary file has a name of its own ($$): jobs
// running side by side on one server upload the same helper (tp-probe) at once, and with a
// shared name one's mv took the other's file from under its chmod.
func uploadCmd(path string, mode os.FileMode) string {
	return fmt.Sprintf(`mkdir -p %s && t=%s.$$ && { cat > "$t" && chmod %o "$t" && mv -f "$t" %s || { rm -f "$t"; exit 1; }; }`,
		shq(filepath.Dir(path)), shq(path+".tp-tmp"), mode, shq(path))
}

// dialFunc opens the TCP path to a server's sshd: direct, via proxy, via a jump host or via an agent.
type dialFunc func(addr string) (net.Conn, error)

type SSHHost struct {
	srv   *Server
	store *Store
	dial  dialFunc
	v6    bool // connect to the server's IPv6 address (the IPv4 path is down)
	mu    sync.Mutex
	cli   *ssh.Client
}

func newSSHHost(st *Store, srv *Server, dial dialFunc) *SSHHost {
	return &SSHHost{srv: srv, store: st, dial: dial}
}

func (h *SSHHost) Label() string { return "IR" }

func (h *SSHHost) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cli != nil {
		h.cli.Close()
		h.cli = nil
	}
}

// sshAddr6 is the server's SSH address over IPv6 ("" when it has none).
func (s *Server) sshAddr6() string {
	if s.IPv6 == "" {
		return ""
	}
	port := s.SSHPort
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(strings.Trim(s.IPv6, "[]"), strconv.Itoa(port))
}

func (s *Server) sshAddr() string {
	host := s.SSHHost
	if host == "" {
		host = s.IPv4
	}
	if host == "" {
		host = s.IPv6
	}
	port := s.SSHPort
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

func (h *SSHHost) sshConfig() (*ssh.ClientConfig, error) {
	var auths []ssh.AuthMethod
	if strings.TrimSpace(h.srv.PrivateKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(h.srv.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if h.srv.Password != "" {
		pw := h.srv.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range ans {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	if len(auths) == 0 {
		return nil, errors.New("no SSH password or key configured")
	}
	user := h.srv.SSHUser
	if user == "" {
		user = "root"
	}
	return &ssh.ClientConfig{
		User:    user,
		Auth:    auths,
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
			pinned := ""
			h.store.View(func(*State) { pinned = h.srv.HostKey })
			if pinned == "" {
				_ = h.store.Update(func(*State) error { h.srv.HostKey = fp; return nil })
				return nil
			}
			if pinned != fp {
				return errors.New("SSH host key changed (possible MITM) — reset the pinned key in the server settings if this is expected")
			}
			return nil
		},
	}, nil
}

func (h *SSHHost) client() (*ssh.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cli != nil {
		if _, _, err := h.cli.SendRequest("keepalive@tunnel-panel", true, nil); err == nil {
			return h.cli, nil
		}
		h.cli.Close()
		h.cli = nil
	}
	cfg, err := h.sshConfig()
	if err != nil {
		return nil, err
	}
	addr := h.srv.sshAddr()
	if h.v6 {
		addr = h.srv.sshAddr6()
	}
	conn, err := h.dial(addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	h.cli = ssh.NewClient(c, chans, reqs)
	return h.cli, nil
}

// alive reports whether the connection already open to the server answers a keepalive
// within a few seconds. It never connects: a closed or unanswering one is simply "no"
// (client() reconnects on the next use).
func (h *SSHHost) alive() bool {
	h.mu.Lock()
	cli := h.cli
	h.mu.Unlock()
	if cli == nil {
		return false
	}
	done := make(chan bool, 1)
	go func() {
		_, _, err := cli.SendRequest("keepalive@tunnel-panel", true, nil)
		done <- err == nil
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(sshTimeout):
		return false
	}
}

// Dial opens a TCP connection from this server's vantage point (for jump-host use).
func (h *SSHHost) Dial(addr string) (net.Conn, error) {
	cli, err := h.client()
	if err != nil {
		return nil, err
	}
	return cli.Dial("tcp", addr)
}

func (h *SSHHost) Run(ctx context.Context, script string, log func(string)) (string, error) {
	cli, err := h.client()
	if err != nil {
		return "", err
	}
	sess, err := cli.NewSession()
	if err != nil {
		h.Close()
		return "", err
	}
	defer sess.Close()
	user := h.srv.SSHUser
	cmd := "bash -s"
	if user != "" && user != "root" {
		cmd = "sudo -n bash -s"
	}
	sess.Stdin = strings.NewReader(scriptPrelude + script)
	pr, pw := io.Pipe()
	sess.Stdout = pw
	sess.Stderr = pw
	buf := &safeBuf{}
	done := make(chan struct{})
	go func() { streamLines(pr, buf, log); close(done) }()
	errc := make(chan error, 1)
	go func() { errc <- sess.Run(cmd) }()
	select {
	case err = <-errc:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		sess.Close()
		err = ctx.Err()
	}
	pw.Close()
	<-done
	return buf.String(), err
}

func (h *SSHHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	cli, err := h.client()
	if err != nil {
		return err
	}
	sess, err := cli.NewSession()
	if err != nil {
		h.Close()
		return err
	}
	defer sess.Close()
	cmd := uploadCmd(path, mode)
	if h.srv.SSHUser != "" && h.srv.SSHUser != "root" {
		cmd = "sudo -n sh -c " + shq(cmd)
	}
	sess.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.Run(cmd); err != nil {
		return fmt.Errorf("upload %s: %v %s", path, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
