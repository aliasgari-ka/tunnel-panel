// Package probe measures a path end to end over TCP, so the benchmark works the same
// through L3 tunnels (to the peer's tunnel IP) and port forwarders (to a forwarded port).
//
//	tp-agent probe serve -listen :41002 -life 120     # on the foreign side
//	tp-agent probe rtt   -addr 10.10.250.2:41002 -n 20
//	tp-agent probe bw    -addr 127.0.0.1:41002 -secs 5 [-down] [-max 8]
//	tp-agent probe check -addr 10.10.3.2:49003 -n 2 [-ping 10.10.3.2]   # "ok <rtt ms> <jitter ms> <loss %|-1>" or "down"
//	tp-agent probe speed -addr 127.0.0.1:50079 -max 2 -secs 8          # download kbit/s, plain
//
// Wire: the client sends one mode byte. 'E' = echo everything back. 'B' + one byte of
// seconds = the server counts what it receives for that long (from the first byte) and
// answers "<bytes> <seconds>\n", so throughput is measured on the receiving end and
// buffers in the tunnel do not inflate it. 'D' + seconds = the server sends for that
// long and the client measures (download direction, foreign -> Iran). 'L' + seconds + 4
// bytes of KiB (big endian) = like 'D', but at most that much (-max: tests that must not
// cost the servers much traffic). 'C' + seconds + 4 bytes of KiB = like 'B', but the server
// also stops at that many bytes and answers on the open connection: a half-close (FIN) to
// end the upload is dropped or turned into a reset by many port forwarders (Backhaul, FRP,
// BackPack), and the report never came back.
package probe

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// Main runs one probe subcommand and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: probe serve|rtt|bw ...")
		return 2
	}
	fs := flag.NewFlagSet("probe "+args[0], flag.ContinueOnError)
	listen := fs.String("listen", ":41002", "serve: listen address")
	life := fs.Int("life", 120, "serve: exit after this many seconds")
	addr := fs.String("addr", "", "rtt/bw: target host:port")
	n := fs.Int("n", 20, "rtt: number of echoes")
	secs := fs.Int("secs", 5, "bw: seconds to send")
	down := fs.Bool("down", false, "bw: measure the far end sending to us")
	maxMB := fs.Float64("max", 0, "bw/speed: stop after this many MB (0 = only the time limit)")
	pingH := fs.String("ping", "", "check: also ping this host for packet loss")
	pn := fs.Int("pn", 10, "check: pings to send")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	var res any
	var err error
	switch args[0] {
	case "serve":
		err = serve(*listen, time.Duration(*life)*time.Second)
	case "rtt":
		res, err = rtt(*addr, *n)
	case "bw":
		if *down {
			res, err = bwDown(*addr, *secs, maxBytes(*maxMB))
		} else {
			res, err = bw(*addr, *secs, maxBytes(*maxMB))
		}
	case "check": // plain output, for shell scripts
		fmt.Println(check(*addr, *n, *pingH, *pn))
		return 0
	case "speed":
		r, err := bwDown(*addr, *secs, maxBytes(*maxMB))
		if err != nil || r.Secs <= 0 {
			fmt.Println(0)
			return 1
		}
		fmt.Println(int64(r.Mbps * 1000))
		return 0
	default:
		err = fmt.Errorf("unknown probe %q", args[0])
	}
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
		return 1
	}
	if res != nil {
		_ = json.NewEncoder(os.Stdout).Encode(res)
	}
	return 0
}

func serve(listen string, life time.Duration) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	time.AfterFunc(life, func() { ln.Close() })
	for {
		c, err := ln.Accept()
		if err != nil {
			return nil // closed by the life timer
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	var hdr [1]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	switch hdr[0] {
	case 'E':
		_, _ = io.Copy(c, c)
	case 'B', 'C':
		var s [1]byte
		if _, err := io.ReadFull(c, s[:]); err != nil {
			return
		}
		limit := int64(math.MaxInt64)
		if hdr[0] == 'C' {
			var kb [4]byte
			if _, err := io.ReadFull(c, kb[:]); err != nil {
				return
			}
			limit = int64(binary.BigEndian.Uint32(kb[:])) << 10
		}
		dur := time.Duration(s[0]) * time.Second
		buf := make([]byte, 256<<10)
		var total int64
		var start time.Time
		for total < limit {
			if !start.IsZero() {
				_ = c.SetReadDeadline(start.Add(dur))
			}
			k, err := c.Read(buf)
			if k > 0 && start.IsZero() {
				start = time.Now()
			}
			total += int64(k)
			if err != nil {
				break
			}
		}
		el := 0.0
		if !start.IsZero() {
			el = time.Since(start).Seconds()
		}
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(c, "%d %.4f\n", total, el)
		// end gracefully: closing with unread data in the socket sends a reset, which can
		// overtake the report on its way through a forwarder
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		// (the client closes once it has the report; on a slow path the forwarder may still
		// be delivering buffered data, so give it time)
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, _ = io.Copy(io.Discard, c)
	case 'D', 'L':
		var s [1]byte
		if _, err := io.ReadFull(c, s[:]); err != nil {
			return
		}
		limit := int64(math.MaxInt64)
		if hdr[0] == 'L' {
			var kb [4]byte
			if _, err := io.ReadFull(c, kb[:]); err != nil {
				return
			}
			limit = int64(binary.BigEndian.Uint32(kb[:])) << 10
		}
		end := time.Now().Add(time.Duration(s[0]) * time.Second)
		buf := make([]byte, 64<<10)
		for sent := int64(0); sent < limit && time.Now().Before(end); {
			k := int64(len(buf))
			if limit-sent < k {
				k = limit - sent
			}
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(buf[:k]); err != nil {
				return
			}
			sent += k
		}
	}
}

// RTTResult is the outcome of an echo series.
type RTTResult struct {
	ConnectMs float64 `json:"connectMs"`
	RTTms     float64 `json:"rttMs"`
	Jitterms  float64 `json:"jitterMs"`
	Sent      int     `json:"sent"`
	Received  int     `json:"received"`
}

func rtt(addr string, n int) (*RTTResult, error) {
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	r := &RTTResult{ConnectMs: ms(time.Since(t0))}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if _, err := c.Write([]byte{'E'}); err != nil {
		return nil, err
	}
	msg := make([]byte, 64)
	back := make([]byte, 64)
	var samples []float64
	for i := 0; i < n; i++ {
		r.Sent++
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		t := time.Now()
		if _, err := c.Write(msg); err != nil {
			break
		}
		if _, err := io.ReadFull(c, back); err != nil {
			break // a stalled stream will not recover inside the window
		}
		samples = append(samples, ms(time.Since(t)))
		r.Received++
		time.Sleep(100 * time.Millisecond)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("connected but no echo came back through the tunnel")
	}
	// drop the first sample: it often pays for lazy stream setup in muxed tunnels
	if len(samples) > 3 {
		samples = samples[1:]
	}
	var sum float64
	for _, s := range samples {
		sum += s
	}
	r.RTTms = sum / float64(len(samples))
	var dev float64
	for _, s := range samples {
		dev += math.Abs(s - r.RTTms)
	}
	r.Jitterms = dev / float64(len(samples))
	return r, nil
}

// BWResult is the receiver-measured throughput.
type BWResult struct {
	Bytes int64   `json:"bytes"`
	Secs  float64 `json:"secs"`
	Mbps  float64 `json:"mbps"`
}

func maxBytes(mb float64) int64 {
	if mb <= 0 {
		return 0
	}
	return int64(mb * (1 << 20))
}

func bw(addr string, secs int, max int64) (*BWResult, error) {
	if secs < 1 {
		secs = 1
	}
	if secs > 60 {
		secs = 60
	}
	c, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req := []byte{'B', byte(secs)}
	if max > 0 {
		// the far end stops counting at max and reports on the open connection (no half-close)
		req = []byte{'C', byte(secs), 0, 0, 0, 0}
		binary.BigEndian.PutUint32(req[2:], uint32(max>>10))
	}
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	type reply struct {
		line string
		err  error
	}
	got := make(chan reply, 1)
	go func() {
		l, err := bufio.NewReader(c).ReadString('\n')
		got <- reply{l, err}
	}()
	buf := make([]byte, 64<<10)
	start := time.Now()
	deadline := start.Add(time.Duration(secs+15) * time.Second)
	sent := int64(0)
	for {
		// enough sent, or the far end's counting window is over: stop sending (more data would
		// only pile up unread and get the connection reset) and wait for its report
		if (max > 0 && sent >= max) || (max > 0 && time.Since(start) > time.Duration(secs)*time.Second+500*time.Millisecond) {
			select {
			case rp := <-got:
				return parseBW(rp.line, fmt.Errorf("no throughput report from the far end (%v)", rp.err))
			case <-time.After(time.Until(deadline)):
				return nil, fmt.Errorf("throughput test timed out")
			}
		}
		select {
		case rp := <-got:
			return parseBW(rp.line, fmt.Errorf("no throughput report from the far end (%v)", rp.err))
		default:
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("throughput test timed out")
		}
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		k, err := c.Write(buf)
		sent += int64(k)
		if err != nil {
			// the server stops reading at the end of its window; wait for its report
			select {
			case rp := <-got:
				return parseBW(rp.line, fmt.Errorf("send failed: %v", err))
			case <-time.After(10 * time.Second):
				return nil, fmt.Errorf("send failed: %v", err)
			}
		}
	}
}

// bwDown asks the far end to send for secs and measures what arrives.
func bwDown(addr string, secs int, max int64) (*BWResult, error) {
	if secs < 1 {
		secs = 1
	}
	if secs > 60 {
		secs = 60
	}
	c, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req := []byte{'D', byte(secs)}
	if max > 0 {
		req = []byte{'L', byte(secs), 0, 0, 0, 0}
		binary.BigEndian.PutUint32(req[2:], uint32((max+1023)>>10))
	}
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 256<<10)
	var r BWResult
	var first, last time.Time
	hard := time.Now().Add(time.Duration(secs+15) * time.Second)
	for {
		_ = c.SetReadDeadline(minTime(time.Now().Add(5*time.Second), hard))
		k, err := c.Read(buf)
		if k > 0 {
			if first.IsZero() {
				first = time.Now()
			}
			last = time.Now()
			r.Bytes += int64(k)
		}
		if err != nil {
			break
		}
	}
	if r.Bytes == 0 {
		return nil, fmt.Errorf("nothing arrived from the far end")
	}
	r.Secs = last.Sub(first).Seconds()
	if r.Secs > 0 {
		r.Mbps = float64(r.Bytes) * 8 / r.Secs / 1e6
	}
	return &r, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func parseBW(line string, failErr error) (*BWResult, error) {
	var r BWResult
	if _, err := fmt.Sscanf(line, "%d %f", &r.Bytes, &r.Secs); err != nil {
		return nil, failErr
	}
	if r.Secs > 0 {
		r.Mbps = float64(r.Bytes) * 8 / r.Secs / 1e6
	}
	return &r, nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// check is one switcher check: a TCP echo through the path and, with pingHost, the packet
// loss of pn pings (-1 when ICMP is filtered: no ping answered while the echo did).
func check(addr string, n int, pingHost string, pn int) string {
	r, err := rtt(addr, n)
	if err != nil {
		return "down"
	}
	loss := -1
	if pingHost != "" {
		if l, ok := ping(pingHost, pn); ok && l < 100 {
			loss = l
		}
	}
	return fmt.Sprintf("ok %d %d %d", int(math.Round(r.RTTms)), int(math.Round(r.Jitterms)), loss)
}

var lossRE = regexp.MustCompile(`([0-9.]+)% packet loss`)

// ping sends n ICMP echoes itself (raw socket, root) and returns the loss in percent; it
// falls back to the system ping where raw sockets aren't allowed.
func ping(host string, n int) (int, bool) {
	if n < 1 {
		n = 1
	}
	if l, ok := rawPing(host, n); ok {
		return l, true
	}
	out, _ := exec.Command("ping", "-n", "-c", strconv.Itoa(n), "-i", "0.2", "-W", "1", host).CombinedOutput()
	m := lossRE.FindSubmatch(out)
	if m == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		return 0, false
	}
	return int(math.Round(f)), true
}

func rawPing(host string, n int) (int, bool) {
	ip := net.ParseIP(host)
	if ip == nil {
		return 0, false
	}
	v4 := ip.To4() != nil
	network, typ, reply := "ip4:icmp", byte(8), byte(0)
	if !v4 {
		network, typ, reply = "ip6:ipv6-icmp", 128, 129
	}
	c, err := net.ListenPacket(network, "")
	if err != nil {
		return 0, false
	}
	defer c.Close()
	id := uint16(os.Getpid() & 0xffff)
	got := map[uint16]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			k, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			b := buf[:k]
			if v4 && len(b) >= 20 && b[0]>>4 == 4 { // some kernels hand the IP header over too
				b = b[int(b[0]&0x0f)*4:]
			}
			if len(b) >= 8 && b[0] == reply && binary.BigEndian.Uint16(b[4:]) == id {
				if a, ok := from.(*net.IPAddr); ok && a.IP.Equal(ip) {
					got[binary.BigEndian.Uint16(b[6:])] = true
				}
			}
		}
	}()
	dst := &net.IPAddr{IP: ip}
	for seq := 1; seq <= n; seq++ {
		msg := make([]byte, 64)
		msg[0] = typ
		binary.BigEndian.PutUint16(msg[4:], id)
		binary.BigEndian.PutUint16(msg[6:], uint16(seq))
		if v4 { // ICMPv6 checksums are filled in by the kernel
			binary.BigEndian.PutUint16(msg[2:], icmpSum(msg))
		}
		if _, err := c.WriteTo(msg, dst); err != nil {
			return 0, false
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	<-done
	return (n - len(got)) * 100 / n, true
}

func icmpSum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}
