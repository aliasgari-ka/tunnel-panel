// Package probe measures a path end to end over TCP, so the benchmark works the same
// through L3 tunnels (to the peer's tunnel IP) and port forwarders (to a forwarded port).
//
//	tp-agent probe serve -listen :41002 -life 120     # on the foreign side
//	tp-agent probe rtt   -addr 10.10.250.2:41002 -n 20
//	tp-agent probe bw    -addr 127.0.0.1:41002 -secs 5 [-down]
//
// Wire: the client sends one mode byte. 'E' = echo everything back. 'B' + one byte of
// seconds = the server counts what it receives for that long (from the first byte) and
// answers "<bytes> <seconds>\n", so throughput is measured on the receiving end and
// buffers in the tunnel do not inflate it. 'D' + seconds = the server sends for that
// long and the client measures (download direction, foreign -> Iran).
package probe

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
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
			res, err = bwDown(*addr, *secs)
		} else {
			res, err = bw(*addr, *secs)
		}
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
	case 'B':
		var s [1]byte
		if _, err := io.ReadFull(c, s[:]); err != nil {
			return
		}
		dur := time.Duration(s[0]) * time.Second
		buf := make([]byte, 256<<10)
		var total int64
		var start time.Time
		for {
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
	case 'D':
		var s [1]byte
		if _, err := io.ReadFull(c, s[:]); err != nil {
			return
		}
		end := time.Now().Add(time.Duration(s[0]) * time.Second)
		buf := make([]byte, 64<<10)
		for time.Now().Before(end) {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(buf); err != nil {
				return
			}
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

func bw(addr string, secs int) (*BWResult, error) {
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
	if _, err := c.Write([]byte{'B', byte(secs)}); err != nil {
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
	deadline := time.Now().Add(time.Duration(secs+15) * time.Second)
	for {
		select {
		case rp := <-got:
			return parseBW(rp.line, fmt.Errorf("no throughput report from the far end (%v)", rp.err))
		default:
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("throughput test timed out")
		}
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(buf); err != nil {
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
func bwDown(addr string, secs int) (*BWResult, error) {
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
	if _, err := c.Write([]byte{'D', byte(secs)}); err != nil {
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
