package probe

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCappedTests(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	addr := ln.Addr().String()
	go func() { _ = serve(addr, 30e9) }()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
	}
	dn, err := bwDown(addr, 10, 1<<20)
	if err != nil || dn.Bytes != 1<<20 {
		t.Fatalf("capped download: %+v %v (want exactly 1 MiB)", dn, err)
	}
	up, err := bw(addr, 10, 1<<20)
	if err != nil || up.Bytes < 1<<20 || up.Bytes > 1<<20+64<<10 {
		t.Fatalf("capped upload: %+v %v", up, err)
	}
	if r := check(addr, 2, "", 0); !strings.HasPrefix(r, "ok ") || !strings.HasSuffix(r, " -1") {
		t.Errorf("check: %q", r)
	}
	if os.Geteuid() == 0 {
		if l, ok := rawPing("127.0.0.1", 3); !ok || l != 0 {
			t.Errorf("raw ping of loopback: loss %d ok %v", l, ok)
		}
		if r := check(addr, 2, "127.0.0.1", 3); !strings.HasSuffix(r, " 0") {
			t.Errorf("check with ping: %q", r)
		}
	}
	if r := check("127.0.0.1:1", 2, "", 0); r != "down" {
		t.Errorf("check of a closed port: %q", r)
	}

	// through a forwarder that tears the whole connection down when the client half-closes
	// (as Backhaul / FRP / BackPack reverse did): the capped upload still gets its report
	fw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fw.Close()
	go func() {
		for {
			in, err := fw.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", addr)
			if err != nil {
				in.Close()
				return
			}
			go func() { _, _ = io.Copy(in, out); in.Close(); out.Close() }()
			go func() { _, _ = io.Copy(out, in); in.Close(); out.Close() }()
		}
	}()
	up, err = bw(fw.Addr().String(), 10, 1<<20)
	if err != nil || up.Bytes < 1<<20 || up.Mbps <= 0 {
		t.Fatalf("capped upload through a forwarder: %+v %v", up, err)
	}

	// a slow forwarder (≈2 Mbit/s, like a weak route): the 8 MB cap is never reached within
	// the 1 s window; the upload still ends with a report instead of a reset
	slow, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	go func() {
		for {
			in, err := slow.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", addr)
			if err != nil {
				in.Close()
				return
			}
			go func() { _, _ = io.Copy(in, out); in.Close(); out.Close() }()
			go func() {
				buf := make([]byte, 16<<10)
				for {
					n, err := in.Read(buf)
					if n > 0 {
						if _, werr := out.Write(buf[:n]); werr != nil {
							break
						}
						time.Sleep(60 * time.Millisecond) // ~2 Mbit/s
					}
					if err != nil {
						break
					}
				}
				in.Close()
				out.Close()
			}()
		}
	}()
	up, err = bw(slow.Addr().String(), 1, 8<<20)
	if err != nil || up.Bytes == 0 || up.Mbps <= 0 || up.Mbps > 20 {
		t.Fatalf("capped upload through a slow forwarder: %+v %v", up, err)
	}

	// a forwarder that, like Backhaul, tears the whole connection down (reset) as soon as the
	// far end half-closes: the report must arrive before any such close
	rst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rst.Close()
	go func() {
		for {
			in, err := rst.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", addr)
			if err != nil {
				in.Close()
				return
			}
			go func() {
				// replies take 100 ms through the "tunnel"; a FIN from the far end resets the
				// client at once and drops what is still on its way (as Backhaul did)
				type chunk []byte
				q := make(chan chunk, 64)
				go func() {
					for b := range q {
						time.Sleep(100 * time.Millisecond)
						if _, err := in.Write(b); err != nil {
							return
						}
					}
				}()
				buf := make([]byte, 32<<10)
				for {
					n, err := out.Read(buf)
					if n > 0 {
						q <- append(chunk(nil), buf[:n]...)
					}
					if err != nil {
						break
					}
				}
				if tc, ok := in.(*net.TCPConn); ok {
					_ = tc.SetLinger(0) // reset, not FIN
				}
				in.Close()
				out.Close()
			}()
			go func() { _, _ = io.Copy(out, in); out.Close() }()
		}
	}()
	up, err = bw(rst.Addr().String(), 1, 8<<20)
	if err != nil || up.Bytes == 0 {
		t.Fatalf("capped upload through a forwarder that resets on half-close: %+v %v", up, err)
	}
}
