package probe

import (
	"net"
	"os"
	"strings"
	"testing"
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
}
