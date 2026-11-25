package main

// The test account's own IPv6 address on the panel host.
//
// On 2026-11-25 Google no longer placed the host's IPv4 152.53.86.103 in any country: the
// keyless Gemini page named "google.com" there, and the signed-in app said "Gemini isn't
// currently supported in your country". The host's IPv6 /64 still read Germany (".de"). So the
// account leaves from one fixed address of that /64, gemHomeV6IID, that nothing else uses:
//   - not the agent's IPv6 pool (16 random /128s for the users' Google),
//   - not the host's main address (its own IPv6 traffic),
//   - never a default source: it is added with preferred_lft 0, so the kernel picks it only for
//     a socket bound to it, which is gemOwn (gemjar.go) alone.
// After a reboot the address is gone; the account loop adds it again every gemAcctTick.

import (
	"context"
	"net"
	"os/exec"
	"sync/atomic"
	"time"
)

// gemHomeV6IID: the interface id of the account's address in the host's /64 ("gmhome1").
var gemHomeV6IID = [8]byte{0x00, 0x67, 0x6d, 0x68, 0x6f, 0x6d, 0x65, 0x31}

var gemHomeV6IP atomic.Pointer[net.IP]

// gemHomeV6: the account's IPv6 address (nil = none: the account uses the host's IPv4 relay).
func gemHomeV6() net.IP {
	if p := gemHomeV6IP.Load(); p != nil {
		return *p
	}
	return nil
}

// gemHomeV6Addr: the account's address in the /64 of a global IPv6 (nil if it is no global
// unicast IPv6 address).
func gemHomeV6Addr(ip net.IP) net.IP {
	if ip == nil || ip.To4() != nil || ip.To16() == nil || !ip.IsGlobalUnicast() {
		return nil
	}
	a := make(net.IP, 16)
	copy(a, ip.To16()[:8])
	copy(a[8:], gemHomeV6IID[:])
	return a
}

// gemHomeV6Ensure finds the home host's /64 and puts the account's address on its interface. It
// does nothing on any other host (a panel elsewhere, a test machine).
func gemHomeV6Ensure() {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, it := range ifs {
		addrs, err := it.Addrs()
		if err != nil {
			continue
		}
		home, have := false, false
		var want net.IP
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if n.IP.To4() != nil {
				home = home || n.IP.String() == gemHomeHost()
				continue
			}
			if ones, bits := n.Mask.Size(); bits == 128 && ones == 64 && want == nil {
				want = gemHomeV6Addr(n.IP)
			}
		}
		if !home {
			continue
		}
		if want == nil {
			gemHomeV6IP.Store(nil)
			return
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(want) {
				have = true
			}
		}
		if !have {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := exec.CommandContext(ctx, "ip", "-6", "addr", "add", want.String()+"/128", "dev", it.Name, "nodad", "preferred_lft", "0").Run()
			cancel()
			if err != nil {
				gemHomeV6IP.Store(nil)
				return
			}
		}
		gemHomeV6IP.Store(&want)
		return
	}
}

// gemHomeDesc: where the account goes out, in words.
func gemHomeDesc() string {
	if ip := gemHomeV6(); ip != nil {
		return "the panel host's own IPv6 " + ip.String() + " (the test account's alone)"
	}
	return gemHomeV4Relay + " (the panel host's own IPv4)"
}
