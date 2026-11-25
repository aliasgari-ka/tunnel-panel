//go:build linux

package main

import "syscall"

// gemMarkCtl marks the account's sockets 255 like the agent's own outbounds: the agent rejects
// unmarked IPv6 to ports 80/443 (so programs fall back to IPv4, where it catches them).
func gemMarkCtl(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 255)
	}); err != nil {
		return err
	}
	return serr
}
