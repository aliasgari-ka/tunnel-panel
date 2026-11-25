//go:build !linux

package main

import "syscall"

// gemMarkCtl: no socket marks off Linux (tests on other systems).
func gemMarkCtl(_, _ string, _ syscall.RawConn) error { return nil }
