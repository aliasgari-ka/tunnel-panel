//go:build linux

package pktfilter

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Apply narrows pid's packet sockets that carry the vendor's filter for s. Returns how many
// it narrowed and how many packet sockets have no filter yet (the core may still attach it).
func Apply(pid int, s Spec) (narrowed, waiting int, err error) {
	fds, err := packetFDs(pid)
	if err != nil || len(fds) == 0 {
		return 0, 0, err
	}
	pfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(pfd)
	for _, fd := range fds {
		nfd, err := unix.PidfdGetfd(pfd, fd, 0)
		if err != nil {
			continue // closed meanwhile
		}
		cur, gerr := getFilter(nfd)
		if gerr == nil {
			st, accept := Classify(s, cur)
			switch st {
			case NoFilter:
				waiting++
			case IsVendor:
				prog, perr := Narrow(s, accept)
				if perr == nil {
					perr = setFilter(nfd, prog)
				}
				if perr != nil {
					err = fmt.Errorf("fd %d: %w", fd, perr)
				} else {
					narrowed++
				}
			}
		}
		unix.Close(nfd)
	}
	return narrowed, waiting, err
}

// packetFDs lists pid's descriptors that are AF_PACKET sockets (their inodes are listed in
// /proc/net/packet of this network namespace).
func packetFDs(pid int) ([]int, error) {
	inodes := map[string]bool{}
	f, err := os.Open("/proc/net/packet")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fl := strings.Fields(sc.Text()); len(fl) >= 9 && fl[0] != "sk" {
			inodes[fl[len(fl)-1]] = true
		}
	}
	f.Close()
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, e := range ents {
		l, err := os.Readlink(dir + "/" + e.Name())
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		if inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] {
			if n, err := strconv.Atoi(e.Name()); err == nil {
				fds = append(fds, n)
			}
		}
	}
	return fds, nil
}

// getFilter reads the classic BPF filter attached to fd (SO_GET_FILTER: the length is in
// instructions, not bytes; a zero length asks for the count only).
func getFilter(fd int) ([]bpf.RawInstruction, error) {
	n := uint32(0)
	if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_GET_FILTER, 0, uintptr(unsafe.Pointer(&n)), 0); e != 0 {
		return nil, e
	}
	if n == 0 || n > 4096 {
		return nil, nil
	}
	buf := make([]unix.SockFilter, n)
	l := n
	if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_GET_FILTER, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0); e != 0 {
		return nil, e
	}
	if l < n {
		buf = buf[:l]
	}
	out := make([]bpf.RawInstruction, len(buf))
	for i, b := range buf {
		out[i] = bpf.RawInstruction{Op: b.Code, Jt: b.Jt, Jf: b.Jf, K: b.K}
	}
	return out, nil
}

func setFilter(fd int, prog []bpf.RawInstruction) error {
	fs := make([]unix.SockFilter, len(prog))
	for i, r := range prog {
		fs[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(fs)), Filter: &fs[0]})
}
