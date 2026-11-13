// Package pktfilter narrows the packet filter of the Backhaul Premium core's raw socket.
//
// The Premium core reads its ipx carrier with an AF_PACKET socket (ETH_P_ALL) on the
// interface toward the peer, and attaches a classic BPF filter that keeps only IPv4 packets
// of the carrier's protocol from the peer's address. For the default tcp carrier that is
// every TCP packet the peer server sends to this one — also the users' traffic of every
// other TCP path of the same two servers (BackPack, TP Tunnel, FRP…). Each of those packets
// is copied into the core's ring and handed to its userspace, where it fails decryption and
// is dropped. Seen live (2026-11-13, usa / IRAN-USA): an "idle" standby Premium path burned
// 30-90 % of a core while the users rode BackPack between the same servers; idle Premium
// paths on routes without other TCP traffic stayed at 2-5 %.
//
// The tcp carrier always runs 443 -> 443 (the panel's NOTRACK rules rely on it too), so the
// filter can also check both ports. The panel runs
//
//	tp-agent pktfilter -pid <core pid> -peer <peer IPv4> [-proto 6 -sport 443 -dport 443]
//
// after the core starts: it waits until the core has attached its own filter, takes a copy
// of the socket's descriptor (pidfd_getfd) and replaces that filter with the narrower one,
// only when it is exactly the vendor's known shape for this peer and protocol (anything
// else is left alone). The core keeps its socket and its carrier packets; only the
// packets that were never its own stop reaching it.
package pktfilter

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/bpf"
)

// Spec is what the carrier looks like on the wire.
type Spec struct {
	Peer         net.IP // the peer server's public IPv4
	Proto        uint8  // IP protocol of the carrier (6 = tcp)
	SPort, DPort uint16 // the carrier's ports as seen in packets from the peer
}

func (s Spec) peer32() (uint32, error) {
	v4 := s.Peer.To4()
	if v4 == nil {
		return 0, fmt.Errorf("peer %v is not an IPv4 address", s.Peer)
	}
	return binary.BigEndian.Uint32(v4), nil
}

// Vendor is the filter the Premium core attaches for spec (accept = its accept value):
// ethertype IPv4, the protocol, the peer as IPv4 source. Nothing about ports.
func Vendor(s Spec, accept uint32) ([]bpf.RawInstruction, error) {
	p, err := s.peer32()
	if err != nil {
		return nil, err
	}
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 5},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(s.Proto), SkipFalse: 3},
		bpf.LoadAbsolute{Off: 26, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: p, SkipFalse: 1},
		bpf.RetConstant{Val: accept},
		bpf.RetConstant{Val: 0},
	})
}

// Narrow is the vendor's filter plus the carrier's ports: IPv4, the protocol, from the
// peer, and (for the first fragment, which carries the TCP/UDP header) source and
// destination port. A later fragment has no ports and passes as before.
func Narrow(s Spec, accept uint32) ([]bpf.RawInstruction, error) {
	p, err := s.peer32()
	if err != nil {
		return nil, err
	}
	if s.SPort == 0 || s.DPort == 0 {
		return nil, fmt.Errorf("both carrier ports are needed")
	}
	// 14 = drop, 13 = accept
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},                                   // 0 ethertype
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 12},          // 1
		bpf.LoadAbsolute{Off: 23, Size: 1},                                   // 2 IP protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(s.Proto), SkipFalse: 10}, // 3
		bpf.LoadAbsolute{Off: 26, Size: 4},                                   // 4 IP source
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: p, SkipFalse: 8},                // 5
		bpf.LoadAbsolute{Off: 20, Size: 2},                                   // 6 flags + fragment offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 5},          // 7 a later fragment: as before
		bpf.LoadMemShift{Off: 14},                                            // 8 X = IP header length
		bpf.LoadIndirect{Off: 14, Size: 2},                                   // 9 source port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(s.SPort), SkipFalse: 3},  // 10
		bpf.LoadIndirect{Off: 16, Size: 2},                                   // 11 destination port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(s.DPort), SkipFalse: 1},  // 12
		bpf.RetConstant{Val: accept},                                         // 13
		bpf.RetConstant{Val: 0},                                              // 14
	})
}

// State says what to do with a socket that has filter cur.
type State int

const (
	NoFilter State = iota // the core hasn't attached its filter yet: wait (it would replace ours)
	IsVendor              // the vendor's filter for this spec: replace it
	IsNarrow              // already narrowed
	Other                 // something else: leave it alone
)

// Classify compares cur with the vendor's and the narrow filter for spec; accept is the
// accept value cur uses (0 when it has none).
func Classify(s Spec, cur []bpf.RawInstruction) (State, uint32) {
	if len(cur) == 0 {
		return NoFilter, 0
	}
	accept := uint32(0)
	for _, ins := range cur {
		if ins.Op == 0x06 && ins.K != 0 { // ret #k
			accept = ins.K
			break
		}
	}
	if accept == 0 {
		return Other, 0
	}
	if v, err := Vendor(s, accept); err == nil && same(v, cur) {
		return IsVendor, accept
	}
	if n, err := Narrow(s, accept); err == nil && same(n, cur) {
		return IsNarrow, accept
	}
	return Other, accept
}

func same(a, b []bpf.RawInstruction) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
