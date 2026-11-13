package pktfilter

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

// frame builds an Ethernet + IPv4 (+ TCP/UDP ports) frame.
func frame(ethType uint16, proto uint8, src string, ihl int, frag uint16, sport, dport uint16) []byte {
	b := make([]byte, 14+ihl*4+20)
	binary.BigEndian.PutUint16(b[12:], ethType)
	ip := b[14:]
	ip[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(ip[6:], frag)
	ip[9] = proto
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP("159.195.238.75").To4())
	l4 := ip[ihl*4:]
	binary.BigEndian.PutUint16(l4[0:], sport)
	binary.BigEndian.PutUint16(l4[2:], dport)
	return b
}

func run(t *testing.T, prog []bpf.RawInstruction, pkt []byte) bool {
	t.Helper()
	ins, ok := bpf.Disassemble(prog)
	if !ok {
		t.Fatal("program does not disassemble")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	n, err := vm.Run(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

var spec = Spec{Peer: net.ParseIP("81.12.32.18"), Proto: 6, SPort: 443, DPort: 443}

// The vendor's filter as `ss -0 -b` printed it on usa-kharej (peer IRAN-USA, tcp carrier).
var seenLive = []bpf.RawInstruction{
	{Op: 0x28, K: 12}, {Op: 0x15, Jf: 5, K: 2048}, {Op: 0x30, K: 23}, {Op: 0x15, Jf: 3, K: 6},
	{Op: 0x20, K: 26}, {Op: 0x15, Jf: 1, K: 1359749138}, {Op: 0x06, K: 4294967295}, {Op: 0x06, K: 0},
}

func TestVendorShapeIsTheOneSeenLive(t *testing.T) {
	st, acc := Classify(spec, seenLive)
	if st != IsVendor || acc != 0xffffffff {
		t.Fatalf("Classify(live vendor filter) = %v %x, want IsVendor", st, acc)
	}
	// another peer or protocol is not ours to touch
	other := spec
	other.Peer = net.ParseIP("51.255.47.161")
	if st, _ := Classify(other, seenLive); st != Other {
		t.Fatalf("filter for another peer classified %v", st)
	}
	other = spec
	other.Proto = 1
	if st, _ := Classify(other, seenLive); st != Other {
		t.Fatalf("filter for another protocol classified %v", st)
	}
	if st, _ := Classify(spec, nil); st != NoFilter {
		t.Fatalf("no filter classified %v", st)
	}
}

func TestNarrowKeepsOnlyTheCarrier(t *testing.T) {
	n, err := Narrow(spec, 0xffffffff)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := Classify(spec, n); st != IsNarrow {
		t.Fatalf("narrow filter classified %v", st)
	}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"carrier 443->443 from the peer", frame(0x0800, 6, "81.12.32.18", 5, 0, 443, 443), true},
		{"carrier with IP options", frame(0x0800, 6, "81.12.32.18", 7, 0, 443, 443), true},
		{"carrier, DF set", frame(0x0800, 6, "81.12.32.18", 5, 0x4000, 443, 443), true},
		{"a later fragment from the peer (no ports)", frame(0x0800, 6, "81.12.32.18", 5, 0x0010, 1, 2), true},
		{"BackPack reverse from the peer", frame(0x0800, 6, "81.12.32.18", 5, 0, 40080, 48542), false},
		{"peer to our 443 from another port", frame(0x0800, 6, "81.12.32.18", 5, 0, 51000, 443), false},
		{"peer from 443 to another port", frame(0x0800, 6, "81.12.32.18", 5, 0, 443, 51000), false},
		{"tcp 443->443 from someone else", frame(0x0800, 6, "1.2.3.4", 5, 0, 443, 443), false},
		{"udp 443->443 from the peer", frame(0x0800, 17, "81.12.32.18", 5, 0, 443, 443), false},
		{"IPv6 frame", frame(0x86dd, 6, "81.12.32.18", 5, 0, 443, 443), false},
		{"ARP", frame(0x0806, 0, "81.12.32.18", 5, 0, 0, 0), false},
	}
	v, _ := Vendor(spec, 0xffffffff)
	for _, c := range cases {
		if got := run(t, n, c.pkt); got != c.want {
			t.Errorf("narrow: %s: accepted=%v, want %v", c.name, got, c.want)
		}
		// everything the narrow filter keeps, the vendor's kept too: no carrier packet is lost
		if c.want && !run(t, v, c.pkt) {
			t.Errorf("vendor filter drops %s, which the narrow one keeps", c.name)
		}
	}
}

func TestNarrowNeedsPortsAndIPv4(t *testing.T) {
	if _, err := Narrow(Spec{Peer: net.ParseIP("81.12.32.18"), Proto: 6}, 1); err == nil {
		t.Fatal("no ports: want an error")
	}
	if _, err := Narrow(Spec{Peer: net.ParseIP("2001:db8::1"), Proto: 6, SPort: 443, DPort: 443}, 1); err == nil {
		t.Fatal("IPv6 peer: want an error")
	}
}
