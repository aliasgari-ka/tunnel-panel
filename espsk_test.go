package main

import (
	"strings"
	"testing"
)

// The static-key ESP method builds a route-based XFRM tunnel with the keys installed by
// hand (no IKE), the same keys and SPIs on both ends, and tears its own SAs/policies down
// without touching other IPsec on the host.
func TestESPStaticKeyBuild(t *testing.T) {
	srv := &Server{ID: "ir", IPv4: "81.12.35.113", IPv6: "2a05:9080::1"}
	fsrv := &Server{ID: "kh", IPv4: "51.68.197.222", IPv6: "2001:41d0::1", Role: "foreign"}
	tn := &Tunnel{ID: "t1", Name: "uk", ServerID: "ir", ForeignID: "kh", Family: "v4", Ports: "443", Index: 2}

	ir, kh, err := buildPlans(methodESPStaticKey, tn, srv, fsrv, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	irUp := scriptBody(ir, "/up.sh")
	khUp := scriptBody(kh, "/up.sh")
	irDown := scriptBody(ir, "/down.sh")

	// the XFRM interface for this index, and raw ESP state with an AEAD key — no IKE/UDP
	for _, want := range []string{"ip link add tp2 type xfrm", "if_id 42002", "proto esp spi 0x10002", "proto esp spi 0x20002", "rfc4106(gcm(aes))", "mode tunnel"} {
		if !strings.Contains(irUp, want) {
			t.Errorf("Iran up.sh missing %q", want)
		}
	}
	// both ends install the same two SAs (same src/dst/spi), so the keys match
	for _, spi := range []string{"spi 0x10002", "spi 0x20002"} {
		if strings.Count(irUp, spi) != strings.Count(khUp, spi) || strings.Count(irUp, spi) == 0 {
			t.Errorf("SA %q not defined identically on both ends", spi)
		}
	}
	// the two ends send with opposite out-policy templates
	if !strings.Contains(irUp, "dir out src 0.0.0.0/0 dst 0.0.0.0/0 if_id 42002 tmpl src 81.12.35.113 dst 51.68.197.222") {
		t.Error("Iran out policy should tunnel Iran→foreign")
	}
	if !strings.Contains(khUp, "dir out src 0.0.0.0/0 dst 0.0.0.0/0 if_id 42002 tmpl src 51.68.197.222 dst 81.12.35.113") {
		t.Error("foreign out policy should tunnel foreign→Iran")
	}
	// teardown removes only our own SAs and policies (by spi / selector+if_id), not a flush
	for _, want := range []string{"state deleteall src 51.68.197.222 dst 81.12.35.113 proto esp spi 0x10002", "policy delete dir $dir src 0.0.0.0/0 dst 0.0.0.0/0 if_id 42002"} {
		if !strings.Contains(irDown, want) {
			t.Errorf("down.sh missing precise cleanup %q", want)
		}
	}
	if strings.Contains(irDown, "xfrm state flush") || strings.Contains(irDown, "xfrm policy flush") {
		t.Error("teardown must not flush all IPsec on the host")
	}

	// both AEAD keys (one per direction) are 40-hex (AES-GCM-128 key+salt), differ, and are
	// the same on both ends (so the SAs match within a deploy)
	keys := aeadKeys(irUp)
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("want two distinct 40-hex keys, got %v", keys)
	}
	for _, k := range keys {
		if len(k) != 40 || !strings.Contains(khUp, k) {
			t.Errorf("key %q (len %d) not 40-hex or not shared with the foreign end", k, len(k))
		}
	}

	// classified like the other kernel L3 tunnels
	if !benchIsL3(methodESPStaticKey, nil) {
		t.Error("espsk should be an L3 method")
	}
	if userspaceIran(methodESPStaticKey, tn) {
		t.Error("espsk is a kernel tunnel; the kernel DNATs user ports, not a daemon")
	}
}

// aeadKeys pulls the hex keys out of "aead 'rfc4106(gcm(aes))' 0x<hex> 128" lines.
func aeadKeys(sh string) []string {
	var out []string
	for _, ln := range strings.Split(sh, "\n") {
		a := strings.Index(ln, "aead ")
		if a < 0 {
			continue
		}
		i := strings.Index(ln[a:], "0x") // the key's 0x, after the aead cipher name
		if i < 0 {
			continue
		}
		rest := ln[a+i+2:]
		if j := strings.IndexByte(rest, ' '); j > 0 {
			out = append(out, rest[:j])
		}
	}
	return out
}

func scriptBody(p SidePlan, suffix string) string {
	for path, f := range p.Files {
		if strings.HasSuffix(path, suffix) {
			return string(f.Content)
		}
	}
	return ""
}
