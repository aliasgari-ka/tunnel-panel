package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

// The Golden-GRE relay is compiled from C on every release, and two builds of the same source
// can differ byte for byte (the arm64 cross compiler is whichever the release machine had).
// Comparing the binaries made Repair rebuild Golden tunnels — cutting their users — after
// updates that never touched the relay (seen live: usa after fc09e2c). What counts is the
// source: its hash goes next to the binary on the server (golden-gre-relay.src) and Repair
// renews the relay only when that differs.

//go:embed third_party/golden-gre/golden-gre-relay.c third_party/golden-gre/monocypher.c third_party/golden-gre/monocypher.h
var goldenSrcFS embed.FS

// goldenRelaySrc identifies the relay's source (16 hex chars).
var goldenRelaySrc = func() string {
	h := sha256.New()
	for _, f := range []string{"golden-gre-relay.c", "monocypher.c", "monocypher.h"} {
		b, _ := goldenSrcFS.ReadFile("third_party/golden-gre/" + f)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}()
