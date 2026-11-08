package main

import "testing"

// Methods whose closed core exists for one CPU only run it under emulation elsewhere
// (provision.go), so the UI must ask for that one build, not one per server arch.
func TestHelperArch(t *testing.T) {
	for id, want := range map[string]string{"premium": "amd64", "tpk": "amd64", "tpk_rev": "amd64"} {
		m := methodByID[id]
		if m == nil {
			t.Fatalf("no method %s", id)
		}
		if m.HelperArch != want {
			t.Errorf("%s: HelperArch %q, want %q", id, m.HelperArch, want)
		}
	}
}
