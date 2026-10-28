package main

import "testing"

// Only a definite failure gets a hot-standby tunnel applied again: the switcher answered and
// the users' path is dead, or its files are gone. A switcher the panel can't reach (SSH
// flaky, server busy) is never a reason to rebuild a tunnel that may well be carrying users.
func TestHSRebuildable(t *testing.T) {
	for reason, want := range map[string]bool{
		"tunnel link down (no traffic between the servers)":                    true,
		"Iran service switcher state unreadable: Process exited with status 3": true,
		"Iran service switcher state unreadable: ssh: handshake failed: EOF":   false,
		"Iran service switcher state unreadable: context deadline exceeded":    false,
		"Iran server unreachable":    false,
		"foreign server unreachable": false,
		"":                           false,
		"tunnel link down (no traffic between the servers) — the Premium license…": true,
	} {
		if got := hsRebuildable(reason); got != want {
			t.Errorf("hsRebuildable(%q) = %v, want %v", reason, got, want)
		}
	}
}
