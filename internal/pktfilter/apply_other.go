//go:build !linux

package pktfilter

import "errors"

// Apply needs Linux (pidfd_getfd, AF_PACKET).
func Apply(pid int, s Spec) (narrowed, waiting int, err error) {
	return 0, 0, errors.New("pktfilter works on Linux only")
}
