//go:build !unix

package agent

import "os/exec"

// killGroup: no process groups here (the agent runs on Linux); a cancel kills the process.
func killGroup(cmd *exec.Cmd) {}
