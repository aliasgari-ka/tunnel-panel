//go:build unix

package agent

import (
	"os/exec"
	"syscall"
)

// killGroup runs cmd in a process group of its own and makes a cancel kill the whole group.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
