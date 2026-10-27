//go:build linux

package ipvanish

import (
	"os/exec"
	"syscall"
)

// A runtime crash must not leave its privileged transport running unsupervised.
func configureChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
