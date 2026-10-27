//go:build !linux

package ovpn

import "os/exec"

// The provider runtime requires Linux; keep control/API tests portable.
func configureChild(cmd *exec.Cmd) {}
