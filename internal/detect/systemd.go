package detect

import (
	"os/exec"
)

// HasBinary checks if a binary exists in PATH.
func HasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// HasSystemd checks if systemd is the init system.
func HasSystemd() bool {
	return HasBinary("systemctl")
}
