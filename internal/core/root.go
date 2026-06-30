package core

import (
	"fmt"
	"os"
)

// CheckRoot exits if not running as root.
func CheckRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root")
	}
	return nil
}
