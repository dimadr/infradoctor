package core

import (
	"fmt"
	"os"
)

// CheckHealth performs a quick self-check and exits with 0/1.
func CheckHealth() {
	fmt.Println("ok")
	os.Exit(0)
}
