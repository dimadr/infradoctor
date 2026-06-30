package ui

import (
	"fmt"

	"github.com/dimadr/infradoctor/internal/modules"
)

// ShowMenu prints the numbered list of detected components.
func ShowMenu(items []modules.Module) {
	fmt.Println("Detected components:")
	for i, m := range items {
		fmt.Printf("  [%d] %s\n", i+1, m.Name())
	}
	fmt.Println()
}
