package core

import (
	"fmt"

	"github.com/dimadr/infradoctor/internal/detect"
	"github.com/dimadr/infradoctor/internal/modules"
	"github.com/dimadr/infradoctor/internal/report"
	"github.com/dimadr/infradoctor/internal/ui"
)

// App is the top-level application that orchestrates diagnosis.
type App struct{}

// NewApp creates a new App.
func NewApp() *App {
	return &App{}
}

// Run executes the full diagnostic workflow.
func (a *App) Run() error {
	if err := CheckRoot(); err != nil {
		return err
	}

	osInfo := DetectOS()

	fmt.Println("InfraDoctor")
	fmt.Printf("OS: %s\n", osInfo.PrettyName)
	fmt.Printf("Kernel: %s\n", osInfo.Kernel)
	fmt.Printf("Hostname: %s\n", osInfo.Hostname)
	fmt.Println()

	registry := modules.NewRegistry()
	found := detect.Components(registry)

	if len(found) == 0 {
		fmt.Println("No known components detected.")
		return nil
	}

	selected, err := ui.AskSelection(found)
	if err != nil {
		return fmt.Errorf("selection: %w", err)
	}

	results := Run(selected)

	mdPath, err := report.WriteMD(osInfo, results)
	if err != nil {
		return fmt.Errorf("report md: %w", err)
	}
	fmt.Printf("Report written: %s\n", mdPath)

	jsonPath, err := report.WriteJSON(osInfo, results)
	if err != nil {
		return fmt.Errorf("report json: %w", err)
	}
	fmt.Printf("Report written: %s\n", jsonPath)

	return nil
}
