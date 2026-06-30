package core

import (
	"context"
	"fmt"

	"github.com/dimadr/infradoctor/internal/model"
	"github.com/dimadr/infradoctor/internal/modules"
)

// Run executes Diagnose on each selected module and returns results.
func Run(selected []modules.Module) []model.Result {
	ctx := context.Background()
	var results []model.Result

	for _, m := range selected {
		fmt.Printf("  Diagnosing %s...\n", m.Name())
		r := m.Diagnose(ctx)
		results = append(results, r)
	}

	return results
}
