package modules

import (
	"context"

	"github.com/dimadr/infradoctor/internal/model"
)

// Module is the interface for all diagnostic modules.
// Each module implements ID, Name, Detect (is the component present),
// and Diagnose (run checks and return results).
type Module interface {
	ID() string
	Name() string
	Detect() bool
	Diagnose(ctx context.Context) model.Result
}
