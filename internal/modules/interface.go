package modules

import (
	"context"

	"github.com/dimadr/infradoctor/internal/model"
)

type Module interface {
	ID() string
	Name() string
	Detect() bool
	Diagnose(ctx context.Context) model.Result
}
