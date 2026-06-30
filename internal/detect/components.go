package detect

import (
	"github.com/dimadr/infradoctor/internal/modules"
)

func Components(registry *modules.Registry) []modules.Module {
	var found []modules.Module
	for _, m := range registry.All() {
		if m.Detect() {
			found = append(found, m)
		}
	}
	return found
}
