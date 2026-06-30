package modules

import (
	"github.com/dimadr/infradoctor/internal/model"
)

// aggregateStatus derives the overall status from a set of sections.
func aggregateStatus(sections []model.Section) model.Status {
	s := model.StatusOK
	for _, sec := range sections {
		switch sec.Status {
		case model.StatusCritical:
			s = model.StatusCritical
		case model.StatusWarning:
			if s != model.StatusCritical {
				s = model.StatusWarning
			}
		}
	}
	return s
}

// collectRecommendations gathers recommendation messages from warning/critical checks.
func collectRecommendations(sections []model.Section) []string {
	var recs []string
	for _, sec := range sections {
		for _, c := range sec.Checks {
			if c.Status == model.StatusWarning || c.Status == model.StatusCritical {
				recs = append(recs, c.Message)
			}
		}
	}
	return recs
}
