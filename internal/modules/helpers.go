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

// buildRecommendation creates a structured Recommendation with full context.
func buildRecommendation(code string, severity model.Status, title, context, impact, action, command string, safe bool) model.Recommendation {
	return model.Recommendation{
		Code:     code,
		Severity: severity,
		Title:    title,
		Context:  context,
		Impact:   impact,
		Action:   action,
		Command:  command,
		Safe:     safe,
	}
}

// flatRec creates a flat Recommendation from a check message.
func flatRec(severity model.Status, code, title string) model.Recommendation {
	return model.Recommendation{
		Code:     code,
		Severity: severity,
		Title:    title,
		Safe:     false,
	}
}

// addFlatRecs adds flat recommendations for warning/critical checks not covered
// by manual recommendations. skipCodes are codes that identify checks
// with existing manual recs.
func addFlatRecs(checks []model.Check, skipCodes []string) []model.Recommendation {
	var recs []model.Recommendation
	for _, c := range checks {
		if c.Status != model.StatusWarning && c.Status != model.StatusCritical {
			continue
		}
		skip := false
		for _, code := range skipCodes {
			if c.Code == code {
				skip = true
				break
			}
		}
		if !skip {
			recs = append(recs, flatRec(c.Status, c.Code, c.Message))
		}
	}
	return recs
}

// addFlatRecsFromSections is addFlatRecs over multiple sections, keyed by section name.
func addFlatRecsFromSections(sections []model.Section, skipCodes map[string][]string) []model.Recommendation {
	var recs []model.Recommendation
	for _, sec := range sections {
		recs = append(recs, addFlatRecs(sec.Checks, skipCodes[sec.Name])...)
	}
	return recs
}
