package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/dimadr/infradoctor/internal/model"
)

// JSONReport is the top-level JSON structure.
type JSONReport struct {
	Generated       string                `json:"generated"`
	System          model.OSInfo          `json:"system"`
	Results         []model.Result        `json:"results"`
	ExposureSummary model.ExposureSummary `json:"exposure_summary"`
}

// WriteJSON generates report.json.
func WriteJSON(osInfo model.OSInfo, results []model.Result) (string, error) {
	const filename = "report.json"

	sanitized := sanitizeResults(results)
	rpt := JSONReport{
		Generated:       time.Now().Format(time.RFC3339),
		System:          osInfo,
		Results:         sanitized,
		ExposureSummary: BuildExposureSummary(sanitized),
	}

	data, err := json.MarshalIndent(rpt, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return "", err
	}

	return filename, nil
}

func sanitizeResults(results []model.Result) []model.Result {
	out := make([]model.Result, len(results))
	for i, r := range results {
		r.Name = Sanitize(r.Name)
		r.Summary = Sanitize(r.Summary)
		r.Recommendations = make([]model.Recommendation, len(r.Recommendations))
		copy(r.Recommendations, results[i].Recommendations)
		for j := range r.Recommendations {
			r.Recommendations[j].Title = Sanitize(r.Recommendations[j].Title)
			r.Recommendations[j].Context = Sanitize(r.Recommendations[j].Context)
			r.Recommendations[j].Impact = Sanitize(r.Recommendations[j].Impact)
			r.Recommendations[j].Action = Sanitize(r.Recommendations[j].Action)
			r.Recommendations[j].Command = Sanitize(r.Recommendations[j].Command)
		}
		r.Sections = make([]model.Section, len(r.Sections))
		copy(r.Sections, results[i].Sections)
		for j := range r.Sections {
			r.Sections[j].Name = Sanitize(r.Sections[j].Name)
			r.Sections[j].Checks = make([]model.Check, len(r.Sections[j].Checks))
			copy(r.Sections[j].Checks, results[i].Sections[j].Checks)
			for k := range r.Sections[j].Checks {
				r.Sections[j].Checks[k].Message = Sanitize(r.Sections[j].Checks[k].Message)
			}
		}
		out[i] = r
	}
	return out
}
