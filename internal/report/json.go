package report

import (
	"encoding/json"
	"os"
	"time"

	"github.com/dimadr/infradoctor/internal/model"
)

// JSONReport is the top-level JSON structure.
type JSONReport struct {
	Generated string        `json:"generated"`
	System    model.OSInfo  `json:"system"`
	Results   []model.Result `json:"results"`
}

// WriteJSON generates report.json.
func WriteJSON(osInfo model.OSInfo, results []model.Result) (string, error) {
	const filename = "report.json"

	rpt := JSONReport{
		Generated: time.Now().Format(time.RFC3339),
		System:    osInfo,
		Results:   sanitizeResults(results),
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
		for j, s := range r.Sections {
			r.Sections[j].Name = Sanitize(s.Name)
			for k, c := range s.Checks {
				r.Sections[j].Checks[k].Message = Sanitize(c.Message)
			}
		}
		for j, rec := range r.Recommendations {
			r.Recommendations[j] = Sanitize(rec)
		}
		out[i] = r
	}
	return out
}
