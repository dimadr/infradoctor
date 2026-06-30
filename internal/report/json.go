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
		Results:   results,
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
