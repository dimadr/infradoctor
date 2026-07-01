package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// BuildExposureSummary extracts cross-module exposure data from results.
func BuildExposureSummary(results []model.Result) model.ExposureSummary {
	var s model.ExposureSummary

	for _, r := range results {
		switch r.ID {
		case "networking":
			for _, sec := range r.Sections {
				if sec.Name == "Listening Ports" {
					for _, c := range sec.Checks {
						if c.Code == "networking.risky_service" {
							s.RiskyServices = append(s.RiskyServices, c.Message)
						}
						if c.Code == "networking.port_count" {
							n := 0
							parts := strings.Split(c.Message, "(")
							if len(parts) >= 2 {
								before := strings.TrimSpace(strings.Split(parts[1], ",")[0])
								fmt.Sscanf(before, "%d", &n)
							}
							s.PublicPorts = n
						}
					}
				}
			}
		case "docker":
			for _, sec := range r.Sections {
				if sec.Name == "Containers" {
					for _, c := range sec.Checks {
						if c.Code == "docker.exposed_critical" {
							s.DockerExposed++
						}
					}
				}
			}
		case "storage":
			for _, sec := range r.Sections {
				if sec.Name == "Filesystems" {
					for _, c := range sec.Checks {
						if c.Code == "storage.root_high" {
							s.StoragePressure = c.Message
						}
					}
				}
			}
		case "systemd":
			for _, sec := range r.Sections {
				if sec.Name == "Failed Units" {
					for _, c := range sec.Checks {
						if c.Code == "systemd.degraded" {
							s.SystemState = c.Message
						}
					}
				}
			}
		case "security":
			for _, sec := range r.Sections {
				if sec.Name == "Kernel" {
					for _, c := range sec.Checks {
						if c.Code == "security.reboot_required" {
							s.RebootRequired = true
						}
					}
				}
			}
		}
	}

	var allRecs []model.Recommendation
	for _, r := range results {
		allRecs = append(allRecs, r.Recommendations...)
	}
	severityOrder := map[model.Status]int{
		model.StatusCritical: 0,
		model.StatusWarning:  1,
		model.StatusInfo:     2,
	}
	sort.SliceStable(allRecs, func(i, j int) bool {
		si := severityOrder[allRecs[i].Severity]
		sj := severityOrder[allRecs[j].Severity]
		if si != sj {
			return si < sj
		}
		return len(allRecs[i].Impact) < len(allRecs[j].Impact)
	})
	n := 3
	if len(allRecs) < n {
		n = len(allRecs)
	}
	s.TopRecommendations = allRecs[:n]

	return s
}
