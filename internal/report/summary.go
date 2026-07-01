package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

var riskPriority = map[string]int{
	"networking.risky_service":      0,
	"docker.exposed_critical":       1,
	"firewall.docker_empty_chain":   2,
	"firewall.docker_missing_chain": 2,
	"firewall.ufw_inactive":         2,
	"firewall.ufw_no_ssh":           2,
	"storage.root_high":             3,
	"security.reboot_required":      4,
	"ssh.permit_root_login":         5,
	"ssh.password_auth":             5,
	"ssh.empty_passwords":           5,
	"ssh.dsa_key":                   5,
	"ssh.x11_forwarding":            5,
	"ssh.gateway_ports":             5,
}

func recPriority(rec model.Recommendation) int {
	if p, ok := riskPriority[rec.Code]; ok {
		return p
	}
	return 999
}

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
			uniqueContainers := map[string]bool{}
			for _, sec := range r.Sections {
				if sec.Name == "Containers" {
					for _, c := range sec.Checks {
						if c.Code == "docker.exposed_critical" {
							msg := c.Message
							if start := strings.Index(msg, "("); start != -1 {
								before := strings.TrimSpace(msg[:start])
								if fields := strings.Fields(before); len(fields) >= 2 {
									uniqueContainers[fields[1]] = true
								}
							}
						}
					}
				}
			}
			s.DockerExposed = len(uniqueContainers)
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
		pi := recPriority(allRecs[i])
		pj := recPriority(allRecs[j])
		if pi != pj {
			return pi < pj
		}
		si := severityOrder[allRecs[i].Severity]
		sj := severityOrder[allRecs[j].Severity]
		if si != sj {
			return si < sj
		}
		return allRecs[i].Code < allRecs[j].Code
	})
	n := 3
	if len(allRecs) < n {
		n = len(allRecs)
	}
	s.TopRecommendations = allRecs[:n]

	return s
}
