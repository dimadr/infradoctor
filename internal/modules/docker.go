package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// DockerModule diagnoses Docker containers, images, networks, and volumes.
type DockerModule struct{}

func (m *DockerModule) ID() string   { return "docker" }
func (m *DockerModule) Name() string { return "Docker Module" }
func (m *DockerModule) Detect() bool {
	return hasBinary("docker")
}

func (m *DockerModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseDockerEngine(ctx))
	sections = append(sections, diagnoseDockerContainers(ctx))
	sections = append(sections, diagnoseDockerNetworks(ctx))
	sections = append(sections, diagnoseDockerStorage(ctx))

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: collectRecommendations(sections),
	}
}

func diagnoseDockerEngine(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "Docker engine not reachable"})
		return model.Section{Name: "Engine", Status: model.StatusWarning, Checks: checks}
	}
	checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("Docker engine version: %s", out)})

	out, _ = runCmd(ctx, "docker", "info", "--format", "{{.CgroupDriver}}")
	if out != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("Cgroup driver: %s", out)})
	}

	return model.Section{
		Name:   "Engine",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseDockerContainers(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "docker", "ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}\t{{.Mounts}}")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No containers found"})
		return model.Section{Name: "Containers", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(out, "\n")
	totalCount := len(lines)
	checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("Total containers: %d", totalCount)})

	runningCount := 0
	exposedRisky := 0
	privileged := 0
	noRestart := 0

	for _, line := range lines {
		fields := strings.SplitN(line, "\t", 6)
		if len(fields) < 5 {
			continue
		}
		id := fields[0]
		image := fields[1]
		status := fields[2]
		ports := fields[3]
		name := fields[4]

		if strings.HasPrefix(status, "Up") {
			runningCount++
		}

		if ports != "" && ports != "<nil>" {
			for _, p := range strings.Split(ports, ",") {
				p = strings.TrimSpace(p)
				if strings.Contains(p, "0.0.0.0:") || strings.Contains(p, ":::") {
					for portNum, svc := range riskyPorts {
						portStr := fmt.Sprintf("->%d/", portNum)
						if strings.Contains(p, portStr) {
							exposedRisky++
							checks = append(checks, model.Check{
								Status:  model.StatusWarning,
								Message: fmt.Sprintf("Container %s (%s) exposes %s (%s) on all interfaces: %s", name, image, svc, p, id),
							})
							break
						}
					}
				}
			}
		}

	}

	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Running containers: %d / %d", runningCount, totalCount),
	})

	if exposedRisky > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusWarning,
			Message: fmt.Sprintf("%d container(s) expose risky services (DB/Redis) on all interfaces", exposedRisky),
		})
	}

	if privileged > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusWarning,
			Message: fmt.Sprintf("%d container(s) running in privileged mode", privileged),
		})
	}

	if noRestart > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: fmt.Sprintf("%d container(s) without restart policy", noRestart),
		})
	}

	// Check for privileged containers
	outPriv, _ := runCmd(ctx, "docker", "ps", "--quiet", "--filter", "privileged=true")
	if outPriv != "" {
		privLines := strings.Split(strings.TrimSpace(outPriv), "\n")
		privileged = len(privLines)
		if privileged > 0 {
			checks = append(checks, model.Check{
				Status:  model.StatusWarning,
				Message: fmt.Sprintf("%d running privileged container(s)", privileged),
			})
		}
	}

	if runningCount == 0 {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "No containers are running"})
	}

	return model.Section{
		Name:   "Containers",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseDockerNetworks(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "docker", "network", "ls", "--format", "{{.Name}}\t{{.Driver}}")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No Docker networks found"})
		return model.Section{Name: "Networks", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(out, "\n")
	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Docker networks: %d", len(lines)),
	})

	for _, line := range lines {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) >= 2 {
			name := fields[0]
			driver := fields[1]
			if driver == "bridge" {
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: fmt.Sprintf("Network %s — %s (default bridge)", name, driver),
				})
			} else if driver == "host" || driver == "macvlan" {
				checks = append(checks, model.Check{
					Status:  model.StatusWarning,
					Message: fmt.Sprintf("Network %s — %s (bypasses Docker NAT, containers share host network)", name, driver),
				})
			} else {
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: fmt.Sprintf("Network %s — %s", name, driver),
				})
			}
		}
	}

	return model.Section{
		Name:   "Networks",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseDockerStorage(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "docker", "system", "df", "--format", "{{.Type}}\t{{.TotalCount}}\t{{.Size}}\t{{.Reclaimable}}")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Cannot get Docker disk usage"})
		return model.Section{Name: "Storage", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) >= 3 {
			typ := fields[0]
			count := fields[1]
			size := fields[2]
			reclaimable := ""
			if len(fields) >= 4 {
				reclaimable = fields[3]
			}
			msg := fmt.Sprintf("%s: %s items, %s", typ, count, size)
			if reclaimable != "" && reclaimable != "0B" {
				msg += fmt.Sprintf(" (reclaimable: %s)", reclaimable)
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: msg,
				})
			} else {
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: msg,
				})
			}
		}
	}

	return model.Section{
		Name:   "Storage",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}
