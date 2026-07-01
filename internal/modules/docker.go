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
	var recs []model.Recommendation

	sections = append(sections, diagnoseDockerEngine(ctx))
	sec, extraRecs := diagnoseDockerContainers(ctx)
	sections = append(sections, sec)
	recs = append(recs, extraRecs...)
	sections = append(sections, diagnoseDockerNetworks(ctx))
	sections = append(sections, diagnoseDockerStorage(ctx))

	// Flat recs for uncovered warnings/criticals
	skipPatterns := map[string][]string{
		"Containers": {"docker.exposed_critical", "docker.privileged", "docker.host_network"},
	}
	recs = append(recs, addFlatRecsFromSections(sections, skipPatterns)...)

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: recs,
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

func diagnoseDockerContainers(ctx context.Context) (model.Section, []model.Recommendation) {
	var checks []model.Check
	var recs []model.Recommendation

	out, err := runCmd(ctx, "docker", "ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No containers found"})
		return model.Section{Name: "Containers", Status: model.StatusInfo, Checks: checks}, recs
	}

	lines := strings.Split(out, "\n")
	totalCount := len(lines)
	checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("Total containers: %d", totalCount)})

	runningCount := 0
	exposedRisky := 0
	var containerIDs []string

	for _, line := range lines {
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) < 5 {
			continue
		}
		id := fields[0]
		image := fields[1]
		status := fields[2]
		ports := fields[3]
		name := fields[4]

		containerIDs = append(containerIDs, id)

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
								Code:    "docker.exposed_critical",
								Status:  model.StatusWarning,
								Message: fmt.Sprintf("Container %s (%s) exposes %s (%s) on all interfaces: %s", name, image, svc, p, id),
							})
							recs = append(recs, buildRecommendation(
								"docker.exposed_critical",
								model.StatusWarning,
								fmt.Sprintf("Docker container %s exposes %s on all interfaces", name, svc),
								fmt.Sprintf("Container %s publishes %s on 0.0.0.0, making %s accessible from any network", name, p, svc),
								"Unauthenticated access to database or cache from outside the host",
								"Bind to 127.0.0.1 only, or add a DOCKER-USER firewall rule to restrict access",
								fmt.Sprintf("docker inspect %s | jq '.[].NetworkSettings.Ports'", id),
								false,
							))
							break
						}
					}
				}
			}
		}
	}

	// Batch inspect for detailed container info
	if len(containerIDs) > 0 {
		args := append([]string{"inspect", "--format", "{{.ID}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.RestartPolicy.Name}}\t{{.HostConfig.NetworkMode}}\t{{.Config.Healthcheck}}"}, containerIDs...)
		inspectOut, _ := runCmd(ctx, "docker", args...)
		if inspectOut != "" {
			privilegedCount := 0
			noRestartCount := 0
			hostNetCount := 0
			for _, l := range strings.Split(inspectOut, "\n") {
				parts := strings.SplitN(l, "\t", 5)
				if len(parts) < 4 {
					continue
				}
				if parts[1] == "true" {
					privilegedCount++
				}
				if parts[2] == "" || parts[2] == "no" {
					noRestartCount++
				}
				if parts[3] == "host" {
					hostNetCount++
				}
			}
			if hostNetCount > 0 {
				checks = append(checks, model.Check{
					Code:    "docker.host_network",
					Status:  model.StatusWarning,
					Message: fmt.Sprintf("%d container(s) use host network mode (bypasses Docker NAT)", hostNetCount),
				})
				recs = append(recs, buildRecommendation(
					"docker.host_network",
					model.StatusWarning,
					"Container(s) use host network mode",
					fmt.Sprintf("%d container(s) share the host network namespace, bypassing Docker NAT and port mapping", hostNetCount),
					"Containers have full access to host networking; published ports are not isolated by Docker",
					"Use bridge network mode with explicit port mappings instead of host mode",
					"docker network create mynet && docker run --network mynet ...",
					false,
				))
			}
			if privilegedCount > 0 {
				checks = append(checks, model.Check{
					Code:    "docker.privileged",
					Status:  model.StatusWarning,
					Message: fmt.Sprintf("%d container(s) running in privileged mode", privilegedCount),
				})
				recs = append(recs, buildRecommendation(
					"docker.privileged",
					model.StatusWarning,
					"Container(s) run in privileged mode",
					fmt.Sprintf("%d container(s) have elevated privileges, granting access to all host devices and kernel capabilities", privilegedCount),
					"Privileged containers can bypass most Docker security restrictions and access host resources",
					"Drop --privileged and add only required capabilities",
					"docker run --cap-drop ALL --cap-add SYS_ADMIN ...",
					false,
				))
			}
			if noRestartCount > 0 {
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: fmt.Sprintf("%d container(s) without restart policy", noRestartCount),
				})
			}
		}
	}

	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Running containers: %d / %d", runningCount, totalCount),
	})

	if exposedRisky > 0 {
		checks = append(checks, model.Check{
			Code:    "docker.exposed_critical",
			Status:  model.StatusWarning,
			Message: fmt.Sprintf("%d container(s) expose risky services (DB/Redis) on all interfaces", exposedRisky),
		})
	}

	if runningCount == 0 {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "No containers are running"})
	}

	return model.Section{
		Name:   "Containers",
		Status: sectionStatus(checks),
		Checks: checks,
	}, recs
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
