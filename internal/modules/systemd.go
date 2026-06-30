package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// SystemdModule diagnoses systemd unit state, timers, sockets, and failures.
type SystemdModule struct{}

func (m *SystemdModule) ID() string   { return "systemd" }
func (m *SystemdModule) Name() string { return "Systemd Module" }
func (m *SystemdModule) Detect() bool {
	return hasBinary("systemctl")
}

func (m *SystemdModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseSystemdFailed(ctx))
	sections = append(sections, diagnoseSystemdInactive(ctx))
	sections = append(sections, diagnoseSystemdTimers(ctx))
	sections = append(sections, diagnoseSystemdSockets(ctx))

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: collectRecommendations(sections),
	}
}

func diagnoseSystemdFailed(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "systemctl", "--failed", "--no-legend", "--no-pager")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "systemctl --failed: unable to check"})
		return model.Section{Name: "Failed Units", Status: model.StatusWarning, Checks: checks}
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	failedCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		failedCount++
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			checks = append(checks, model.Check{
				Status:  model.StatusCritical,
				Message: fmt.Sprintf("Failed unit: %s (%s)", fields[0], fields[1]),
			})
		}
	}

	if failedCount == 0 {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "No failed units"})
	}

	// Check overall system state
	stateOut, _ := runCmd(ctx, "systemctl", "is-system-running")
	if stateOut == "degraded" {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "System state: degraded (some units failed or offline)"})
	} else if stateOut != "" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("System state: %s", stateOut)})
	}

	return model.Section{
		Name:   "Failed Units",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSystemdInactive(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "systemctl", "list-units", "--all", "--state=inactive", "--no-legend", "--no-pager")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "systemctl: unable to list inactive units"})
		return model.Section{Name: "Inactive Units", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	totalInactive := 0
	enabledInactive := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		totalInactive++
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] == "enabled" && fields[1] == "inactive" {
			enabledInactive++
			checks = append(checks, model.Check{
				Status:  model.StatusWarning,
				Message: fmt.Sprintf("Enabled but inactive: %s", fields[0]),
			})
		}
	}

	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Total inactive units: %d (%d enabled but inactive)", totalInactive, enabledInactive),
	})

	return model.Section{
		Name:   "Inactive Units",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSystemdTimers(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "systemctl", "list-timers", "--all", "--no-legend", "--no-pager")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "systemctl: unable to list timers"})
		return model.Section{Name: "Timers", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	timerCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		timerCount++
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("Timer: %s (next: %s)", fields[len(fields)-1], fields[0]),
			})
		}
	}

	if timerCount == 0 {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No timers configured"})
	} else {
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: fmt.Sprintf("Total timers: %d", timerCount),
		})
	}

	return model.Section{
		Name:   "Timers",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSystemdSockets(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "systemctl", "list-sockets", "--all", "--no-legend", "--no-pager")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "systemctl: unable to list sockets"})
		return model.Section{Name: "Sockets", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	socketCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "listening on") {
			continue
		}
		socketCount++
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Detect SSH socket activation
			if strings.Contains(strings.ToLower(line), "ssh") || strings.Contains(strings.ToLower(line), "sshd") {
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: fmt.Sprintf("SSH socket active: %s", line),
				})
			}
		}
	}

	socketCount = len(lines) - 1 // subtract header
	if socketCount < 0 {
		socketCount = 0
	}

	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Active sockets: %d", socketCount),
	})

	return model.Section{
		Name:   "Sockets",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}
