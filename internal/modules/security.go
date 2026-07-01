package modules

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// SecurityModule checks security baseline: users, sudo, updates, fail2ban, time sync.
type SecurityModule struct{}

func (m *SecurityModule) ID() string   { return "security" }
func (m *SecurityModule) Name() string { return "Security Baseline Module" }
func (m *SecurityModule) Detect() bool { return true }

func (m *SecurityModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseUsers(ctx))
	sections = append(sections, diagnoseSudo(ctx))
	sections = append(sections, diagnoseUpdates(ctx))
	sections = append(sections, diagnoseServices(ctx))
	sections = append(sections, diagnoseKernel(ctx))

	// Manual recommendations for key security risks
	var recs []model.Recommendation
	hasReboot := false
	hasUID0 := false
	for _, sec := range sections {
		for _, c := range sec.Checks {
			switch {
			case strings.Contains(c.Message, "System reboot required"):
				hasReboot = true
			case strings.Contains(c.Message, "Non-root user with UID 0"):
				hasUID0 = true
			}
		}
	}
	if hasReboot {
		recs = append(recs, buildRecommendation(
			"security.reboot_required",
			model.StatusWarning, "System reboot required — pending kernel update",
			"A kernel update has been installed but the system has not been rebooted. The running kernel may have unpatched vulnerabilities.",
			"System is running an older kernel with potentially unpatched vulnerabilities",
			"Schedule a maintenance window and reboot the server",
			"reboot",
			false,
		))
	}
	if hasUID0 {
		recs = append(recs, buildRecommendation(
			"security.non_root_uid0",
			model.StatusWarning, "Non-root user has UID 0 (root privileges)",
			"Users other than root with UID 0 have full root privileges and may be backdoor accounts",
			"Unauthorized users gain unrestricted root access with standard user credentials",
			"Investigate non-root UID 0 users and remove or reassign UID",
			"awk -F: '($3 == 0) { print $1 }' /etc/passwd",
			false,
		))
	}
	// Flat recs for uncovered warnings (e.g., world-writable dirs)
	skipPatterns := map[string][]string{
		"Users":  {"security.non_root_uid0"},
		"Kernel": {"security.reboot_required"},
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

func diagnoseUsers(ctx context.Context) model.Section {
	var checks []model.Check

	// Users with UID 0 (root-equivalent)
	out, _ := runCmd(ctx, "awk", "-F:", `($3 == "0") { print $1 }`, "/etc/passwd")
	uids := strings.Split(strings.TrimSpace(out), "\n")
	uid0Count := 0
	for _, u := range uids {
		u = strings.TrimSpace(u)
		if u == "root" {
			continue
		}
		if u != "" {
			uid0Count++
			checks = append(checks, model.Check{
				Code:    "security.non_root_uid0",
				Status:  model.StatusWarning,
				Message: fmt.Sprintf("Non-root user with UID 0: %s", u),
			})
		}
	}
	if uid0Count == 0 {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "Only root has UID 0"})
	}

	// Users with login shell
	out, _ = runCmd(ctx, "awk", "-F:", `$7 ~ /^\// { print $1 ":" $7 }`, "/etc/passwd")
	users := strings.Split(strings.TrimSpace(out), "\n")
	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Users with login shell: %d", len(users)),
	})

	return model.Section{
		Name:   "Users",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSudo(ctx context.Context) model.Section {
	var checks []model.Check

	if hasBinary("sudo") {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "sudo is installed"})
	}

	// Check sudoers include files
	out, _ := runCmd(ctx, "ls", "/etc/sudoers.d/")
	if out != "" {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: fmt.Sprintf("sudoers.d entries: %d", len(lines)),
		})
	}

	return model.Section{
		Name:   "Sudo",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseUpdates(ctx context.Context) model.Section {
	var checks []model.Check

	// Check if unattended-upgrades is active
	if hasBinary("systemctl") {
		out, _ := runCmd(ctx, "systemctl", "is-active", "unattended-upgrades")
		if out == "active" {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "unattended-upgrades is active"})
		} else if out != "" {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("unattended-upgrades is %s", out)})
		}
	}

	// Check for pending updates (non-intrusive, uses check command)
	if hasBinary("/usr/lib/update-notifier/apt-check") {
		out, _ := runCmd(ctx, "/usr/lib/update-notifier/apt-check", "--human-readable")
		if out != "" {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("Pending updates: %s", strings.Split(out, "\n")[0]),
			})
		}
	}

	return model.Section{
		Name:   "Updates",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseServices(ctx context.Context) model.Section {
	var checks []model.Check

	// Time sync
	if hasBinary("timedatectl") {
		out, _ := runCmd(ctx, "timedatectl", "show", "--property=NTP", "--value")
		if out == "yes" {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "NTP time synchronization enabled"})
		} else if out == "no" {
			checks = append(checks, model.Check{Status: model.StatusWarning, Message: "NTP time synchronization disabled"})
		}

		out, _ = runCmd(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
		if out == "yes" {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "System clock synchronized with NTP"})
		} else {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Time sync: " + out})
		}
	}

	// Fail2ban
	if hasBinary("fail2ban-client") {
		out, _ := runCmd(ctx, "fail2ban-client", "status")
		if strings.Contains(out, "Status") {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "fail2ban is active"})
		} else {
			checks = append(checks, model.Check{Status: model.StatusWarning, Message: "fail2ban is installed but not running"})
		}
	} else {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "fail2ban not installed"})
	}

	return model.Section{
		Name:   "Services",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseKernel(ctx context.Context) model.Section {
	var checks []model.Check

	// Check if system reboot is required (kernel update pending)
	if hasBinary("/usr/bin/needs-restarting") {
		out, _ := runCmd(ctx, "/usr/bin/needs-restarting", "-r")
		if strings.Contains(out, "reboot is required") || strings.Contains(out, "REBOOT REQUIRED") {
			checks = append(checks, model.Check{
				Code:    "security.reboot_required",
				Status:  model.StatusWarning,
				Message: "System reboot required — pending kernel update",
			})
		}
	} else {
		// Alternative: check /var/run/reboot-required
		if _, err := os.Stat("/var/run/reboot-required"); err == nil {
			checks = append(checks, model.Check{
				Code:    "security.reboot_required",
				Status:  model.StatusWarning,
				Message: "System reboot required — /var/run/reboot-required exists",
			})
		}
	}

	// Uptime
	out, _ := runCmd(ctx, "cat", "/proc/uptime")
	if out != "" {
		parts := strings.Fields(out)
		if len(parts) > 0 {
			if secs, err := strconv.ParseFloat(parts[0], 64); err == nil {
				days := int(secs / 86400)
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: fmt.Sprintf("System uptime: %d days", days),
				})
			}
		}
	}

	// Check for world-writable directories outside expected paths
	out, _ = runCmd(ctx, "find", "/", "-maxdepth", "3", "-xdev", "-type", "d", "-perm", "-o+w", "-not", "-path", "/proc/*", "-not", "-path", "/sys/*", "-not", "-path", "/dev/*", "-not", "-path", "/run/*", "-not", "-path", "/tmp/*", "-not", "-path", "/var/tmp/*", "-not", "-path", "/var/cache/*", "-not", "-path", "/var/lib/docker/*", "-not", "-path", "/snap/*")
	if out != "" {
		dirs := strings.Split(strings.TrimSpace(out), "\n")
		if len(dirs) > 0 && dirs[0] != "" {
			msg := fmt.Sprintf("World-writable directories found outside /tmp and /var/tmp: %d", len(dirs))
			if len(dirs) > 5 {
				msg += fmt.Sprintf(" (sample: %s, ...)", strings.Join(dirs[:5], ", "))
			} else {
				msg += fmt.Sprintf(" (%s)", strings.Join(dirs, ", "))
			}
			checks = append(checks, model.Check{
				Status:  model.StatusWarning,
				Message: msg,
			})
		}
	}

	return model.Section{
		Name:   "Kernel",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}
