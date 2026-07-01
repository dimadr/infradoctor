package modules

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

type JournalModule struct{}

func (m *JournalModule) ID() string   { return "journal" }
func (m *JournalModule) Name() string { return "Journal Module" }
func (m *JournalModule) Detect() bool { return hasBinary("journalctl") }

func (m *JournalModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section
	var recs []model.Recommendation

	sections = append(sections, diagnoseJournalService(ctx))
	sections = append(sections, diagnoseJournalConfig(ctx))
	sections = append(sections, diagnoseJournalAnalysis(ctx))
	sections = append(sections, diagnoseJournalDisk(ctx))

	recs = append(recs, addFlatRecsFromSections(sections, nil)...)

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: recs,
	}
}

func diagnoseJournalService(ctx context.Context) model.Section {
	var checks []model.Check

	if hasBinary("systemctl") {
		out, _ := runCmd(ctx, "systemctl", "is-active", "systemd-journald")
		if out == "active" {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "systemd-journald is active"})
		} else if out != "" {
			checks = append(checks, model.Check{Status: model.StatusWarning, Message: fmt.Sprintf("systemd-journald is %s", out)})
		}
	}

	_, err := runCmd(ctx, "journalctl", "--no-pager", "-n", "1")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusCritical, Message: "journalctl failed — systemd-journald may not be running"})
		return model.Section{Name: "Service", Status: sectionStatus(checks), Checks: checks}
	}

	return model.Section{
		Name:   "Service",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseJournalConfig(ctx context.Context) model.Section {
	var checks []model.Check

	cfg := readConfig("/etc/systemd/journald.conf")
	if len(cfg) == 0 {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "journald.conf not found, using defaults"})
		return model.Section{Name: "Configuration", Status: sectionStatus(checks), Checks: checks}
	}

	checks = append(checks, model.Check{Status: model.StatusInfo, Message: "journald.conf found"})

	maxUse := cfg["systemmaxuse"]
	runtimeMaxUse := cfg["runtimemaxuse"]
	maxRetention := cfg["maxretentionsec"]
	maxFileSec := cfg["maxfilesec"]
	compress := cfg["compress"]

	if maxUse != "" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("SystemMaxUse=%s", maxUse)})
	} else {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "SystemMaxUse not set — journal may consume up to 10% of filesystem"})
	}
	if runtimeMaxUse != "" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("RuntimeMaxUse=%s", runtimeMaxUse)})
	}
	if maxRetention != "" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("MaxRetentionSec=%s", maxRetention)})
	}
	if maxFileSec != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("MaxFileSec=%s", maxFileSec)})
	}
	if compress != "" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("Compress=%s", compress)})
	}

	return model.Section{
		Name:   "Configuration",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseJournalAnalysis(ctx context.Context) model.Section {
	var checks []model.Check

	errCount, _ := runCmd(ctx, "journalctl", "-p", "err", "--since", "24h ago", "--no-pager", "--quiet")
	errLines := 0
	for _, line := range strings.Split(errCount, "\n") {
		if line != "" {
			errLines++
		}
	}

	if errLines > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusWarning,
			Message: fmt.Sprintf("%d error-level messages in the last 24h", errLines),
		})
	} else {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "No error-level messages in the last 24h"})
	}

	critOut, _ := runCmd(ctx, "journalctl", "-p", "crit", "--since", "7 days ago", "--no-pager", "--quiet")
	critLines := 0
	for _, line := range strings.Split(critOut, "\n") {
		if line != "" {
			critLines++
		}
	}
	if critLines > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusWarning,
			Message: fmt.Sprintf("%d critical-level messages in the last 7 days", critLines),
		})
	}

	// Check for OOM messages
	oomOut, _ := runCmd(ctx, "journalctl", "-g", "oom-killer", "--since", "7 days ago", "--no-pager", "--quiet")
	oomCount := 0
	for _, line := range strings.Split(oomOut, "\n") {
		if line != "" {
			oomCount++
		}
	}
	if oomCount > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusCritical,
			Message: fmt.Sprintf("%d OOM-killer events in last 7 days", oomCount),
		})
	}

	return model.Section{
		Name:   "Log Analysis",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseJournalDisk(ctx context.Context) model.Section {
	var checks []model.Check

	usageOut, err := runCmd(ctx, "journalctl", "--disk-usage")
	if err != nil || usageOut == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Cannot read journal disk usage"})
		return model.Section{Name: "Disk Usage", Status: sectionStatus(checks), Checks: checks}
	}
	checks = append(checks, model.Check{Status: model.StatusInfo, Message: strings.TrimSpace(usageOut)})

	// Parse size from arch|logged: X.XG or X.XM
	sizeStr := ""
	fields := strings.Fields(usageOut)
	for i, f := range fields {
		if f == "archived" || f == "available" {
			continue
		}
		if strings.HasSuffix(f, "G") || strings.HasSuffix(f, "M") {
			if i > 0 && (fields[i-1] == "archived" || fields[i-1] == "available") {
				sizeStr = f
				break
			}
			// try next approach
		}
	}
	if sizeStr == "" {
		// Try parsing: "Journal size: X.XG" or similar
		for _, f := range fields {
			if strings.HasSuffix(f, "G") {
				sizeStr = f
				break
			}
			if strings.HasSuffix(f, "M") {
				sizeStr = f
				break
			}
		}
	}

	if sizeStr != "" {
		sizeMB := parseSizeToMB(sizeStr)
		if sizeMB > 1024 {
			checks = append(checks, model.Check{
				Status:  model.StatusWarning,
				Message: fmt.Sprintf("Journal is %.1fG — consider limiting with SystemMaxUse", float64(sizeMB)/1024),
			})
		} else if sizeMB > 500 {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("Journal is %dM — monitor if growing", sizeMB),
			})
		}
	}

	// Check oldest entry
	headerOut, _ := runCmd(ctx, "journalctl", "--no-pager", "--header")
	for _, line := range strings.Split(headerOut, "\n") {
		if strings.Contains(line, "Oldest entry") {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: strings.TrimSpace(line)})
			break
		}
	}

	return model.Section{
		Name:   "Disk Usage",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func parseSizeToMB(s string) int {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "G") {
		val := strings.TrimSuffix(s, "G")
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0
		}
		return int(f * 1024)
	}
	if strings.HasSuffix(s, "M") {
		val := strings.TrimSuffix(s, "M")
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

func readConfig(path string) map[string]string {
	out, err := runCmd(context.Background(), "cat", path)
	if err != nil {
		return nil
	}
	cfg := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		key = strings.ReplaceAll(key, "-", "")
		cfg[key] = val
	}
	return cfg
}
