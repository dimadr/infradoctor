package modules

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// StorageModule diagnoses filesystem usage, inodes, and disk health.
type StorageModule struct{}

func (m *StorageModule) ID() string   { return "storage" }
func (m *StorageModule) Name() string { return "Storage Module" }
func (m *StorageModule) Detect() bool {
	return hasBinary("df")
}

func (m *StorageModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseFilesystems(ctx))
	sections = append(sections, diagnoseInodes(ctx))
	sections = append(sections, diagnoseDiskAnalysis(ctx))

	// Manual recommendation for root filesystem pressure
	var recs []model.Recommendation
	rootHigh := false
	for _, sec := range sections {
		if sec.Name == "Filesystems" {
			for _, c := range sec.Checks {
				if strings.Contains(c.Message, "Root filesystem at") && c.Status == model.StatusWarning {
					rootHigh = true
				}
			}
		}
	}
	if rootHigh {
		recs = append(recs, buildRecommendation(
			"storage.root_high",
			model.StatusWarning,
			"Root filesystem usage above 80%",
			"The root filesystem is approaching capacity, which can affect system stability",
			"Database writes may fail, logs may be lost, Docker pulls may stall, cron jobs may fail",
			"Clean unused packages, remove old Docker images, prune logs, or expand the partition",
			"docker system prune -af && journalctl --vacuum-size=500M && apt-get autoremove --purge",
			false,
		))
	}
	// Flat recs for uncovered warnings (e.g., critical filesystem usage on other mounts)
	skipPatterns := map[string][]string{
		"Filesystems": {"storage.root_high"},
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

type fsEntry struct {
	fstype string
	mount  string
	size   string
	used   string
	avail  string
	usePct int
}

func diagnoseFilesystems(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "df", "-hT", "--exclude-type", "tmpfs", "--exclude-type", "devtmpfs", "--exclude-type", "squashfs", "--exclude-type", "overlay")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "df: unable to read filesystem info"})
		return model.Section{Name: "Filesystems", Status: model.StatusInfo, Checks: checks}
	}

	var entries []fsEntry
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Filesystem") || strings.HasPrefix(line, "Type") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		pctStr := strings.TrimSuffix(fields[5], "%")
		pct, err := strconv.Atoi(pctStr)
		if err != nil {
			continue
		}

		entries = append(entries, fsEntry{
			fstype: fields[1],
			mount:  fields[6],
			size:   fields[2],
			used:   fields[3],
			avail:  fields[4],
			usePct: pct,
		})
	}

	if len(entries) == 0 {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No filesystems detected"})
		return model.Section{Name: "Filesystems", Status: model.StatusInfo, Checks: checks}
	}

	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Filesystems checked: %d", len(entries)),
	})

	for _, e := range entries {
		status := model.StatusOK
		if e.usePct >= 90 {
			status = model.StatusCritical
		} else if e.usePct >= 80 {
			status = model.StatusWarning
		}
		checks = append(checks, model.Check{
			Status:  status,
			Message: fmt.Sprintf("%s [%s]: %s used / %s total (%d%%)", e.mount, e.fstype, e.used, e.size, e.usePct),
		})
	}

	// Check root specifically
	for _, e := range entries {
		if e.mount == "/" && e.usePct >= 80 {
			checks = append(checks, model.Check{
				Code:    "storage.root_high",
				Status:  model.StatusWarning,
				Message: fmt.Sprintf("Root filesystem at %d%% — high usage may affect database writes, logs, and Docker pulls", e.usePct),
			})
		}
	}

	return model.Section{
		Name:   "Filesystems",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseInodes(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "df", "-ihT")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "df -ih: unable to read inode info"})
		return model.Section{Name: "Inodes", Status: model.StatusInfo, Checks: checks}
	}

	lines := strings.Split(out, "\n")
	found := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Filesystem") || strings.HasPrefix(line, "Type") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		fstype := fields[1]
		if fstype == "tmpfs" || fstype == "devtmpfs" || fstype == "squashfs" || fstype == "overlay" {
			continue
		}

		pctStr := strings.TrimSuffix(fields[5], "%")
		pct, err := strconv.Atoi(pctStr)
		if err != nil {
			continue
		}
		found = true

		status := model.StatusOK
		if pct >= 90 {
			status = model.StatusCritical
		} else if pct >= 80 {
			status = model.StatusWarning
		}
		checks = append(checks, model.Check{
			Status:  status,
			Message: fmt.Sprintf("%s: inodes %d%% used", fields[len(fields)-1], pct),
		})
	}

	if !found {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No inode data available"})
	}

	return model.Section{
		Name:   "Inodes",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseDiskAnalysis(ctx context.Context) model.Section {
	var checks []model.Check

	// Journal disk usage
	if hasBinary("journalctl") {
		out, _ := runCmd(ctx, "journalctl", "--disk-usage")
		if out != "" {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("Journal: %s", out),
			})
		}
	}

	// Top-level directory sizes (root filesystem, depth 1, excludes virtual mounts)
	duOut, _ := runCmd(ctx, "du", "-h", "--max-depth=1", "/", "--exclude=/proc", "--exclude=/sys", "--exclude=/dev", "--exclude=/run")
	if duOut != "" {
		lines := strings.Split(duOut, "\n")
		var dirs []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasSuffix(line, "\t/") {
				continue
			}
			dirs = append(dirs, line)
		}
		if len(dirs) > 5 {
			dirs = dirs[:5]
		}
		if len(dirs) > 0 {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("Top directories by size: %s", strings.Join(dirs, ", ")),
			})
		}
	}

	// Check /var/lib/docker size if it exists
	dockerOut, err := runCmd(ctx, "du", "-sh", "/var/lib/docker")
	if err == nil && dockerOut != "" {
		fields := strings.Fields(dockerOut)
		if len(fields) >= 1 {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("Docker data directory: %s", fields[0]),
			})
		}
	}

	return model.Section{
		Name:   "Disk Analysis",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}
