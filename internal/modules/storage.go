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

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: collectRecommendations(sections),
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
