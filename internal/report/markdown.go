package report

import (
	"fmt"
	"os"
	"time"

	"github.com/dimadr/infradoctor/internal/model"
)

// WriteMD generates report.md.
func WriteMD(osInfo model.OSInfo, results []model.Result) (string, error) {
	const filename = "report.md"

	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprintln(f, "# InfraDoctor Report")
	fmt.Fprintln(f)
	fmt.Fprintf(f, "Generated: %s\n\n", time.Now().Format(time.RFC3339))

	fmt.Fprintln(f, "## System")
	fmt.Fprintln(f)
	fmt.Fprintf(f, "| Field | Value |\n")
	fmt.Fprintf(f, "|-------|-------|\n")
	fmt.Fprintf(f, "| Hostname | %s |\n", osInfo.Hostname)
	fmt.Fprintf(f, "| OS | %s |\n", osInfo.PrettyName)
	fmt.Fprintf(f, "| Kernel | %s |\n", osInfo.Kernel)
	fmt.Fprintln(f)

	for _, r := range results {
		fmt.Fprintf(f, "## %s\n\n", r.Name)
		fmt.Fprintf(f, "**Status:** %s\n\n", r.Status)
		if r.Summary != "" {
			fmt.Fprintf(f, "%s\n\n", r.Summary)
		}
		for _, c := range r.Checks {
			fmt.Fprintf(f, "- [%s] %s\n", c.Status, c.Message)
		}
		fmt.Fprintln(f)
	}

	fmt.Fprintln(f, "---")
	fmt.Fprintln(f, "*read-only — no system changes made*")

	return filename, nil
}
