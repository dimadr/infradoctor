package modules

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

type FirewallModule struct{}

func (m *FirewallModule) ID() string   { return "firewall" }
func (m *FirewallModule) Name() string { return "Firewall Module" }
func (m *FirewallModule) Detect() bool {
	for _, bin := range []string{"iptables", "nft", "ufw"} {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

func (m *FirewallModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section
	var recommendations []string

	if hasBinary("ufw") {
		sections = append(sections, diagnoseUFW(ctx))
	}
	sections = append(sections, diagnoseIPTables(ctx))
	if hasBinary("nft") {
		sections = append(sections, diagnoseNFTables(ctx))
	}

	for _, s := range sections {
		for _, c := range s.Checks {
			if c.Status == "warning" || c.Status == "critical" {
				recommendations = append(recommendations, c.Message)
			}
		}
	}

	status := "ok"
	for _, s := range sections {
		switch s.Status {
		case "critical":
			status = "critical"
		case "warning":
			if status != "critical" {
				status = "warning"
			}
		}
	}

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          status,
		Sections:        sections,
		Recommendations: recommendations,
	}
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func diagnoseUFW(ctx context.Context) model.Section {
	var checks []model.Check

	out, _ := runCmd(ctx, "ufw", "status", "verbose")
	lines := strings.Split(out, "\n")

	status := "unknown"
	defaultIn := ""
	defaultOut := ""
	logging := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimPrefix(line, "Status: ")
		case strings.HasPrefix(line, "Default: "):
			parts := strings.Split(strings.TrimPrefix(line, "Default: "), " (")
			if len(parts) > 0 {
				vals := strings.Fields(parts[0])
				if len(vals) >= 2 {
					defaultIn = vals[0]
					defaultOut = vals[1]
				}
			}
		case strings.HasPrefix(line, "Logging: "):
			logging = strings.TrimPrefix(line, "Logging: ")
		}
	}

	switch status {
	case "active":
		checks = append(checks, model.Check{Status: "ok", Message: "UFW is active"})
	case "inactive":
		checks = append(checks, model.Check{Status: "warning", Message: "UFW is inactive — enable with: ufw enable"})
	default:
		checks = append(checks, model.Check{Status: "info", Message: "UFW status: " + status})
	}

	if defaultIn != "" {
		if defaultIn == "deny" || defaultIn == "reject" {
			checks = append(checks, model.Check{Status: "ok", Message: "UFW default incoming: " + defaultIn})
		} else {
			checks = append(checks, model.Check{Status: "warning", Message: "UFW default incoming: " + defaultIn + " — set to deny: ufw default deny incoming"})
		}
	}
	if defaultOut != "" {
		checks = append(checks, model.Check{Status: "info", Message: "UFW default outgoing: " + defaultOut})
	}

	if logging != "" && logging != "on" {
		checks = append(checks, model.Check{Status: "info", Message: "UFW logging: " + logging + " — enable with: ufw logging on"})
	}

	if status == "active" {
		ruleCount := 0
		hasSSH := false
		for _, line := range lines {
			if strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") || strings.Contains(line, "REJECT") || strings.Contains(line, "LIMIT") {
				ruleCount++
				if strings.Contains(line, "22") || strings.Contains(line, "ssh") {
					hasSSH = true
				}
			}
		}
		checks = append(checks, model.Check{Status: "info", Message: fmt.Sprintf("UFW rules: %d", ruleCount)})
		if !hasSSH {
			checks = append(checks, model.Check{Status: "warning", Message: "No UFW rule for SSH (22/tcp) — add: ufw allow ssh"})
		}
	}

	return model.Section{
		Name:   "UFW",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseIPTables(ctx context.Context) model.Section {
	var checks []model.Check

	hasIPTables := hasBinary("iptables")
	hasIPv6 := hasBinary("ip6tables")

	if !hasIPTables {
		checks = append(checks, model.Check{Status: "info", Message: "iptables not installed"})
		return model.Section{Name: "iptables", Status: "info", Checks: checks}
	}

	chains := []string{"INPUT", "FORWARD", "OUTPUT"}
	for _, chain := range chains {
		out, _ := runCmd(ctx, "iptables", "-L", chain, "-n", "--line-numbers")
		policy := extractPolicy(out)
		if policy != "" {
			status := "ok"
			if chain == "INPUT" && policy != "DROP" && policy != "REJECT" {
				status = "warning"
			}
			if chain == "FORWARD" && policy != "DROP" && policy != "REJECT" {
				status = "warning"
			}
			checks = append(checks, model.Check{
				Status:  status,
				Message: fmt.Sprintf("iptables %s policy: %s", chain, policy),
			})
		}

		rules := countRules(out)
		if rules > 0 {
			checks = append(checks, model.Check{Status: "info", Message: fmt.Sprintf("iptables %s: %d rules", chain, rules)})
		}
	}

	if hasIPv6 {
		v6Rules := false
		for _, chain := range chains {
			out, _ := runCmd(ctx, "ip6tables", "-L", chain, "-n")
			if countRules(out) > 0 {
				v6Rules = true
			}
		}
		if v6Rules {
			checks = append(checks, model.Check{Status: "info", Message: "ip6tables has IPv6 rules"})
		}
	}

	return model.Section{
		Name:   "iptables",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseNFTables(ctx context.Context) model.Section {
	var checks []model.Check

	out, _ := runCmd(ctx, "nft", "list", "ruleset")
	if out == "" {
		checks = append(checks, model.Check{Status: "info", Message: "nftables: no ruleset found"})
		return model.Section{Name: "nftables", Status: "info", Checks: checks}
	}

	tableCount := 0
	chainCount := 0
	ruleCount := 0

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "table "):
			tableCount++
		case strings.HasPrefix(trimmed, "chain "):
			chainCount++
		case strings.Contains(line, "counter"):
			ruleCount++
		}
	}

	checks = append(checks, model.Check{Status: "ok", Message: fmt.Sprintf("nftables: %d tables, %d chains, %d rules", tableCount, chainCount, ruleCount)})

	return model.Section{
		Name:   "nftables",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func extractPolicy(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "policy "); idx >= 0 {
			rest := line[idx+7:]
			end := strings.IndexAny(rest, ") \t")
			if end < 0 {
				end = len(rest)
			}
			return rest[:end]
		}
	}
	return ""
}

func countRules(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "policy") || strings.HasPrefix(line, "num") || strings.HasPrefix(line, "pkts") {
			continue
		}
		if strings.Contains(line, "target") || strings.Contains(line, "prot") {
			continue
		}
		count++
	}
	return count
}
