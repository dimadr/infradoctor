package modules

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// FirewallModule diagnoses UFW, iptables, and nftables firewall state.
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

	sections = append(sections, diagnoseEffectiveStack(ctx))
	if hasBinary("ufw") {
		sections = append(sections, diagnoseUFW(ctx))
	}
	sections = append(sections, diagnoseIPTables(ctx))
	if hasBinary("nft") {
		sections = append(sections, diagnoseNFTables(ctx))
	}

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: collectRecommendations(sections),
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

	status := model.StatusUnknown
	defaultIn := ""
	defaultOut := ""
	logging := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Status: "):
			status = model.Status(strings.TrimPrefix(line, "Status: "))
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

	sshPort := detectSSHPort(lines)

	switch status {
	case "active":
		checks = append(checks, model.Check{	Status: model.StatusOK, Message: "UFW is active"})
	case "inactive":
		msg := "UFW is inactive"
		if sshPort != "" {
			msg += " — to enable safely: ufw allow " + sshPort + " && ufw enable"
		} else {
			msg += " — ensure SSH is allowed before: ufw enable"
		}
		checks = append(checks, model.Check{	Status: model.StatusWarning, Message: msg})
	default:
		checks = append(checks, model.Check{	Status: model.StatusInfo, Message: "UFW status: " + string(status)})
	}

	if defaultIn != "" {
		if defaultIn == "deny" || defaultIn == "reject" {
			checks = append(checks, model.Check{	Status: model.StatusOK, Message: "UFW default incoming: " + defaultIn})
		} else {
			checks = append(checks, model.Check{	Status: model.StatusWarning, Message: "UFW default incoming: " + defaultIn + " — ensure SSH is allowed before setting: ufw default deny incoming"})
		}
	}
	if defaultOut != "" {
		checks = append(checks, model.Check{	Status: model.StatusInfo, Message: "UFW default outgoing: " + defaultOut})
	}

	if logging != "" && logging != "on" {
		checks = append(checks, model.Check{	Status: model.StatusInfo, Message: "UFW logging: " + logging + " — enable with: ufw logging on"})
	}

	if status == "active" {
		ruleCount := 0
		hasSSH := false
		for _, line := range lines {
			upper := strings.ToUpper(line)
			if strings.Contains(upper, "ALLOW") || strings.Contains(upper, "DENY") || strings.Contains(upper, "REJECT") || strings.Contains(upper, "LIMIT") {
				ruleCount++
				if strings.Contains(line, sshPort) || strings.Contains(upper, "SSH") || strings.Contains(line, "/22") {
					hasSSH = true
				}
			}
		}
		checks = append(checks, model.Check{	Status: model.StatusInfo, Message: fmt.Sprintf("UFW rules: %d", ruleCount)})
		if !hasSSH {
			checks = append(checks, model.Check{	Status: model.StatusWarning, Message: "No UFW rule for SSH — add: ufw allow " + sshPort})
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
		checks = append(checks, model.Check{	Status: model.StatusInfo, Message: "iptables not installed"})
		return model.Section{Name: "iptables", 	Status: model.StatusInfo, Checks: checks}
	}

	chains := []string{"INPUT", "FORWARD", "OUTPUT"}
	for _, chain := range chains {
		out, _ := runCmd(ctx, "iptables", "-L", chain, "-n", "--line-numbers")
		policy := extractPolicy(out)
		if policy != "" {
			status := model.StatusOK
			if chain == "INPUT" && policy != "DROP" && policy != "REJECT" {
				status = model.StatusWarning
			}
			if chain == "FORWARD" && policy != "DROP" && policy != "REJECT" {
				status = model.StatusWarning
			}
			checks = append(checks, model.Check{
				Status:  status,
				Message: fmt.Sprintf("iptables %s policy: %s", chain, policy),
			})
		}

		rules := countRules(out)
		if rules > 0 {
			checks = append(checks, model.Check{	Status: model.StatusInfo, Message: fmt.Sprintf("iptables %s: %d rules", chain, rules)})
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
			checks = append(checks, model.Check{	Status: model.StatusInfo, Message: "ip6tables has IPv6 rules"})
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
		checks = append(checks, model.Check{	Status: model.StatusInfo, Message: "nftables: no ruleset found"})
		return model.Section{Name: "nftables", 	Status: model.StatusInfo, Checks: checks}
	}

	tableCount := 0
	chainCount := 0
	ruleCount := 0
	inChain := false

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "table "):
			tableCount++
		case strings.HasPrefix(trimmed, "chain "):
			chainCount++
			inChain = true
		case trimmed == "}":
			inChain = false
		case inChain && trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "type "):
			ruleCount++
		}
	}

	checks = append(checks, model.Check{	Status: model.StatusOK, Message: fmt.Sprintf("nftables: %d tables, %d chains, %d rules", tableCount, chainCount, ruleCount)})

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

func diagnoseEffectiveStack(ctx context.Context) model.Section {
	var checks []model.Check

	ufwPresent := hasBinary("ufw")
	iptablesPresent := hasBinary("iptables")
	nftPresent := hasBinary("nft")
	dockerPresent := hasBinary("docker")

	var active []string
	if ufwPresent {
		out, _ := runCmd(ctx, "ufw", "status")
		if strings.Contains(out, "active") {
			active = append(active, "UFW")
		} else {
			active = append(active, "UFW (inactive)")
		}
	}
	if iptablesPresent {
		active = append(active, "iptables")
	}
	if nftPresent {
		active = append(active, "nftables")
	}

	checks = append(checks, model.Check{
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Firewall stack: %s", strings.Join(active, " + ")),
	})

	// Check DOCKER-USER chain if docker is present
	if dockerPresent {
		out, _ := runCmd(ctx, "iptables", "-L", "DOCKER-USER", "-n", "--line-numbers")
		if strings.Contains(out, "Chain DOCKER-USER") {
			ruleCount := countRules(out)
			if ruleCount > 0 {
				checks = append(checks, model.Check{
					Status:  model.StatusOK,
					Message: fmt.Sprintf("DOCKER-USER chain exists with %d rule(s) — Docker-published ports can be filtered", ruleCount),
				})
			} else {
				checks = append(checks, model.Check{
					Status:  model.StatusWarning,
					Message: "DOCKER-USER chain exists but has no rules — Docker-published ports bypass UFW and raw iptables INPUT policy",
				})
			}
		} else {
			checks = append(checks, model.Check{
				Status:  model.StatusWarning,
				Message: "DOCKER-USER chain not found — Docker-published ports bypass UFW and raw iptables INPUT policy",
			})
		}

		// Check if Docker is managing iptables (iptables rules generated by Docker)
		out, _ = runCmd(ctx, "iptables", "-L", "DOCKER", "-n")
		if strings.Contains(out, "Chain DOCKER") {
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: "Docker manages iptables rules — published ports are accessible even if UFW is enabled and set to deny incoming",
			})
		}
	}

	return model.Section{
		Name:   "Effective Stack",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func detectSSHPort(lines []string) string {
	// Look for "22/tcp" or "22" in UFW rule lines like:
	// 22/tcp                     ALLOW IN    Anywhere
	// Also try to find SSH port from sshd config
	port := "22/tcp"
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Match numbered ports like "2222/tcp" or "2222" in UFW rules
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			first := fields[0]
			if strings.HasSuffix(first, "/tcp") || strings.HasSuffix(first, "/udp") {
				if !strings.EqualFold(first, "anywhere") && !strings.Contains(first, ":") {
					port = first
					return port
				}
			}
		}
		// Also match lines with "ssh" service name
		if strings.Contains(strings.ToLower(line), "ssh") {
			// Check that it's actually a service name, not part of a comment
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.EqualFold(f, "ssh") {
					return "ssh"
				}
			}
		}
	}
	return port
}
