package modules

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// NetworkingModule diagnoses network interfaces, listening ports, routing, and DNS.
type NetworkingModule struct{}

func (m *NetworkingModule) ID() string   { return "networking" }
func (m *NetworkingModule) Name() string { return "Networking Module" }
func (m *NetworkingModule) Detect() bool {
	return hasBinary("ss") || hasBinary("ip") || hasBinary("route")
}

func (m *NetworkingModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseListeningPorts(ctx))
	sections = append(sections, diagnoseRouting(ctx))
	sections = append(sections, diagnoseDNS(ctx))

	// Manual recommendations for risky public services
	var recs []model.Recommendation
	var riskyServices []struct {
		svc  string
		port string
		addr string
	}
	for _, sec := range sections {
		if sec.Name == "Listening Ports" {
			for _, c := range sec.Checks {
				if strings.Contains(c.Message, "risky service") {
					msg := c.Message
					var svc, port, addr string
					if _, after, ok := strings.Cut(msg, " — risky service ("); ok {
						if end := strings.LastIndex(after, ")"); end > 0 {
							svc = after[:end]
						}
					}
					fields := strings.Fields(msg)
					for i, f := range fields {
						if f == "port" && i+1 < len(fields) {
							port = fields[i+1]
						}
						if f == "on" && i+1 < len(fields) && addr == "" {
							addr = fields[i+1]
						}
					}
					if svc != "" {
						riskyServices = append(riskyServices, struct {
							svc  string
							port string
							addr string
						}{svc, port, addr})
					}
				}
			}
		}
	}
	for _, rs := range riskyServices {
		recs = append(recs, buildRecommendation(
			"networking.risky_service",
			model.StatusWarning,
			fmt.Sprintf("%s exposed on all interfaces (port %s)", rs.svc, rs.port),
			fmt.Sprintf("%s is listening on %s port %s, accessible from any network interface", rs.svc, rs.addr, rs.port),
			fmt.Sprintf("Unauthorized access to %s if not properly authenticated", rs.svc),
			fmt.Sprintf("Bind %s to localhost only, or restrict with firewall rules", rs.svc),
			fmt.Sprintf("ss -tulpn | grep ':%s '", rs.port),
			false,
		))
	}
	// Flat recs for uncovered warnings (e.g., no DNS servers)
	skipPatterns := map[string][]string{
		"Listening Ports": {"networking.risky_service"},
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

var riskyPorts = map[int]string{
	5432:  "PostgreSQL",
	5434:  "PostgreSQL (alt)",
	6379:  "Redis",
	6380:  "Redis (SSL)",
	27017: "MongoDB",
	3306:  "MySQL/MariaDB",
	9200:  "Elasticsearch",
	8086:  "InfluxDB",
	8443:  "Alternative HTTPS",
	9090:  "Prometheus",
}

type listenEntry struct {
	proto    string
	addr     string
	port     int
	process  string
	isPublic bool
}

func diagnoseListeningPorts(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "ss", "-tulpen")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "ss: unable to list listening ports"})
		return model.Section{Name: "Listening Ports", Status: model.StatusWarning, Checks: checks}
	}

	var entries []listenEntry
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := fields[0]
		localAddr := fields[4]

		addr, portStr, err := netSplitHostPort(localAddr)
		if err != nil {
			continue
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		isPublic := addr == "0.0.0.0" || addr == "::" || addr == "[::]"
		process := ""
		for _, f := range fields {
			if strings.HasPrefix(f, "users:((") {
				procInfo := strings.TrimPrefix(f, "users:((")
				procInfo = strings.TrimSuffix(procInfo, "))")
				parts := strings.Split(procInfo, ",")
				if len(parts) > 0 {
					sub := strings.Split(parts[0], "\"")
					if len(sub) >= 2 {
						process = sub[1]
					}
				}
			}
		}

		entries = append(entries, listenEntry{
			proto:    proto,
			addr:     addr,
			port:     port,
			process:  process,
			isPublic: isPublic,
		})
	}

	if len(entries) == 0 {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No listening ports found"})
		return model.Section{Name: "Listening Ports", Status: model.StatusInfo, Checks: checks}
	}

	var publicPorts, localPorts int
	for _, e := range entries {
		if e.isPublic {
			publicPorts++
		} else {
			localPorts++
		}
	}

	checks = append(checks, model.Check{
		Code:    "networking.port_count",
		Status:  model.StatusInfo,
		Message: fmt.Sprintf("Total listening ports: %d (%d public, %d local-only)", len(entries), publicPorts, localPorts),
	})

	for _, e := range entries {
		svc, isRisky := riskyPorts[e.port]
		status := model.StatusInfo
		msg := fmt.Sprintf("%s port %d on %s", strings.ToUpper(e.proto), e.port, e.addr)
		if e.process != "" {
			msg += fmt.Sprintf(" [%s]", e.process)
		}
		code := ""
		if isRisky && e.isPublic {
			status = model.StatusWarning
			code = "networking.risky_service"
			msg += fmt.Sprintf(" — risky service (%s) exposed on all interfaces", svc)
		} else if isRisky {
			status = model.StatusInfo
			msg += fmt.Sprintf(" (%s, local only)", svc)
		}
		checks = append(checks, model.Check{Code: code, Status: status, Message: msg})
	}

	ipv6Only := 0
	for _, e := range entries {
		if e.addr == "::" || e.addr == "[::]" {
			ipv6Only++
		}
	}
	if ipv6Only > 0 {
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: fmt.Sprintf("%d port(s) listening on IPv6 only", ipv6Only),
		})
	}

	return model.Section{
		Name:   "Listening Ports",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseRouting(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "ip", "route", "show", "default")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No default gateway found"})
		return model.Section{Name: "Routing", Status: model.StatusInfo, Checks: checks}
	}

	fields := strings.Fields(out)
	if len(fields) >= 3 {
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: fmt.Sprintf("Default gateway: %s", fields[2]),
		})
	}

	out, err = runCmd(ctx, "ip", "route", "show", "table", "all")
	if err == nil {
		routes := strings.Split(out, "\n")
		routeCount := 0
		for _, line := range routes {
			if strings.TrimSpace(line) != "" {
				routeCount++
			}
		}
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: fmt.Sprintf("Total routes: %d", routeCount),
		})
	}

	return model.Section{
		Name:   "Routing",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseDNS(ctx context.Context) model.Section {
	var checks []model.Check

	resolv, err := runCmd(ctx, "cat", "/etc/resolv.conf")
	if err != nil || resolv == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Cannot read /etc/resolv.conf"})
		return model.Section{Name: "DNS", Status: model.StatusInfo, Checks: checks}
	}

	dnsServers := 0
	for _, line := range strings.Split(resolv, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			dnsServers++
			checks = append(checks, model.Check{
				Status:  model.StatusInfo,
				Message: fmt.Sprintf("DNS server: %s", strings.TrimPrefix(line, "nameserver ")),
			})
		}
	}

	if dnsServers == 0 {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "No DNS nameservers configured in /etc/resolv.conf"})
	}

	return model.Section{
		Name:   "DNS",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func netSplitHostPort(addr string) (host, port string, err error) {
	if strings.HasPrefix(addr, "[") {
		// IPv6: [::1]:80
		closeBracket := strings.LastIndex(addr, "]")
		if closeBracket < 0 {
			return "", "", fmt.Errorf("invalid IPv6 address: %s", addr)
		}
		host = addr[1:closeBracket]
		if len(addr) > closeBracket+1 && addr[closeBracket+1] == ':' {
			port = addr[closeBracket+2:]
		}
	} else {
		// IPv4: 0.0.0.0:80
		lastColon := strings.LastIndex(addr, ":")
		if lastColon < 0 {
			return "", "", fmt.Errorf("no port in address: %s", addr)
		}
		host = addr[:lastColon]
		port = addr[lastColon+1:]
	}
	return host, port, nil
}
