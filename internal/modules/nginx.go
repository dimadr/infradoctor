package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// NginxModule diagnoses nginx configuration, TLS, and security headers.
type NginxModule struct{}

func (m *NginxModule) ID() string   { return "nginx" }
func (m *NginxModule) Name() string { return "Nginx Module" }
func (m *NginxModule) Detect() bool {
	return hasBinary("nginx")
}

func (m *NginxModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseNginxService(ctx))
	sections = append(sections, diagnoseNginxConfig(ctx))

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: collectRecommendations(sections),
	}
}

func diagnoseNginxService(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "nginx", "-v")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "nginx binary not found or not executable"})
		return model.Section{Name: "Service", Status: model.StatusWarning, Checks: checks}
	}
	version := strings.TrimPrefix(out, "nginx version: ")
	checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("nginx version: %s", version)})

	if hasBinary("systemctl") {
		out, _ = runCmd(ctx, "systemctl", "is-active", "nginx")
		if out == "active" {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "nginx service is active"})
		} else if out != "" {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("nginx service is %s", out)})
		}
	}

	return model.Section{
		Name:   "Service",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseNginxConfig(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "nginx", "-t")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusCritical, Message: fmt.Sprintf("nginx -t: config test failed (%v)", err)})
		return model.Section{Name: "Configuration", Status: model.StatusCritical, Checks: checks}
	}
	checks = append(checks, model.Check{Status: model.StatusOK, Message: "nginx -t: config syntax OK"})

	out, err = runCmd(ctx, "nginx", "-T")
	if err != nil || out == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Cannot dump nginx config"})
		return model.Section{Name: "Configuration", Status: sectionStatus(checks), Checks: checks}
	}

	hasHTTP := false
	hasHTTPS := false
	hasRedirect := false
	hasSecurityHeaders := false
	exposedPorts := map[string]bool{}
	var serverNames []string

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "listen") {
			fields := strings.Fields(line)
			for _, f := range fields[1:] {
				if f == "443" || f == "443 ssl" || f == "[::]:443" || strings.Contains(f, ":443") {
					hasHTTPS = true
				} else if f == "80" || f == "[::]:80" || strings.Contains(f, ":80") || strings.Contains(f, ":8080") {
					hasHTTP = true
				}
				for _, p := range strings.Fields(f) {
					if !strings.Contains(p, "$") && !strings.HasPrefix(p, "proxy_") {
						exposedPorts[p] = true
					}
				}
			}
		}

		if strings.HasPrefix(line, "server_name ") {
			name := strings.TrimPrefix(line, "server_name ")
			name = strings.TrimSuffix(name, ";")
			serverNames = append(serverNames, name)
		}

		if strings.Contains(line, "return 301") || strings.Contains(line, "return 302") {
			hasRedirect = true
		}

		if strings.Contains(line, "X-Content-Type-Options") ||
			strings.Contains(line, "X-Frame-Options") ||
			strings.Contains(line, "X-XSS-Protection") ||
			strings.Contains(line, "Strict-Transport-Security") ||
			strings.Contains(line, "Content-Security-Policy") {
			hasSecurityHeaders = true
		}
	}

	if hasHTTP && !hasHTTPS {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "HTTP (port 80) enabled but no HTTPS (port 443) detected — consider TLS"})
	} else if hasHTTP && hasHTTPS {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "HTTP + HTTPS configured"})
		if hasRedirect {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "HTTP to HTTPS redirect detected"})
		} else {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No HTTP→HTTPS redirect found"})
		}
	} else if hasHTTPS {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "HTTPS only (no plain HTTP)"})
	}

	if hasSecurityHeaders {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Security headers detected (HSTS, CSP, X-Frame-Options, etc.)"})
	}

	checks = append(checks, model.Check{Status: model.StatusInfo, Message: fmt.Sprintf("SSL/HTTPS enabled: %t, HTTP enabled: %t", hasHTTPS, hasHTTP)})

	return model.Section{
		Name:   "Configuration",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}
