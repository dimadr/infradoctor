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

// nginxContainerImages lists common nginx image patterns.
var nginxContainerImages = []string{"nginx", "nginx:", "nginxinc/"}

func (m *NginxModule) Detect() bool {
	if hasBinary("nginx") {
		return true
	}
	// Check for nginx running in Docker containers
	if hasBinary("docker") {
		out, _ := runCmd(context.Background(), "docker", "ps", "--format", "{{.Image}}")
		for _, line := range strings.Split(out, "\n") {
			img := strings.TrimSpace(line)
			for _, pattern := range nginxContainerImages {
				if strings.Contains(img, pattern) {
					return true
				}
			}
		}
	}
	return false
}

func (m *NginxModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section
	var recs []model.Recommendation

	hasHostNginx := hasBinary("nginx")
	hasContainerNginx := false

	if !hasHostNginx && hasBinary("docker") {
		// Check for nginx containers
		out, _ := runCmd(ctx, "docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}")
		for _, line := range strings.Split(out, "\n") {
			fields := strings.SplitN(line, "\t", 3)
			if len(fields) >= 2 {
				img := strings.TrimSpace(fields[1])
				for _, pattern := range nginxContainerImages {
					if strings.Contains(img, pattern) {
						hasContainerNginx = true
						sections = append(sections, model.Section{
							Name:   "Container Detection",
							Status: model.StatusInfo,
							Checks: []model.Check{{
								Status:  model.StatusInfo,
								Message: fmt.Sprintf("nginx running in container: %s (image: %s)", fields[2], img),
							}},
						})
						break
					}
				}
			}
		}
	}

	if hasHostNginx {
		sections = append(sections, diagnoseNginxService(ctx))
		sections = append(sections, diagnoseNginxConfig(ctx))
	}

	if hasContainerNginx {
		sections = append(sections, diagnoseNginxContainerConfig(ctx))
	}

	if !hasHostNginx && !hasContainerNginx {
		sections = append([]model.Section{{
			Name:   "Service",
			Status: model.StatusInfo,
			Checks: []model.Check{{Status: model.StatusInfo, Message: "nginx not found on host or in containers"}},
		}}, sections...)
	}

	recs = append(recs, addFlatRecsFromSections(sections, nil)...)

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: recs,
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

func diagnoseNginxContainerConfig(ctx context.Context) model.Section {
	var checks []model.Check

	out, err := runCmd(ctx, "docker", "ps", "--format", "{{.ID}}\t{{.Image}}", "--filter", "ancestor=nginx")
	if err != nil || out == "" {
		out, _ = runCmd(ctx, "docker", "ps", "--format", "{{.ID}}\t{{.Image}}")
	}
	cid := ""
	for _, line := range strings.Split(out, "\n") {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) < 2 {
			continue
		}
		img := strings.TrimSpace(fields[1])
		for _, pattern := range nginxContainerImages {
			if strings.Contains(img, pattern) {
				cid = strings.TrimSpace(fields[0])
				break
			}
		}
		if cid != "" {
			break
		}
	}
	if cid == "" {
		return model.Section{Name: "Container Configuration", Status: model.StatusInfo,
			Checks: []model.Check{{Status: model.StatusInfo, Message: "No nginx container found for config diagnosis"}}}
	}

	_, err = runCmd(ctx, "docker", "exec", cid, "nginx", "-t")
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusCritical,
			Message: fmt.Sprintf("Container nginx -t: config test failed (%v)", err)})
		return model.Section{Name: "Container Configuration", Status: model.StatusCritical, Checks: checks}
	}
	checks = append(checks, model.Check{Status: model.StatusOK,
		Message: "Container nginx config: syntax OK"})

	cOut, err := runCmd(ctx, "docker", "exec", cid, "nginx", "-T")
	if err != nil || cOut == "" {
		checks = append(checks, model.Check{Status: model.StatusInfo,
			Message: "Cannot dump container nginx config"})
		return model.Section{Name: "Container Configuration", Status: sectionStatus(checks), Checks: checks}
	}

	hasHTTP := false
	hasHTTPS := false
	hasRedirect := false
	hasSecurityHeaders := false

	for _, line := range strings.Split(cOut, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "listen") {
			fields := strings.Fields(line)
			for _, f := range fields[1:] {
				if f == "443" || f == "443 ssl" || f == "[::]:443" || strings.Contains(f, ":443") {
					hasHTTPS = true
				} else if f == "80" || f == "[::]:80" || strings.Contains(f, ":80") || strings.Contains(f, ":8080") {
					hasHTTP = true
				}
			}
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
		checks = append(checks, model.Check{Status: model.StatusWarning,
			Message: "HTTP (port 80) enabled but no HTTPS (port 443) detected in container — consider TLS"})
	} else if hasHTTP && hasHTTPS {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "HTTP + HTTPS configured in container"})
		if hasRedirect {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "HTTP to HTTPS redirect detected in container"})
		} else {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: "No HTTP→HTTPS redirect found in container"})
		}
	} else if hasHTTPS {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "HTTPS only in container (no plain HTTP)"})
	}

	if hasSecurityHeaders {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "Security headers detected in container config"})
	}

	return model.Section{
		Name:   "Container Configuration",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}
