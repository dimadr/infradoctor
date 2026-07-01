package modules

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// SSHModule diagnoses SSH server configuration, authentication, keys, and security.
type SSHModule struct{}

func (m *SSHModule) ID() string   { return "ssh" }
func (m *SSHModule) Name() string { return "SSH Module" }
func (m *SSHModule) Detect() bool {
	_, err := exec.LookPath("sshd")
	return err == nil
}

func (m *SSHModule) Diagnose(ctx context.Context) model.Result {
	var sections []model.Section

	sections = append(sections, diagnoseSSHService(ctx))
	sections = append(sections, diagnoseSSHConfig(ctx))
	sections = append(sections, diagnoseSSHAuth(ctx))
	sections = append(sections, diagnoseSSHKeys())
	sections = append(sections, diagnoseSSHPermissions())
	sections = append(sections, diagnoseSSHSecurity(ctx))

	// Determine which key risks are present
	hasRootLogin := false
	hasPasswordAuth := false
	hasEmptyPasswords := false
	hasDSAKey := false
	hasX11Forwarding := false
	hasGatewayPorts := false
	for _, sec := range sections {
		for _, c := range sec.Checks {
			switch {
			case strings.Contains(c.Message, "PermitRootLogin: yes"):
				hasRootLogin = true
			case strings.Contains(c.Message, "PasswordAuthentication: yes"):
				hasPasswordAuth = true
			case strings.Contains(c.Message, "PermitEmptyPasswords: yes"):
				hasEmptyPasswords = true
			case strings.Contains(c.Message, "DSA host key present"):
				hasDSAKey = true
			case strings.Contains(c.Message, "X11Forwarding: yes"):
				hasX11Forwarding = true
			case strings.Contains(c.Message, "GatewayPorts: yes"):
				hasGatewayPorts = true
			}
		}
	}
	// Build manual recs for found risks only
	var recs []model.Recommendation
	if hasRootLogin {
		recs = append(recs, buildRecommendation("ssh.permit_root_login", model.StatusWarning, "Root SSH login allowed with password",
			"PermitRootLogin is set to 'yes', allowing direct root login with password",
			"Attackers can brute-force root password directly via SSH",
			"Change PermitRootLogin to 'prohibit-password' to require key-based auth for root",
			"sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && systemctl reload sshd",
			false,
		))
	}
	if hasPasswordAuth {
		recs = append(recs, buildRecommendation("ssh.password_auth", model.StatusWarning, "SSH password authentication enabled",
			"PasswordAuthentication is enabled, allowing password-based logins",
			"Increases risk of brute-force attacks against SSH",
			"Disable password auth and use key-based authentication only",
			"sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd",
			false,
		))
	}
	if hasEmptyPasswords {
		recs = append(recs, buildRecommendation("ssh.empty_passwords", model.StatusCritical, "SSH allows empty password logins",
			"PermitEmptyPasswords is set to 'yes', allowing login with no password",
			"Any user with an empty password can log in via SSH — immediate risk",
			"Set PermitEmptyPasswords to 'no' immediately",
			"sed -i 's/^PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config && systemctl reload sshd",
			true,
		))
	}
	if hasDSAKey {
		recs = append(recs, buildRecommendation("ssh.dsa_key", model.StatusWarning, "DSA host key in use",
			"DSA host key found — DSA is deprecated and considered weak (limited to 1024 bits)",
			"SSH connections using DSA host key verification are less secure",
			"Remove DSA host key and use Ed25519 or ECDSA",
			"rm /etc/ssh/ssh_host_dsa_key* && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''",
			false,
		))
	}
	if hasX11Forwarding {
		recs = append(recs, buildRecommendation("ssh.x11_forwarding", model.StatusWarning, "SSH X11 forwarding enabled",
			"X11Forwarding is enabled, allowing X11 traffic over SSH connections",
			"Increases attack surface — X11 forwarding can be abused to capture keystrokes or screen content",
			"Disable X11 forwarding if not required",
			"sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config && systemctl reload sshd",
			true,
		))
	}
	if hasGatewayPorts {
		recs = append(recs, buildRecommendation("ssh.gateway_ports", model.StatusWarning, "SSH GatewayPorts enabled",
			"GatewayPorts allows remote hosts to connect to forwarded ports, not just localhost",
			"SSH port forwarding becomes accessible from other hosts, increasing exposure",
			"Disable GatewayPorts if remote forwarding is not needed",
			"sed -i 's/^GatewayPorts yes/GatewayPorts no/' /etc/ssh/sshd_config && systemctl reload sshd",
			true,
		))
	}
	// Codes that identify checks covered by manual recommendations
	skipCodes := []string{
		"ssh.permit_root_login",
		"ssh.password_auth",
		"ssh.empty_passwords",
		"ssh.dsa_key",
		"ssh.x11_forwarding",
		"ssh.gateway_ports",
	}
	// Add flat recs for uncovered warnings/criticals
	for _, sec := range sections {
		recs = append(recs, addFlatRecs(sec.Checks, skipCodes)...)
	}

	return model.Result{
		ID:              m.ID(),
		Name:            m.Name(),
		Status:          aggregateStatus(sections),
		Sections:        sections,
		Recommendations: recs,
	}
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func diagnoseSSHService(ctx context.Context) model.Section {
	var checks []model.Check

	unitName := detectSSHUnit(ctx)

	out, _ := runCmd(ctx, "systemctl", "is-active", unitName)
	if out == "" {
		out = "unknown"
	}

	isActive := out == "active"
	checks = append(checks, model.Check{
		Status:  checkStatus(isActive),
		Message: fmt.Sprintf("%s service is %s", unitName, out),
	})

	out, _ = runCmd(ctx, "systemctl", "is-enabled", unitName)
	if out == "" {
		out = "unknown"
	}
	checks = append(checks, model.Check{
		Status:  checkStatus(out == "enabled"),
		Message: fmt.Sprintf("%s is %s on boot", unitName, out),
	})

	// Socket activation: on Ubuntu 24.04 ssh.socket may be active while ssh.service is not
	sockOut, _ := runCmd(ctx, "systemctl", "is-active", "ssh.socket")
	if sockOut == "active" {
		checks = append(checks, model.Check{
			Status:  model.StatusInfo,
			Message: "ssh.socket is active — SSH works via socket activation even if ssh.service is inactive",
		})
	}

	// Show actual listen address/port from ss
	ssOut, _ := runCmd(ctx, "ss", "-tulpn")
	for _, line := range strings.Split(ssOut, "\n") {
		if strings.Contains(line, "sshd") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				checks = append(checks, model.Check{
					Status:  model.StatusInfo,
					Message: fmt.Sprintf("SSH listening on: %s (%s)", fields[4], fields[0]),
				})
			}
		}
	}

	return model.Section{
		Name:   "Service Status",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func detectSSHUnit(ctx context.Context) string {
	var activeUnit, existingUnit string

	for _, name := range []string{"sshd", "ssh"} {
		out, err := runCmd(ctx, "systemctl", "is-active", name)
		if err == nil && out == "active" {
			activeUnit = name
		}
		if out == "" || strings.Contains(out, "could not be found") {
			continue
		}
		if existingUnit == "" {
			existingUnit = name
		}
	}

	if activeUnit != "" {
		return activeUnit
	}
	if existingUnit != "" {
		return existingUnit
	}
	return "sshd"
}

func diagnoseSSHConfig(ctx context.Context) model.Section {
	var checks []model.Check

	if _, err := runCmd(ctx, "sshd", "-t"); err != nil {
		checks = append(checks, model.Check{
			Status:  model.StatusCritical,
			Message: fmt.Sprintf("sshd -t: syntax error (%v)", err),
		})
	} else {
		checks = append(checks, model.Check{
			Status:  model.StatusOK,
			Message: "sshd -t: config syntax OK",
		})
	}

	if _, err := os.Stat("/etc/ssh/sshd_config"); err == nil {
		checks = append(checks, model.Check{
			Status:  model.StatusOK,
			Message: "/etc/ssh/sshd_config exists",
		})
	} else {
		checks = append(checks, model.Check{
			Status:  model.StatusCritical,
			Message: "/etc/ssh/sshd_config not found",
		})
	}

	return model.Section{
		Name:   "Configuration",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSSHAuth(ctx context.Context) model.Section {
	config, err := readEffectiveConfig(ctx)
	if err != nil {
		config, err = readSSHConfig("/etc/ssh/sshd_config")
		if err != nil {
			return model.Section{
				Name:   "Authentication",
				Status: model.StatusUnknown,
				Checks: []model.Check{{Status: model.StatusUnknown, Message: fmt.Sprintf("cannot read sshd_config: %v", err)}},
			}
		}
	}

	var checks []model.Check

	val := config["permitrootlogin"]
	switch val {
	case "yes":
		checks = append(checks, model.Check{Code: "ssh.permit_root_login", Status: model.StatusWarning, Message: "PermitRootLogin: yes (consider 'prohibit-password' or 'no')"})
	case "prohibit-password", "without-password":
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "PermitRootLogin: " + val})
	case "no":
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "PermitRootLogin: no"})
	default:
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "PermitRootLogin: " + val})
	}

	val = config["passwordauthentication"]
	switch val {
	case "yes":
		checks = append(checks, model.Check{Code: "ssh.password_auth", Status: model.StatusWarning, Message: "PasswordAuthentication: yes (consider key-based auth)"})
	case "no":
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "PasswordAuthentication: no"})
	default:
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "PasswordAuthentication: " + val})
	}

	val = config["pubkeyauthentication"]
	switch val {
	case "yes":
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "PubkeyAuthentication: yes"})
	case "no":
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "PubkeyAuthentication: no (public key auth disabled)"})
	default:
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "PubkeyAuthentication: " + val})
	}

	val = config["kbdinteractiveauthentication"]
	if val == "yes" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "KbdInteractiveAuthentication: yes"})
	}

	val = config["challengeresponseauthentication"]
	if val == "yes" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "ChallengeResponseAuthentication: yes"})
	}

	if v := config["allowusers"]; v != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "AllowUsers: " + v})
	}
	if v := config["allowgroups"]; v != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "AllowGroups: " + v})
	}
	if v := config["denyusers"]; v != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "DenyUsers: " + v})
	}
	if v := config["denygroups"]; v != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "DenyGroups: " + v})
	}

	val = config["permitemptypasswords"]
	if val == "yes" {
		checks = append(checks, model.Check{Code: "ssh.empty_passwords", Status: model.StatusCritical, Message: "PermitEmptyPasswords: yes (allows empty password logins)"})
	} else if val == "no" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "PermitEmptyPasswords: no"})
	}

	if v := config["authenticationmethods"]; v != "" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "AuthenticationMethods: " + v})
	}

	return model.Section{
		Name:   "Authentication",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSSHKeys() model.Section {
	var checks []model.Check

	authKeys := filepath.Join(homeDir(), ".ssh", "authorized_keys")
	data, err := os.ReadFile(authKeys)
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "No authorized_keys found — key-based auth may not work"})
	} else {
		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "ssh-") || strings.HasPrefix(line, "ecdsa-") || strings.HasPrefix(line, "sk-") {
				count++
			}
		}
		if count == 0 {
			checks = append(checks, model.Check{Status: model.StatusWarning, Message: "authorized_keys exists but contains no valid keys"})
		} else {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("authorized_keys: %d key(s) configured", count)})
		}
	}

	hostKeyDir := "/etc/ssh"
	hostKeyTypes := []struct {
		file    string
		keyType string
	}{
		{"ssh_host_rsa_key", "RSA"},
		{"ssh_host_ecdsa_key", "ECDSA"},
		{"ssh_host_ed25519_key", "Ed25519"},
		{"ssh_host_dsa_key", "DSA"},
	}

	var found []string
	hasDSA := false
	for _, hk := range hostKeyTypes {
		privPath := filepath.Join(hostKeyDir, hk.file)

		if info, err := os.Stat(privPath); err == nil {
			perm := info.Mode().Perm()
			if perm&0077 != 0 {
				checks = append(checks, model.Check{Status: model.StatusWarning, Message: fmt.Sprintf("%s: permissions %04o (should be 0600)", hk.file, perm)})
			}
			if hk.keyType == "DSA" {
				hasDSA = true
			}
			found = append(found, hk.keyType)
		}
	}

	if hasDSA {
		checks = append(checks, model.Check{Code: "ssh.dsa_key", Status: model.StatusWarning, Message: "DSA host key present — DSA is deprecated and considered weak"})
	}

	if len(found) > 0 {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("Host keys: %s", strings.Join(found, ", "))})
	}

	return model.Section{
		Name:   "SSH Keys",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSSHPermissions() model.Section {
	var checks []model.Check

	sshDir := filepath.Join(homeDir(), ".ssh")
	info, err := os.Stat(sshDir)
	if err != nil {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: fmt.Sprintf("%s: %v", sshDir, err)})
		return model.Section{Name: "Permissions", Status: model.StatusWarning, Checks: checks}
	}
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: fmt.Sprintf("%s: permissions %04o (should be 0700)", sshDir, perm)})
	} else {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("%s: permissions %04o", sshDir, perm)})
	}

	authKeys := filepath.Join(sshDir, "authorized_keys")
	info, err = os.Stat(authKeys)
	if err == nil {
		perm = info.Mode().Perm()
		if perm&0077 != 0 || perm&0044 != 0 {
			checks = append(checks, model.Check{Status: model.StatusWarning, Message: fmt.Sprintf("%s: permissions %04o (should be 0600)", authKeys, perm)})
		} else {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: fmt.Sprintf("%s: permissions %04o", authKeys, perm)})
		}
	}

	return model.Section{
		Name:   "Permissions",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func diagnoseSSHSecurity(ctx context.Context) model.Section {
	config, err := readEffectiveConfig(ctx)
	if err != nil {
		config, err = readSSHConfig("/etc/ssh/sshd_config")
		if err != nil {
			return model.Section{
				Name:   "Security",
				Status: model.StatusUnknown,
				Checks: []model.Check{{Status: model.StatusUnknown, Message: fmt.Sprintf("cannot read sshd_config: %v", err)}},
			}
		}
	}

	var checks []model.Check

	if v := config["protocol"]; v != "" {
		if v == "1" {
			checks = append(checks, model.Check{Status: model.StatusCritical, Message: "Protocol: 1 (insecure, use Protocol 2)"})
		} else {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "Protocol: " + v})
		}
	}

	if v := config["loglevel"]; v != "" {
		if v == "INFO" || v == "VERBOSE" {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "LogLevel: " + v})
		} else {
			checks = append(checks, model.Check{Status: model.StatusInfo, Message: "LogLevel: " + v})
		}
	}

	if v := config["maxauthtries"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n <= 3 {
			checks = append(checks, model.Check{Status: model.StatusOK, Message: "MaxAuthTries: " + v})
		} else {
			checks = append(checks, model.Check{Status: model.StatusWarning, Message: "MaxAuthTries: " + v + " (consider ≤ 3)"})
		}
	}

	if v := config["clientaliveinterval"]; v != "" && v != "0" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "ClientAliveInterval: " + v})
	}

	if v := config["usepam"]; v == "yes" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "UsePAM: yes"})
	}

	if v := config["x11forwarding"]; v == "yes" {
		checks = append(checks, model.Check{Code: "ssh.x11_forwarding", Status: model.StatusWarning, Message: "X11Forwarding: yes (disable unless needed)"})
	}

	if v := config["allowtcpforwarding"]; v == "no" {
		checks = append(checks, model.Check{Status: model.StatusOK, Message: "AllowTcpForwarding: no"})
	}

	if v := config["gatewayports"]; v == "yes" {
		checks = append(checks, model.Check{Code: "ssh.gateway_ports", Status: model.StatusWarning, Message: "GatewayPorts: yes (allows remote hosts to connect to forwarded ports)"})
	}

	if v := config["permittunnel"]; v != "" && v != "no" {
		checks = append(checks, model.Check{Status: model.StatusInfo, Message: "PermitTunnel: " + v})
	}

	if v := config["permituserenvironment"]; v == "yes" {
		checks = append(checks, model.Check{Status: model.StatusWarning, Message: "PermitUserEnvironment: yes (may allow environment variable injection via ~/.ssh/environment)"})
	}

	return model.Section{
		Name:   "Security",
		Status: sectionStatus(checks),
		Checks: checks,
	}
}

func readSSHConfig(path string) (map[string]string, error) {
	config := make(map[string]string)
	var includes []string

	baseDir := filepath.Dir(path)
	if err := parseSSHFile(path, config, &includes, baseDir); err != nil {
		return nil, err
	}

	for _, pattern := range includes {
		files, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Strings(files)
		for _, f := range files {
			if _, err := os.Stat(f); err != nil {
				continue
			}
			parseSSHFile(f, config, nil, baseDir)
		}
	}

	return config, nil
}

func parseSSHFile(path string, config map[string]string, includes *[]string, baseDir string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := strings.TrimSpace(parts[1])

		if strings.EqualFold(key, "include") {
			if includes != nil {
				val = strings.Trim(val, "\"")
				for _, p := range strings.Fields(val) {
					if !filepath.IsAbs(p) {
						p = filepath.Join(baseDir, p)
					}
					*includes = append(*includes, p)
				}
			}
			continue
		}

		val = strings.Trim(val, "\"")
		config[key] = val
	}
	return scanner.Err()
}

func readEffectiveConfig(ctx context.Context) (map[string]string, error) {
	out, err := runCmd(ctx, "sshd", "-T")
	if err != nil {
		return nil, fmt.Errorf("sshd -T: %w", err)
	}
	config := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			config[parts[0]] = strings.TrimSpace(parts[1])
		}
	}
	return config, nil
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/root"
	}
	return home
}

func checkStatus(ok bool) model.Status {
	if ok {
		return model.StatusOK
	}
	return model.StatusWarning
}

func sectionStatus(checks []model.Check) model.Status {
	status := model.StatusOK
	for _, c := range checks {
		switch c.Status {
		case model.StatusCritical:
			return model.StatusCritical
		case model.StatusWarning:
			status = model.StatusWarning
		case model.StatusUnknown:
			if status != model.StatusWarning && status != model.StatusCritical {
				status = model.StatusUnknown
			}
		}
	}
	return status
}
