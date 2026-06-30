package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSSHConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")

	if err := os.WriteFile(cfg, []byte("Port 2222\nPermitRootLogin no\n"), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := readSSHConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if config["Port"] != "2222" {
		t.Errorf("Port = %q, want %q", config["Port"], "2222")
	}
	if config["PermitRootLogin"] != "no" {
		t.Errorf("PermitRootLogin = %q, want %q", config["PermitRootLogin"], "no")
	}
}

func TestReadSSHConfig_WithInclude(t *testing.T) {
	dir := t.TempDir()
	mainCfg := filepath.Join(dir, "sshd_config")
	incDir := filepath.Join(dir, "sshd_config.d")
	if err := os.MkdirAll(incDir, 0755); err != nil {
		t.Fatal(err)
	}
	incFile := filepath.Join(incDir, "01-custom.conf")

	if err := os.WriteFile(mainCfg, []byte("Port 2222\nInclude "+incDir+"/*.conf\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(incFile, []byte("PermitRootLogin prohibit-password\n"), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := readSSHConfig(mainCfg)
	if err != nil {
		t.Fatal(err)
	}

	if config["Port"] != "2222" {
		t.Errorf("Port = %q, want %q", config["Port"], "2222")
	}
	if config["PermitRootLogin"] != "prohibit-password" {
		t.Errorf("PermitRootLogin = %q, want %q", config["PermitRootLogin"], "prohibit-password")
	}
}

func TestReadSSHConfig_CommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")

	content := "# This is a comment\n\nPort 2222\n# Another comment\nPermitRootLogin no\n"
	if err := os.WriteFile(cfg, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := readSSHConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(config) != 2 {
		t.Errorf("got %d keys, want 2", len(config))
	}
}

func TestReadSSHConfig_MissingFile(t *testing.T) {
	_, err := readSSHConfig("/nonexistent/sshd_config")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReadSSHConfig_QuotedValue(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sshd_config")

	if err := os.WriteFile(cfg, []byte(`Banner "/etc/ssh/banner"`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	config, err := readSSHConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if config["Banner"] != "/etc/ssh/banner" {
		t.Errorf("Banner = %q, want %q", config["Banner"], "/etc/ssh/banner")
	}
}
