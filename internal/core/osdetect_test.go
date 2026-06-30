package core

import (
	"path/filepath"
	"testing"

	"github.com/dimadr/infradoctor/internal/model"
)

func TestParseOSRelease_Ubuntu(t *testing.T) {
	var info model.OSInfo
	parseOSRelease(filepath.Join("..", "..", "testdata", "os-release", "ubuntu"), &info)

	if info.PrettyName != "Ubuntu 24.04 LTS" {
		t.Errorf("PrettyName: got %q, want %q", info.PrettyName, "Ubuntu 24.04 LTS")
	}
	if info.Name != "Ubuntu" {
		t.Errorf("Name: got %q, want %q", info.Name, "Ubuntu")
	}
	if info.ID != "ubuntu" {
		t.Errorf("ID: got %q, want %q", info.ID, "ubuntu")
	}
	if info.VersionID != "24.04" {
		t.Errorf("VersionID: got %q, want %q", info.VersionID, "24.04")
	}
}

func TestParseOSRelease_Debian(t *testing.T) {
	var info model.OSInfo
	parseOSRelease(filepath.Join("..", "..", "testdata", "os-release", "debian"), &info)

	if info.PrettyName != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("PrettyName: got %q, want %q", info.PrettyName, "Debian GNU/Linux 12 (bookworm)")
	}
	if info.ID != "debian" {
		t.Errorf("ID: got %q, want %q", info.ID, "debian")
	}
}

func TestParseOSRelease_Missing(t *testing.T) {
	var info model.OSInfo
	parseOSRelease("/nonexistent/path", &info)

	if info.Name != "" {
		t.Errorf("expected empty Name for missing file, got %q", info.Name)
	}
}

func TestSplitKV(t *testing.T) {
	tests := []struct {
		line    string
		wantKey string
		wantVal string
		wantOK  bool
	}{
		{`ID=ubuntu`, "ID", "ubuntu", true},
		{`PRETTY_NAME="Ubuntu 24.04"`, "PRETTY_NAME", "Ubuntu 24.04", true},
		{"", "", "", false},
		{"nodelimiter", "", "", false},
	}
	for _, tc := range tests {
		key, val, ok := splitKV(tc.line)
		if ok != tc.wantOK || key != tc.wantKey || val != tc.wantVal {
			t.Errorf("splitKV(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.line, key, val, ok, tc.wantKey, tc.wantVal, tc.wantOK)
		}
	}
}
