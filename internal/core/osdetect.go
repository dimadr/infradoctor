package core

import (
	"bufio"
	"os"
	"strings"

	"github.com/dimadr/infradoctor/internal/model"
)

// DetectOS reads /etc/os-release, hostname, kernel.
func DetectOS() model.OSInfo {
	info := model.OSInfo{}

	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	if k, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(k))
	}

	parseOSRelease("/etc/os-release", &info)

	return info
}

func parseOSRelease(path string, info *model.OSInfo) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch key {
		case "PRETTY_NAME":
			info.PrettyName = val
		case "NAME":
			info.Name = val
		case "VERSION_ID":
			info.VersionID = val
		case "ID":
			info.ID = val
		}
	}
	_ = scanner.Err()
}

func splitKV(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	key = line[:i]
	val = strings.Trim(line[i+1:], "\"")
	return key, val, true
}
