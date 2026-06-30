package model

// OSInfo holds parsed /etc/os-release data + system info.
type OSInfo struct {
	PrettyName string `json:"pretty_name"`
	Name       string `json:"name"`
	VersionID  string `json:"version_id"`
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	Kernel     string `json:"kernel"`
}

// Result is the output of a diagnostic run.
type Result struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Status  string  `json:"status"` // ok, warning, critical, unknown
	Summary string  `json:"summary,omitempty"`
	Checks  []Check `json:"checks,omitempty"`
}

// Check is a single diagnostic finding.
type Check struct {
	Status  string `json:"status"` // ok, warning, critical, info
	Message string `json:"message"`
}
