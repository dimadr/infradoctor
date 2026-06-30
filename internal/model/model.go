package model

// Status type for diagnostic results.
type Status string

const (
	StatusOK       Status = "ok"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
	StatusInfo     Status = "info"
	StatusUnknown  Status = "unknown"
)

// OSInfo holds parsed /etc/os-release data + system info.
type OSInfo struct {
	PrettyName string `json:"pretty_name"`
	Name       string `json:"name"`
	VersionID  string `json:"version_id"`
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	Kernel     string `json:"kernel"`
}

// Recommendation is a structured recommendation with context, impact, and action.
type Recommendation struct {
	Severity Status `json:"severity"`
	Title    string `json:"title"`
	Context  string `json:"context,omitempty"`
	Impact   string `json:"impact,omitempty"`
	Action   string `json:"action,omitempty"`
	Command  string `json:"command,omitempty"`
	Safe     bool   `json:"safe"`
}

// Result holds the full diagnostic output of a single module.
type Result struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Status          Status           `json:"status"`
	Summary         string           `json:"summary,omitempty"`
	Sections        []Section        `json:"sections,omitempty"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
}

// Section is a named group of checks within a module result.
type Section struct {
	Name   string  `json:"name"`
	Status Status  `json:"status"`
	Checks []Check `json:"checks,omitempty"`
}

// Check is a single diagnostic observation.
type Check struct {
	Status  Status `json:"status"`
	Message string `json:"message"`
}
