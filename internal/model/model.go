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

type Result struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Status          string   `json:"status"`
	Summary         string   `json:"summary,omitempty"`
	Sections        []Section `json:"sections,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
}

type Section struct {
	Name   string  `json:"name"`
	Status string  `json:"status"`
	Checks []Check `json:"checks,omitempty"`
}

type Check struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}
