package report

import (
	"regexp"
)

var secretPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// password assignments
	{regexp.MustCompile(`(?i)(password\s*[=:]\s*)\S+`), "${1}***MASKED***"},
	// bearer tokens
	{regexp.MustCompile(`(?i)(bearer\s+)\S+`), "${1}***MASKED***"},
	// authorization headers
	{regexp.MustCompile(`(?i)(authorization\s*[=:]\s*)\S+`), "${1}***MASKED***"},
	// private keys (full block)
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "***PRIVATE_KEY_MASKED***"},
	// generic tokens
	{regexp.MustCompile(`(?i)(token\s*[=:]\s*)\S+`), "${1}***MASKED***"},
	// connection strings with passwords
	{regexp.MustCompile(`(?i)(://[^:]+:)[^@]+(@)`), "${1}***MASKED***${2}"},
}

// Sanitize masks secrets in text.
func Sanitize(text string) string {
	for _, p := range secretPatterns {
		text = p.re.ReplaceAllString(text, p.repl)
	}
	return text
}
