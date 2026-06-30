package report

import (
	"testing"
)

func TestSanitize_Password(t *testing.T) {
	in := "password=SuperSecret123"
	out := Sanitize(in)
	if out == in {
		t.Error("password was not masked")
	}
	if !contains(out, "MASKED") {
		t.Errorf("expected MASKED in output, got %q", out)
	}
}

func TestSanitize_Bearer(t *testing.T) {
	in := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret"
	out := Sanitize(in)
	if out == in {
		t.Error("bearer token was not masked")
	}
}

func TestSanitize_PrivateKey(t *testing.T) {
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----"
	out := Sanitize(in)
	if out == in {
		t.Error("private key was not masked")
	}
}

func TestSanitize_ConnectionString(t *testing.T) {
	in := "postgres://admin:secretpass@localhost:5432/db"
	out := Sanitize(in)
	if out == in {
		t.Error("connection string password was not masked")
	}
}

func TestSanitize_Clean(t *testing.T) {
	in := "nothing sensitive here"
	out := Sanitize(in)
	if out != in {
		t.Errorf("clean text was modified: %q", out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstr(s, sub))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
