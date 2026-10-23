package domain

import "testing"

// Only a real mirror is a mirror: unset, and vuln.go.dev itself with or
// without a trailing slash, record no origin.
func TestVulnDBConfig_Mirror(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"https://vuln.go.dev", ""},
		{"https://vuln.go.dev/", ""},
		{"https://mirror.example.com/go/", "https://mirror.example.com/go"},
		{"https://mirror.example.com", "https://mirror.example.com"},
	} {
		if got := (VulnDBConfig{URL: tc.in}).Mirror(); got != tc.want {
			t.Errorf("Mirror(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
