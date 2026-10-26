package yaml_test

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/config/adapters/store/yaml"
)

// vulndb.url loads as written; absent, or written with no value, is vuln.go.dev.
func TestParse_VulnDBSection(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"vulndb:\n", ""},
		{"vulndb:\n  url:\n", ""},
		{"vulndb:\n  url: https://mirror.example.com/go/\n", "https://mirror.example.com/go/"},
	} {
		cfg, err := yaml.Parse([]byte("version: \"3\"\n" + tc.in))
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if cfg.VulnDB.URL != tc.want {
			t.Errorf("%q: vulndb.url = %q, want %q", tc.in, cfg.VulnDB.URL, tc.want)
		}
	}
	_, err := yaml.Parse([]byte("version: \"3\"\nvulndb:\n  url: http://mirror.example.com\n"))
	want := `vulndb.url requires an https:// URL with a host (the base of a mirror of https://vuln.go.dev), got "http://mirror.example.com"`
	if err == nil || err.Error() != want {
		t.Errorf("http mirror: err = %v\nwant %s", err, want)
	}
}
