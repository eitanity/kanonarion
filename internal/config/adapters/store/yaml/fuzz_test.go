package yaml_test

import (
	"strings"
	"testing"

	configyaml "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
)

// FuzzParse fuzzes the config YAML loader. Config files are operator-supplied
// local input (relates, relates); a malformed or hostile file
// must degrade to an error, never panic or parse unboundedly. gopkg.in/yaml.v3
// caps alias expansion. Contract asserted: Parse returns (zero, error) or a
// Config with a non-empty Version and the optional sections defaulted.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzParse./internal/config/adapters/store/yaml
func FuzzParse(f *testing.F) {
	// Valid config.
	f.Add([]byte("version: \"1\"\npreferences:\n  json: true\n  log_level: debug\n"))
	// Valid with license policy rules.
	f.Add([]byte(`version: "1"
license_policy:
  categories:
    permissive: [MIT, Apache-2.0]
  rules:
    - scope: production
      allow: [permissive]
      default: warn
      unknown_license: block
`))
	// Minimal.
	f.Add([]byte("version: \"1\"\n"))
	// Missing version.
	f.Add([]byte("preferences:\n  json: true\n"))
	// Version newer than supported.
	f.Add([]byte("version: \"99\"\n"))
	// Invalid enum values (defined error paths in parseOutcome/parseUnknownLicense).
	f.Add([]byte("version: \"1\"\nlicense_policy:\n  rules:\n    - scope: x\n      default: explode\n"))
	f.Add([]byte("version: \"1\"\nlicense_policy:\n  rules:\n    - scope: x\n      unknown_license: maybe\n"))
	// Wrong types.
	f.Add([]byte("version: \"1\"\npreferences: \"not-a-map\"\n"))
	f.Add([]byte("version: \"1\"\nlicense_overrides: [list, not, map]\n"))
	// Malformed / empty / binary.
	f.Add([]byte("version: \"1\nbroken: ["))
	f.Add([]byte(""))
	f.Add([]byte("null\n"))
	f.Add([]byte("\x00\x01 not yaml"))
	// Alias bomb (yaml.v3 caps expansion).
	f.Add([]byte(`version: "1"
license_policy:
  categories:
    a: &a [x,x,x,x,x,x,x,x,x]
    b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
    c: [*b,*b,*b,*b,*b,*b,*b,*b,*b]`))
	// Deep nesting.
	f.Add([]byte("version: \"1\"\npreferences: " + strings.Repeat("[", 4096)))
	// Many rules.
	f.Add([]byte("version: \"1\"\nlicense_policy:\n  rules:\n" +
		strings.Repeat("    - scope: s\n      default: allow\n", 512)))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := configyaml.Parse(data)
		if err != nil {
			return
		}
		// On success Version is non-empty (Parse rejects empty) and optional
		// sections are defaulted so callers never see a nil log level.
		if cfg.Version == "" {
			t.Fatalf("Parse returned nil error with empty Version for %q", data)
		}
		if cfg.Preferences.LogLevel == "" {
			t.Fatalf("Parse left LogLevel unset (should default) for %q", data)
		}
	})
}
