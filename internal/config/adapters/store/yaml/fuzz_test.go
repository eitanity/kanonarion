package yaml_test

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	configyaml "github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
)

// schemaKeys are the top-level keys the config schema defines.
var schemaKeys = map[string]bool{
	"version": true, "preferences": true, "license_policy": true, "license_overrides": true,
	"copyright_declarations": true, "callgraph": true, "staleness": true, "directive_policy": true,
	"godebug_policy": true, "vendor_policy": true, "fips_policy": true, "fetch_policy": true, "storage": true,
}

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

	// Unknown keys at the top, nested, inside a list item, a module entry and a
	// merge, and a registered backend's section.
	f.Add([]byte("version: \"3\"\nlicence_policy: {default: warn}\n"))
	f.Add([]byte("version: \"3\"\nfetch_policy: {alowed_vcs_hosts: [example.org]}\n"))
	f.Add([]byte("version: \"3\"\nlicense_policy:\n  rules:\n    - scope: x\n      defualt: warn\n"))
	f.Add([]byte("version: \"3\"\nlicense_overrides:\n  example.com/m: {spdx: MIT, basiss: x}\n"))
	f.Add([]byte("version: \"3\"\nbase: &b {jsn: true}\npreferences:\n  <<: *b\n"))
	f.Add([]byte("version: \"3\"\nsqlite:\n  path: /x\npostgres: {url: x}\n"))
	f.Add([]byte("version: \"3\"\npreferences: {log_level: verbose}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := configyaml.Parse(data, "sqlite")
		if err != nil {
			return
		}
		// A top-level key the schema does not define never loads.
		var doc map[string]any
		if yaml.Unmarshal(data, &doc) == nil {
			for key := range doc {
				if !schemaKeys[key] && key != "sqlite" {
					t.Fatalf("Parse accepted unknown key %q in %q", key, data)
				}
			}
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
