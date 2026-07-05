package localfile_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/adapters/policy/localfile"
)

// FuzzParse fuzzes the policy.yaml loader. Policy files are operator-supplied
// local input (relates, relates) — lower risk than network
// data, but a malformed or hostile YAML file must still degrade to an error,
// never a panic or unbounded parse. gopkg.in/yaml.v3 caps alias expansion, so
// the harness asserts the contract: Parse returns (zero, error) or a valid
// DepthPolicy, and never panics.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzParse./internal/walk/adapters/policy/localfile
func FuzzParse(f *testing.F) {
	// Valid policy.
	f.Add([]byte("version: \"1\"\nstages:\n  walk:\n    max_depth: 3\n    follow_test: true\n"))
	// Valid, minimal.
	f.Add([]byte("version: \"1\"\n"))
	// Missing version (defined error path).
	f.Add([]byte("stages:\n  walk:\n    max_depth: 1\n"))
	// Version newer than supported.
	f.Add([]byte("version: \"99\"\n"))
	// Wrong types where ints/bools/maps expected.
	f.Add([]byte("version: 1\nstages: \"not-a-map\"\n"))
	f.Add([]byte("version: \"1\"\nstages:\n  walk:\n    max_depth: not-an-int\n"))
	// Malformed YAML.
	f.Add([]byte("version: \"1\nstages: [unterminated"))
	f.Add([]byte("\t- : :\n  ::"))
	// Empty / null / binary.
	f.Add([]byte(""))
	f.Add([]byte("null\n"))
	f.Add([]byte("\x00\x01\x02 not yaml"))
	// Billion-laughs / alias bomb (yaml.v3 should cap expansion).
	f.Add([]byte(`version: "1"
stages:
  a: &a {max_depth: 1}
  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
  d: [*c,*c,*c,*c,*c,*c,*c,*c,*c]`))
	// Deeply nested flow collections.
	f.Add([]byte("version: \"1\"\nstages: " + strings.Repeat("[", 4096)))
	// Many duplicate keys.
	f.Add([]byte("version: \"1\"\nstages:\n" + strings.Repeat("  s:\n    max_depth: 1\n", 512)))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := localfile.Parse(data)
		if err != nil {
			return
		}
		// On success Version must be non-empty (Parse rejects empty version)
		// and the Stages map must be non-nil so callers can range safely.
		if p.Version == "" {
			t.Fatalf("Parse returned nil error with empty Version for %q", data)
		}
		if p.Stages == nil {
			t.Fatalf("Parse returned nil error with nil Stages for %q", data)
		}
	})
}
