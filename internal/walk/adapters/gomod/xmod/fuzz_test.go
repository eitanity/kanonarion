package xmod_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
)

// FuzzParse exercises the go.mod parser against untrusted bytes. The parser
// runs on content fetched from the module proxy ( relates), so
// it must never panic regardless of how malformed or adversarial the input
// is — it may only return a value or an error.
//
// Run locally with: go test -run=NONE -fuzz=FuzzParse./internal/walk/adapters/gomod/xmod
// Crashers found by the fuzzer are persisted under testdata/fuzz/FuzzParse and
// replayed automatically by `go test`, wiring them in as regression cases.
func FuzzParse(f *testing.F) {
	seeds := []string{
		// Valid: minimal.
		"module example.com/m\n\ngo 1.21\n",
		// Valid: full feature set.
		`module example.com/target

go 1.24

toolchain go1.24.0

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.7.0 // indirect
	github.com/some/mod v0.0.0-20230101120000-abcdef012345
)

replace github.com/old/pkg v1.0.0 => github.com/new/pkg v1.1.0
replace github.com/local/pkg => ./local/pkg
replace github.com/wild/pkg => github.com/wild/fork v2.0.0+incompatible

exclude github.com/foo/bar v1.2.3

retract (
	v1.0.0 // security issue
	[v1.1.0, v1.2.0] // broken range
)

tool golang.org/x/tools/cmd/stringer
`,
		// Malformed: not a go.mod at all.
		"this is not a valid go.mod file ;;;",
		// Malformed: truncated directive.
		"module\n",
		"require (\n",
		// Adversarial: empty input.
		"",
		// Adversarial: invalid UTF-8.
		"module example.com/m\n\nrequire x \xff\xfe v1.0.0\n",
		// Adversarial: NUL bytes.
		"module example.com/m\x00\n\ngo 1.21\n",
		// Adversarial: replace/exclude edge cases.
		"module m\n\nreplace => \n",
		"module m\n\nreplace x v1 => \n",
		"module m\n\nreplace x => y\n",
		"module m\n\nexclude\n",
		"module m\n\nexclude x\n",
		"module m\n\nexclude x v1.0.0 v2.0.0\n",
		// Adversarial: huge require block.
		"module example.com/m\n\ngo 1.21\n\nrequire (\n" +
			strings.Repeat("github.com/x/y v1.0.0\n", 5000) + ")\n",
		// Adversarial: deeply nested / repeated parens.
		"module m\n\nrequire " + strings.Repeat("(", 4096),
		// Adversarial: very long single token.
		"module " + strings.Repeat("a", 100000) + "\n",
		// Adversarial: many newlines only.
		strings.Repeat("\n", 10000),
		// Adversarial: pseudo-version and +incompatible edge cases.
		"module m\n\nrequire github.com/x/y v2.0.0+incompatible\n",
		"module m\n\nrequire github.com/x/y v0.0.0-00010101000000-000000000000\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	p := xmod.New()
	f.Fuzz(func(t *testing.T, data []byte) {
		// The only contract under fuzzing: Parse must not panic and must
		// return either a usable value or a non-nil error.
		got, err := p.Parse("go.mod", data)
		if err != nil {
			return
		}
		// On success the slices are always initialised (never nil) so callers
		// can range over them without a guard.
		if got.Require == nil || got.Replace == nil || got.Exclude == nil ||
			got.Retract == nil || got.Tools == nil {
			t.Fatalf("Parse returned nil slice on success: %#v", got)
		}
	})
}
