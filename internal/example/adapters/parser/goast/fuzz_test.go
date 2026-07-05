package goast_test

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
)

// makeZip builds a ZIP from name->content, writing names verbatim so the seed
// corpus can carry traversal and zero-length entries.
func makeZip(tb testing.TB, entries map[string]string) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		fw, err := w.Create(name)
		if err != nil {
			tb.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := io.WriteString(fw, content); err != nil {
			tb.Fatalf("write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

// FuzzParse fuzzes the example zip reader (the goast parser, moved here under
// ). It scans _test.go entries of a proxy-fetched module zip and parses
// them with go/parser — all untrusted input ( relates).
// Invariant: Parse must never panic; it may only return values or an error.
//
// Run locally with:
//
//	go test -run=NONE -fuzz=FuzzParse./internal/example/adapters/parser/goast
func FuzzParse(f *testing.F) {
	const prefix = "example.com/m@v1.0.0/"

	// Valid: a real Example function in a _test.go entry.
	f.Add(makeZip(f, map[string]string{
		prefix + "go.mod": "module example.com/m\n\ngo 1.21\n",
		prefix + "ex_test.go": `package m_test

import "fmt"

// ExampleFoo shows Foo.
func ExampleFoo() {
	fmt.Println("hi")
	// Output: hi
}
`,
		prefix + "not_test.go": "package m\n\nfunc Foo() {}\n",
	}), prefix)
	// _test.go entry that fails to parse (recorded as a ParseFailure, not a panic).
	f.Add(makeZip(f, map[string]string{
		prefix + "broken_test.go": "package m\nfunc Example( {{{ not go",
	}), prefix)
	// Path-traversal + zero-length _test.go entries.
	f.Add(makeZip(f, map[string]string{
		"../../../evil_test.go":  "package x\nfunc Example() {}\n",
		prefix + "empty_test.go": "",
		prefix + "dir/":          "",
	}), prefix)
	// Example with no body / weird braces (exercises extractBody offset maths).
	f.Add(makeZip(f, map[string]string{
		prefix + "edge_test.go": "package m\nfunc Example()\nfunc ExampleX() { { } }\n",
	}), prefix)
	// Highly compressible _test.go (bomb-shaped, modest seed).
	f.Add(makeZip(f, map[string]string{
		prefix + "big_test.go": "package m\n" + strings.Repeat("// x\n", 1<<16),
	}), prefix)
	// Non-zip bytes / empty input with assorted prefixes.
	f.Add([]byte("not a zip"), prefix)
	f.Add([]byte{}, "")
	f.Add([]byte("PK\x03\x04 truncated"), prefix)

	p := goast.New()
	f.Fuzz(func(t *testing.T, zipData []byte, modulePrefix string) {
		// Contract: no panic. A bad zip yields an error; bad Go inside a
		// _test.go yields a ParseFailure, not a crash.
		examples, failures, err := p.Parse(zipData, modulePrefix)
		if err != nil {
			if examples != nil || failures != nil {
				t.Fatalf("Parse returned data alongside error: ex=%v fail=%v err=%v",
					examples, failures, err)
			}
			return
		}
		// On success every reported example must carry a name (it is derived
		// from the parsed FuncDecl and must never be empty).
		for _, e := range examples {
			if e.Name == "" {
				t.Fatalf("Parse returned an example with an empty Name: %#v", e)
			}
		}
	})
}

// FuzzParseSource fuzzes the Go-source AST extraction class rather
// than the zip container (covered by FuzzParse): arbitrary source
// text is wrapped in a fixed, valid module zip as a _test.go entry so the
// fuzzer explores go/parser + Example* extraction, not zip framing. Source
// from arbitrary modules is untrusted (relates). Contract:
// never panic; unparseable Go is recorded as a ParseFailure, never an error.
func FuzzParseSource(f *testing.F) {
	const prefix = "example.com/m@v1.0.0/"

	seeds := []string{
		"package m_test\n\nfunc ExampleFoo() {\n\t// Output:\n}\n",
		"package m\nfunc ExampleX() { { } }\nfunc Example()\n",
		"package m\nfunc Example( {{{ not go",
		"package",
		"",
		// Pathological generics in an example body.
		"package m\nfunc ExampleG[T any]() { var _ T }\n",
		// Huge identifier.
		"package m\nfunc Example" + strings.Repeat("X", 1<<16) + "() {}\n",
		// Deeply nested.
		"package m\nfunc Example() {" + strings.Repeat("{", 2048) + strings.Repeat("}", 2048) + "}\n",
		// Invalid UTF-8.
		"package m\n// \xff\xfe\nfunc Example() {}\n",
		"package m\nfunc Example\xff() {}\n",
		// Example with Output directive variants.
		"package m\nfunc Example() {\n\t// Unordered output: a\n\t// b\n}\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	p := goast.New()
	f.Fuzz(func(t *testing.T, src string) {
		zipData := makeZip(t, map[string]string{
			prefix + "go.mod":     "module example.com/m\n\ngo 1.21\n",
			prefix + "ex_test.go": src,
		})

		examples, failures, err := p.Parse(zipData, prefix)
		if err != nil {
			// The zip is always valid here, so Parse must not error.
			t.Fatalf("Parse errored on a valid zip with fuzzed source: %v", err)
		}
		for _, e := range examples {
			if e.Name == "" {
				t.Fatalf("example with empty Name from source %q", src)
			}
		}
		// Any recorded failure must name the offending file — a graceful
		// ParseFailure, not a swallowed crash.
		for _, fail := range failures {
			if fail.File == "" {
				t.Fatalf("ParseFailure with empty File from source %q", src)
			}
		}
	})
}
