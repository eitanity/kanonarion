package goast_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/iface/adapters/spelling/goast"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

// The motivating measurement: spf13/cast's v1.4.1 → v1.10.0 bump rewrites
// interface{} as any across its whole surface and stops naming two results. Not
// one of those is a change a consumer can be broken by, and counting them as
// breaking would have reported 56 breaking changes in a release that broke
// nothing.
func TestDiffersOnlyInSpelling_AliasAndResultNames(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
	}{
		{
			name: "empty interface rewritten as any",
			a:    "func ToBool(i interface{}) bool",
			b:    "func ToBool(i any) bool",
		},
		{
			name: "alias inside a composite type",
			a:    "func ToStringMapE(i interface{}) (map[string]interface{}, error)",
			b:    "func ToStringMapE(i any) (map[string]any, error)",
		},
		{
			name: "results stopped being named",
			a:    "func ToDurationE(i interface{}) (d time.Duration, err error)",
			b:    "func ToDurationE(i any) (time.Duration, error)",
		},
		{
			name: "parameter renamed",
			a:    "func Parse(s string) error",
			b:    "func Parse(raw string) error",
		},
		{
			name: "byte is uint8",
			a:    "func Sum(b []byte) uint32",
			b:    "func Sum(b []uint8) uint32",
		},
		{
			name: "rune is int32",
			a:    "func At(i int) rune",
			b:    "func At(i int) int32",
		},
		{
			name: "layout only",
			a:    "type Config struct {\n\tName string\n}",
			b:    "type Config struct { Name string }",
		},
		{
			name: "value declaration type spelling",
			a:    "map[string]interface{}",
			b:    "map[string]any",
		},
		{
			name: "alias behind a pointer, slice, map, channel and variadic",
			a:    "func F(a *interface{}, b []interface{}, c map[interface{}]interface{}, d chan interface{}, e ...interface{}) (f func(interface{}) interface{})",
			b:    "func F(a *any, b []any, c map[any]any, d chan any, e ...any) func(any) any",
		},
		{
			name: "alias inside a struct field and an array",
			a:    "type T struct {\n\tA [4]interface{}\n\tB struct{ C interface{} }\n}",
			b:    "type T struct {\n\tA [4]any\n\tB struct{ C any }\n}",
		},
		{
			name: "alias inside a generic instantiation",
			a:    "func F(a Box[interface{}], b Pair[interface{}, interface{}]) error",
			b:    "func F(a Box[any], b Pair[any, any]) error",
		},
		{
			name: "alias inside a non-empty interface and a constraint union",
			a:    "type T interface {\n\tM(interface{}) error\n}",
			b:    "type T interface {\n\tM(any) error\n}",
		},
		{
			name: "grouped parameters expand to the same arity",
			a:    "func F(a, b interface{}) error",
			b:    "func F(a any, b any) error",
		},
		{
			name: "parenthesised type",
			a:    "func F(a (interface{})) error",
			b:    "func F(a any) error",
		},
		{
			name: "constraint union elements are normalised",
			a:    "type T interface{ ~[]byte | ~[4]interface{} }",
			b:    "type T interface{ ~[]uint8 | ~[4]any }",
		},
		{
			name: "approximation constraint keeps its element",
			a:    "type T interface{ ~[]byte }",
			b:    "type T interface{ ~[]uint8 }",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !goast.DiffersOnlyInSpelling(tc.a, tc.b) {
				canonA, _ := goast.CanonicalDeclaration(tc.a)
				canonB, _ := goast.CanonicalDeclaration(tc.b)
				t.Errorf("want spelling-equivalent\n a: %s\n b: %s\n canon a: %q\n canon b: %q",
					tc.a, tc.b, canonA, canonB)
			}
		})
	}
}

// The other half of the contract, and the one that keeps the count honest:
// everything a consumer CAN be broken by must survive normalisation.
func TestDiffersOnlyInSpelling_RealChangesSurvive(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
	}{
		{
			name: "parameter added",
			a:    "func Parse(s string) error",
			b:    "func Parse(s string, strict bool) error",
		},
		{
			name: "parameter type changed",
			a:    "func Parse(s string) error",
			b:    "func Parse(s []byte) error",
		},
		{
			name: "result added",
			a:    "func Parse(s string) error",
			b:    "func Parse(s string) (int, error)",
		},
		{
			name: "grouped parameters are not collapsed to one",
			a:    "func F(a, b interface{}) error",
			b:    "func F(a any) error",
		},
		{
			name: "variadic is not the same as a slice",
			a:    "func F(a ...any) error",
			b:    "func F(a []any) error",
		},
		{
			name: "struct field renamed",
			a:    "type T struct{ A int }",
			b:    "type T struct{ B int }",
		},
		{
			name: "struct tag changed",
			a:    "type T struct {\n\tA int `json:\"a\"`\n}",
			b:    "type T struct {\n\tA int `json:\"b\"`\n}",
		},
		{
			name: "interface gained a method",
			a:    "type T interface{ M() error }",
			b:    "type T interface {\n\tM() error\n\tN() error\n}",
		},
		{
			name: "non-empty interface is not any",
			a:    "func F(a interface{ M() }) error",
			b:    "func F(a any) error",
		},
		{
			name: "type parameter constraint changed",
			a:    "func F[T any](a T) error",
			b:    "func F[T comparable](a T) error",
		},
		{
			name: "alias declaration is not the defined type",
			a:    "type T = int",
			b:    "type T int",
		},
		{
			name: "channel direction changed",
			a:    "func F(c chan any) error",
			b:    "func F(c <-chan any) error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if goast.DiffersOnlyInSpelling(tc.a, tc.b) {
				t.Errorf("a real change was discounted as spelling\n a: %s\n b: %s", tc.a, tc.b)
			}
		})
	}
}

// Identical text is not a difference, so it is not a SPELLING difference either
// — the diff never asks about it, and a caller that does gets the honest answer.
func TestDiffersOnlyInSpelling_IdenticalTextIsNotADifference(t *testing.T) {
	if goast.DiffersOnlyInSpelling("func F() error", "func F() error") {
		t.Error("identical signatures reported as a spelling difference")
	}
}

// Text this cannot read is never reported as equivalent to anything. Silently
// treating an unreadable signature as unchanged would turn a measurement
// failure into a clean bill of health.
func TestCanonicalDeclaration_UnreadableTextIsRefused(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "only a doc comment", in: "// just a comment"},
		{name: "not Go at all", in: "func F(("},
		{name: "type declaration that will not parse", in: "type T struct{"},
		{name: "a grouped declaration is not one signature", in: "type (\n\tA int\n\tB int\n)"},
		{name: "a value declaration with no type", in: "= 3"},
		{name: "two declarations", in: "func A()\nfunc B()"},
		{name: "an import is not a declaration signature", in: "import \"fmt\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := goast.CanonicalDeclaration(tc.in); ok {
				t.Errorf("want refusal, got %q", got)
			}
			if goast.DiffersOnlyInSpelling(tc.in, "func F() error") {
				t.Error("unreadable text reported as spelling-equivalent")
			}
			if goast.DiffersOnlyInSpelling("func F() error", tc.in) {
				t.Error("unreadable text reported as spelling-equivalent (as the B side)")
			}
		})
	}
}

// A method signature is stored with the receiver omitted, but a record written
// by another producer may carry one. Both forms must canonicalise.
func TestCanonicalDeclaration_AcceptsBothMethodForms(t *testing.T) {
	for _, in := range []string{
		"func Parse(s string) error",
		"func (p *Parser) Parse(s string) error",
		"func(s string) error",
	} {
		if _, ok := goast.CanonicalDeclaration(in); !ok {
			t.Errorf("refused a well-formed signature: %s", in)
		}
	}
}

// The doc comment go/printer would otherwise carry into the signature is not
// part of it, so a release that only reworded a comment is not a change.
func TestCanonicalDeclaration_DocCommentIsNotPartOfTheSignature(t *testing.T) {
	if !goast.DiffersOnlyInSpelling(
		"// Old wording.\nfunc F(i interface{}) error",
		"// New wording entirely.\nfunc F(i any) error",
	) {
		t.Error("a reworded doc comment was counted as a signature change")
	}
}

// -- registry shapes --

// The blind-spot detector reads a TYPE, not a name. Three forms count: a
// string-keyed map of functions or dynamically typed values, a qualified
// FuncMap (text/template and html/template both call theirs that, and the
// record carries the name rather than the map it stands for), and a local named
// type declared as one of those.
func TestRegistryShape_Recognised(t *testing.T) {
	// One level of indirection only: "Registry" resolves to its declared text and
	// that text is checked as a type in its own right. "Chained" points at another
	// local name, which is not followed — the answer stays a measurement of what
	// the record says rather than a search.
	local := map[string]string{
		"Registry": "map[string]any",
		"Chained":  "Registry",
	}
	cases := []struct {
		name string
		in   string
	}{
		{name: "map of any", in: "map[string]any"},
		{name: "map of empty interface", in: "map[string]interface{}"},
		{name: "map of a non-empty interface", in: "map[string]interface{ M() }"},
		{name: "map of funcs", in: "map[string]func(int) error"},
		{name: "template FuncMap", in: "template.FuncMap"},
		{name: "text/template FuncMap under another alias", in: "ttemplate.FuncMap"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if shape, ok := (goast.Reader{}).RegistryShape(tc.in, local); !ok || shape == "" {
				t.Errorf("RegistryShape(%q) = (%q, %v), want a shape", tc.in, shape, ok)
			}
		})
	}
	if shape, ok := (goast.Reader{}).RegistryShape("Registry", local); !ok ||
		!strings.Contains(shape, "map[string]any") {
		t.Errorf("a registry behind a local named type was missed: (%q, %v)", shape, ok)
	}
	if shape, ok := (goast.Reader{}).RegistryShape("Chained", local); ok {
		t.Errorf("a chain of local aliases was followed: (%q, %v)", shape, ok)
	}
}

// Everything else is not a registry, including text that will not parse: an
// unreadable declaration is not evidence of a registry any more than it is
// evidence of sameness.
func TestRegistryShape_Refused(t *testing.T) {
	for _, in := range []string{
		"", "int", "map[int]func() error", "map[string]int", "map[string][]byte",
		"map[string]", "Unknown", "[]func() error",
	} {
		if shape, ok := (goast.Reader{}).RegistryShape(in, map[string]string{"Unknown": ""}); ok {
			t.Errorf("RegistryShape(%q) = (%q, true), want refusal", in, shape)
		}
	}
}

// sprig publishes its registry from a FUNCTION. A detector that only read
// variables would have missed the case it exists for, so the result leg is
// measured on the real shapes.
func TestResultRegistryShape(t *testing.T) {
	recognised := []string{
		"func FuncMap() template.FuncMap",
		"func GenericFuncMap() map[string]interface{}",
		"func HermeticTxtFuncMap() ttemplate.FuncMap",
	}
	for _, in := range recognised {
		if shape, ok := (goast.Reader{}).ResultRegistryShape(in, nil); !ok || shape == "" {
			t.Errorf("ResultRegistryShape(%q) = (%q, %v), want a shape", in, shape, ok)
		}
	}
	for _, in := range []string{
		"", "func Plain() error", "func NoResult()", "func Unreadable((",
		"not a function at all",
	} {
		if shape, ok := (goast.Reader{}).ResultRegistryShape(in, nil); ok {
			t.Errorf("ResultRegistryShape(%q) = (%q, true), want refusal", in, shape)
		}
	}
}

// The port and the domain's own declaration of the same shape are satisfied by
// the same value; the compile-time assertions in the package are what keep them
// from drifting, and this is the runtime witness that the methods are wired.
func TestReader_AnswersThroughThePort(t *testing.T) {
	var r ports.SignatureReader = goast.Reader{}
	if !r.DiffersOnlyInSpelling("func F(i interface{}) error", "func F(i any) error") {
		t.Error("the port's spelling leg is not wired to the implementation")
	}
	if _, ok := r.RegistryShape("map[string]any", nil); !ok {
		t.Error("the port's registry leg is not wired to the implementation")
	}
	if _, ok := r.ResultRegistryShape("func F() map[string]any", nil); !ok {
		t.Error("the port's result-registry leg is not wired to the implementation")
	}
}
