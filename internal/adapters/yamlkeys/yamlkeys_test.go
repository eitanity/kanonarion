package yamlkeys_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eitanity/kanonarion/internal/adapters/yamlkeys"
)

type inner struct {
	Depth int `yaml:"depth"`
}

type embedded struct {
	Shared string `yaml:"shared"`
}

type schema struct {
	Name     string            `yaml:"name,omitempty"`
	Inner    *inner            `yaml:"inner"`
	Items    []inner           `yaml:"items"`
	Fixed    [1]inner          `yaml:"fixed"`
	ByName   map[string]inner  `yaml:"by_name"`
	Free     map[string]any    `yaml:"free"`
	Skipped  string            `yaml:"-"`
	Untagged string            //nolint:tagliatelle // the decoder's own default spelling is under test
	Embedded embedded          `yaml:",inline"`
	Extra    map[string]string `yaml:"extra"`
	hidden   string
}

type openSchema struct {
	Name string         `yaml:"name"`
	Rest map[string]any `yaml:",inline"`
}

type ptrInline struct {
	*embedded `yaml:",inline"`
}

func check(t *testing.T, src string, typ reflect.Type, extra ...string) error {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	return yamlkeys.Check(&doc, typ, extra...)
}

func TestCheck(t *testing.T) {
	typ := reflect.TypeFor[schema]()
	_ = schema{}.hidden
	for _, tc := range []struct{ src, want string }{
		{"name: a\ninner: {depth: 1}\nitems: [{depth: 1}]\nfixed: [{depth: 2}]\n" +
			"by_name: {x: {depth: 1}}\nfree: {any: {thing: 1}}\nuntagged: u\nshared: s\nextra: {k: v}\n", ""},
		{"", ""},
		{"name:\n", ""},
		{"inner: 5\nitems: x\nby_name: [1]\n", ""},
		{"nmae: a", `unknown key "nmae" (did you mean "name"?)`},
		{"hidden: a", `unknown key "hidden"`},
		{"skipped: a", `unknown key "skipped"`},
		{"inner: {dpeth: 1}", `unknown key "inner.dpeth" (did you mean "depth"?)`},
		{"items: [{depth: 1}, {dpth: 2}]", `unknown key "items[1].dpth" (did you mean "depth"?)`},
		{"fixed: [{dep: 2}]", `unknown key "fixed[0].dep" (did you mean "depth"?)`},
		{"by_name: {x: {dept: 1}}", `unknown key "by_name.x.dept" (did you mean "depth"?)`},
		{"anchor_base: &b {dept: 1}\n", `unknown key "anchor_base"`},
		{"inner:\n  <<: {dept: 1}\n", `unknown key "inner.dept" (did you mean "depth"?)`},
		{"inner:\n  <<: [{depth: 1}, {dept: 1}]\n", `unknown key "inner.dept" (did you mean "depth"?)`},
		{"a: &a {depth: 1}\n", `unknown key "a"`},
		{"inner:\n  <<: [{depth: 1}, {depth: 2}]\n  depth: 3\n", ""},
		{"items: [&a {depth: 1}, *a, *a]\ninner: *a\n", ""},
		{"items: [&a {dept: 1}, *a]\n", `unknown key "items[0].dept" (did you mean "depth"?)`},
	} {
		err := check(t, tc.src, typ)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tc.want {
			t.Errorf("%q:\n got  %s\n want %s", tc.src, got, tc.want)
		}
	}
}

func TestCheck_MergeThroughAlias(t *testing.T) {
	src := "inner:\n  <<: *b\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("b: &b {dept: 1}\n"+src), &doc); err != nil {
		t.Fatal(err)
	}
	// Check the inner mapping alone: its merge value is an alias.
	root := doc.Content[0]
	err := yamlkeys.Check(root.Content[3], reflect.TypeFor[inner]())
	if err == nil || err.Error() != `unknown key "dept" (did you mean "depth"?)` {
		t.Errorf("err = %v", err)
	}
}

func TestCheck_ExtraTopLevelKeys(t *testing.T) {
	typ := reflect.TypeFor[schema]()
	if err := check(t, "sqlite: {a: 1}\n", typ, "sqlite"); err != nil {
		t.Errorf("extra key refused: %v", err)
	}
	err := check(t, "sqlit: {a: 1}\n", typ, "sqlite")
	if err == nil || err.Error() != `unknown key "sqlit" (did you mean "sqlite"?)` {
		t.Errorf("err = %v", err)
	}
	// extra is top-level only.
	err = check(t, "inner: {sqlite: 1}\n", typ, "sqlite")
	if err == nil || err.Error() != `unknown key "inner.sqlite"` {
		t.Errorf("err = %v", err)
	}
}

func TestCheck_InlineMapAcceptsAnyKey(t *testing.T) {
	if err := check(t, "name: a\nanything: 1\n", reflect.TypeFor[openSchema]()); err != nil {
		t.Errorf("inline map refused a key: %v", err)
	}
	if err := check(t, "shared: a\n", reflect.TypeFor[ptrInline]()); err != nil {
		t.Errorf("pointer inline struct refused its own key: %v", err)
	}
	if err := check(t, "nope: a\n", reflect.TypeFor[ptrInline]()); err == nil {
		t.Error("pointer inline struct accepted an unknown key")
	}
}

func TestCheck_NilAndEmptyNodes(t *testing.T) {
	if err := yamlkeys.Check(nil, reflect.TypeFor[schema]()); err != nil {
		t.Errorf("nil node: %v", err)
	}
	if err := yamlkeys.Check(&yaml.Node{Kind: yaml.DocumentNode}, reflect.TypeFor[schema]()); err != nil {
		t.Errorf("empty document: %v", err)
	}
	dangling := &yaml.Node{Kind: yaml.AliasNode}
	if err := yamlkeys.Check(dangling, reflect.TypeFor[schema]()); err != nil {
		t.Errorf("dangling alias: %v", err)
	}
}

// An anchor expanded through many aliases is walked once per type, so an alias
// bomb costs what its text costs.
func TestCheck_AliasBombIsLinear(t *testing.T) {
	var b strings.Builder
	b.WriteString("items: &l0 [{depth: 1}]\n")
	for i := 1; i < 40; i++ {
		fmt.Fprintf(&b, "l%d: &l%d [*l%d, *l%d, *l%d, *l%d]\n", i, i, i-1, i-1, i-1, i-1)
	}
	type bomb struct {
		Items []inner `yaml:"items"`
		L     map[string][][]inner
	}
	_ = bomb{}.L
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatal(err)
	}
	err := yamlkeys.Check(&doc, reflect.TypeFor[bomb]())
	if err == nil || err.Error() != `unknown key "l1" (did you mean "l"?)` {
		t.Errorf("err = %v", err)
	}
}

func TestUnknownKeyError(t *testing.T) {
	for _, tc := range []struct {
		err  yamlkeys.UnknownKeyError
		want string
	}{
		{yamlkeys.UnknownKeyError{Key: "a.b"}, `unknown key "a.b"`},
		{yamlkeys.UnknownKeyError{Key: "a.b", File: "p.yaml"}, `unknown key "a.b" in p.yaml`},
		{yamlkeys.UnknownKeyError{Key: "a.b", Suggestion: "c"}, `unknown key "a.b" (did you mean "c"?)`},
		{yamlkeys.UnknownKeyError{Key: "a.b", Suggestion: "c", File: "p.yaml"}, `unknown key "a.b" in p.yaml (did you mean "c"?)`},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
}

func TestInFile(t *testing.T) {
	plain := &yamlkeys.UnknownKeyError{Key: "k"}
	if got := yamlkeys.InFile(plain, "f.yaml").Error(); got != `unknown key "k" in f.yaml` {
		t.Errorf("got %s", got)
	}
	if plain.File != "" {
		t.Error("InFile changed the error it was given")
	}
	wrapped := fmt.Errorf("wrapped: %w", plain)
	if got := yamlkeys.InFile(wrapped, "f.yaml"); !errors.Is(got, wrapped) || got.Error() != wrapped.Error() {
		t.Errorf("a wrapped error changed: %v", got)
	}
	other := errors.New("other")
	if got := yamlkeys.InFile(other, "f.yaml"); !errors.Is(got, other) {
		t.Errorf("a different error changed: %v", got)
	}
	if got := yamlkeys.InFile(nil, "f.yaml"); got != nil {
		t.Errorf("nil became %v", got)
	}
}

func TestNearest(t *testing.T) {
	known := []string{"license_policy", "license_overrides", "stages", "fetch", "red"}
	for key, want := range map[string]string{
		"licence_policy":   "license_policy",
		"licence_override": "license_overrides",
		"stage":            "stages",
		"fecth":            "fetch",
		"rd":               "red",
		"xyz":              "",
		"completely_off":   "",
		"":                 "",
	} {
		if got := yamlkeys.Nearest(key, known); got != want {
			t.Errorf("Nearest(%q) = %q, want %q", key, got, want)
		}
	}
	// A tie goes to the alphabetically first key, whatever the input order.
	if got := yamlkeys.Nearest("ab", []string{"az", "ay"}); got != "ay" {
		t.Errorf("tie = %q, want ay", got)
	}
}
