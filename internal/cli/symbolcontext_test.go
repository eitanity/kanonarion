package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

// -- symbolDoc tests --

func TestSymbolDoc_Func(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{
				ImportPath: "example.com/mod/pkg",
				Funcs:      []ifacedomain.FuncDecl{{Name: "New", Doc: "New creates a client."}},
			},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "func", SymbolName: "New"}
	if got := symbolDoc(rec, ref); got != "New creates a client." {
		t.Errorf("expected doc, got %q", got)
	}
}

func TestSymbolDoc_Type(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{
				ImportPath: "example.com/mod/pkg",
				Types:      []ifacedomain.TypeDecl{{Name: "Client", Doc: "Client is the HTTP client."}},
			},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "type", SymbolName: "Client"}
	if got := symbolDoc(rec, ref); got != "Client is the HTTP client." {
		t.Errorf("expected doc, got %q", got)
	}
}

func TestSymbolDoc_Method(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{
				ImportPath: "example.com/mod/pkg",
				Types: []ifacedomain.TypeDecl{
					{
						Name: "Client",
						Methods: []ifacedomain.MethodDecl{
							{Name: "Do", Doc: "Do executes the request."},
						},
					},
				},
			},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "method", SymbolName: "Do", ParentType: "Client"}
	if got := symbolDoc(rec, ref); got != "Do executes the request." {
		t.Errorf("expected doc, got %q", got)
	}
}

func TestSymbolDoc_Const(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{
				ImportPath: "example.com/mod/pkg",
				Consts:     []ifacedomain.ValueDecl{{Name: "MaxRetries", Doc: "MaxRetries is the max number of retries."}},
			},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "const", SymbolName: "MaxRetries"}
	if got := symbolDoc(rec, ref); got != "MaxRetries is the max number of retries." {
		t.Errorf("expected doc, got %q", got)
	}
}

func TestSymbolDoc_Var(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{
				ImportPath: "example.com/mod/pkg",
				Vars:       []ifacedomain.ValueDecl{{Name: "DefaultClient", Doc: "DefaultClient is the default."}},
			},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "var", SymbolName: "DefaultClient"}
	if got := symbolDoc(rec, ref); got != "DefaultClient is the default." {
		t.Errorf("expected doc, got %q", got)
	}
}

func TestSymbolDoc_WrongPackage(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{ImportPath: "example.com/mod/other", Funcs: []ifacedomain.FuncDecl{{Name: "New", Doc: "doc"}}},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "func", SymbolName: "New"}
	if got := symbolDoc(rec, ref); got != "" {
		t.Errorf("expected empty doc for wrong package, got %q", got)
	}
}

func TestSymbolDoc_MissingSymbol(t *testing.T) {
	rec := ifacedomain.InterfaceRecord{
		Packages: []ifacedomain.PackageInterface{
			{ImportPath: "example.com/mod/pkg", Funcs: []ifacedomain.FuncDecl{{Name: "Other", Doc: "doc"}}},
		},
	}
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "func", SymbolName: "New"}
	if got := symbolDoc(rec, ref); got != "" {
		t.Errorf("expected empty doc for missing symbol, got %q", got)
	}
}

func TestSymbolDoc_EmptyRecord(t *testing.T) {
	ref := ifaceports.SymbolRef{PackagePath: "example.com/mod/pkg", SymbolKind: "func", SymbolName: "New"}
	if got := symbolDoc(ifacedomain.InterfaceRecord{}, ref); got != "" {
		t.Errorf("expected empty doc for empty record, got %q", got)
	}
}

// -- printSymbolContext tests --

func TestPrintSymbolContext_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printSymbolContext(nil, &buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty entries, got: %q", buf.String())
	}
}

func TestPrintSymbolContext_SingleFuncWithDoc(t *testing.T) {
	entries := []symbolContextEntry{
		{
			Module:        "example.com/mod@v1.0.0",
			Package:       "example.com/mod/pkg",
			Name:          "New",
			QualifiedName: "example.com/mod/pkg.New",
			Kind:          "func",
			Signature:     "func New() *Client",
			Doc:           "New creates a client.",
			Examples:      []symbolContextExample{},
		},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/mod@v1.0.0") {
		t.Errorf("expected module in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/mod/pkg.New") {
		t.Errorf("expected qualified name in output, got: %q", out)
	}
	if !strings.Contains(out, "(func)") {
		t.Errorf("expected kind in output, got: %q", out)
	}
	if !strings.Contains(out, "func New() *Client") {
		t.Errorf("expected signature in output, got: %q", out)
	}
	if !strings.Contains(out, "New creates a client.") {
		t.Errorf("expected doc in output, got: %q", out)
	}
}

func TestPrintSymbolContext_TokenCountFooter(t *testing.T) {
	entries := []symbolContextEntry{
		{
			Module:        "example.com/mod@v1.0.0",
			Package:       "example.com/mod/pkg",
			Name:          "New",
			QualifiedName: "example.com/mod/pkg.New",
			Kind:          "func",
			Examples:      []symbolContextExample{},
		},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "tokens") {
		t.Errorf("expected token count footer, got: %q", out)
	}
	if !strings.Contains(out, "bytes") {
		t.Errorf("expected byte count in footer, got: %q", out)
	}
	// Footer must appear after all entry content.
	idx := strings.Index(out, "example.com/mod/pkg.New")
	tokenIdx := strings.Index(out, "tokens")
	if tokenIdx < idx {
		t.Errorf("token count footer appeared before entry content")
	}
}

// Pre-0.3.0 store records persisted the go/printer doc-comment block in the
// Signature field. The renderer must strip it defensively so old records still
// display cleanly.
func TestPrintSymbolContext_StripsLegacyDocComment(t *testing.T) {
	entries := []symbolContextEntry{
		{
			Module:        "example.com/mod@v1.0.0",
			Package:       "example.com/mod/pkg",
			Name:          "New",
			QualifiedName: "example.com/mod/pkg.New",
			Kind:          "func",
			Signature:     "// New creates a client.\n// It never returns nil.\nfunc New() *Client",
			Doc:           "New creates a client.",
			Examples:      []symbolContextExample{},
		},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "func New() *Client") {
		t.Errorf("expected stripped signature in output, got: %q", out)
	}
	if strings.Contains(out, "// New creates a client.") {
		t.Errorf("expected legacy doc-comment lines stripped from signature, got: %q", out)
	}
}

func TestPrintSymbolContext_NoTokenFooter_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printSymbolContext(nil, &buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "tokens") {
		t.Errorf("expected no token count for empty entries, got: %q", buf.String())
	}
}

func TestPrintSymbolContext_NoSignatureNoDoc(t *testing.T) {
	entries := []symbolContextEntry{
		{
			Module:        "example.com/mod@v1.0.0",
			Package:       "example.com/mod",
			Name:          "ErrNotFound",
			QualifiedName: "example.com/mod.ErrNotFound",
			Kind:          "var",
			Signature:     "",
			Doc:           "",
			Examples:      []symbolContextExample{},
		},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ErrNotFound") {
		t.Errorf("expected symbol name, got: %q", out)
	}
	// No whitespace-only non-empty lines (blank separator lines are empty strings, not spaces).
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == "" && l != "" {
			t.Errorf("unexpected whitespace-only line: %q", out)
		}
	}
}

func TestPrintSymbolContext_WithExamples(t *testing.T) {
	entries := []symbolContextEntry{
		{
			Module:        "example.com/mod@v1.0.0",
			Package:       "example.com/mod/pkg",
			Name:          "New",
			QualifiedName: "example.com/mod/pkg.New",
			Kind:          "func",
			Signature:     "func New() *Client",
			Examples: []symbolContextExample{
				{Name: "ExampleNew", Package: "example.com/mod/pkg", Validates: true},
				{Name: "ExampleNew_withOptions", Package: "example.com/mod/pkg", Validates: false},
			},
		},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ExampleNew") {
		t.Errorf("expected example name, got: %q", out)
	}
	if !strings.Contains(out, "(validates)") {
		t.Errorf("expected validates marker, got: %q", out)
	}
	if !strings.Contains(out, "ExampleNew_withOptions") {
		t.Errorf("expected second example, got: %q", out)
	}
	// Second example should NOT have the validates marker.
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "ExampleNew_withOptions") && strings.Contains(l, "(validates)") {
			t.Errorf("non-validating example should not show (validates): %q", l)
		}
	}
}

func TestPrintSymbolContext_MultipleEntries_Separator(t *testing.T) {
	entries := []symbolContextEntry{
		{Module: "a@v1.0.0", Package: "a", Name: "Foo", QualifiedName: "a.Foo", Kind: "func", Examples: []symbolContextExample{}},
		{Module: "b@v1.0.0", Package: "b", Name: "Foo", QualifiedName: "b.Foo", Kind: "func", Examples: []symbolContextExample{}},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "a@v1.0.0") || !strings.Contains(out, "b@v1.0.0") {
		t.Errorf("expected both modules in output, got: %q", out)
	}
	// Token count must appear once, at the end.
	count := strings.Count(out, "tokens")
	if count != 1 {
		t.Errorf("expected exactly one token count footer, got %d occurrences in: %q", count, out)
	}
}

func TestPrintSymbolContext_MethodQualifiedName(t *testing.T) {
	entries := []symbolContextEntry{
		{
			Module:        "example.com/mod@v1.0.0",
			Package:       "example.com/mod/pkg",
			Name:          "Do",
			QualifiedName: "example.com/mod/pkg.Client.Do",
			Kind:          "method",
			Signature:     "func (c *Client) Do() error",
			Examples:      []symbolContextExample{},
		},
	}
	var buf bytes.Buffer
	if err := printSymbolContext(entries, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Client.Do") {
		t.Errorf("expected Client.Do in output, got: %q", buf.String())
	}
}

// -- deterministic sort --

func TestBuildSymbolContextEntries_DeterministicSort(t *testing.T) {
	// Provide refs in non-alphabetical order; entries must come out sorted by
	// (module, package, kind, parent_type) regardless of input order.
	refs := []ifaceports.SymbolRef{
		{ModulePath: "z.io/mod", ModuleVersion: "v1.0.0", PackagePath: "z.io/mod", SymbolKind: "func", SymbolName: "Do"},
		{ModulePath: "a.io/mod", ModuleVersion: "v1.0.0", PackagePath: "a.io/mod", SymbolKind: "func", SymbolName: "Do"},
		{ModulePath: "a.io/mod", ModuleVersion: "v1.0.0", PackagePath: "a.io/mod", SymbolKind: "method", ParentType: "Z", SymbolName: "Do"},
		{ModulePath: "a.io/mod", ModuleVersion: "v1.0.0", PackagePath: "a.io/mod", SymbolKind: "method", ParentType: "A", SymbolName: "Do"},
	}

	// We exercise just the sort, not the full container build, so we test the
	// sort by calling buildSymbolContextEntries via a stub-less path: we can't
	// call it directly without a Container, so we replicate the sort logic and
	// verify the expected canonical output order here.
	//
	// Expected order after sort:
	// a.io/mod pkg kind=func parent=""
	// a.io/mod pkg kind=method parent=A
	// a.io/mod pkg kind=method parent=Z
	// z.io/mod pkg kind=func parent=""

	type key struct{ mod, pkg, kind, parent string }
	want := []key{
		{"a.io/mod", "a.io/mod", "func", ""},
		{"a.io/mod", "a.io/mod", "method", "A"},
		{"a.io/mod", "a.io/mod", "method", "Z"},
		{"z.io/mod", "z.io/mod", "func", ""},
	}

	// Apply the same sort as buildSymbolContextEntries.
	sortSymbolRefs(refs)

	for i, ref := range refs {
		got := key{ref.ModulePath, ref.PackagePath, ref.SymbolKind, ref.ParentType}
		if got != want[i] {
			t.Errorf("refs[%d] = %+v, want %+v", i, got, want[i])
		}
	}
}

// -- integration: empty store --

func TestSymbolContextCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"symbol-context", "--store-root", dir, "Marshal"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no exports found") {
		t.Errorf("expected empty message, got: %q", stdout.String())
	}
	// No token count for empty results.
	if strings.Contains(stdout.String(), "tokens") {
		t.Errorf("expected no token count for empty result, got: %q", stdout.String())
	}
}

func TestSymbolContextCmd_EmptyStore_JSON(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"symbol-context", "--store-root", dir, "--json", "Marshal"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// stdout must be valid JSON and not contain log lines.
	out := stdout.String()
	if !strings.Contains(out, "[]") {
		t.Errorf("expected JSON empty array, got: %q", out)
	}
	// JSON mode: no token count on stdout (it's a human-only feature).
	if strings.Contains(out, "tokens") {
		t.Errorf("token count must not appear in JSON output, got: %q", out)
	}
	// Verify stdout is parseable JSON.
	var result []symbolContextEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &result); err != nil {
		t.Errorf("stdout is not valid JSON: %v\nout=%q", err, out)
	}
}

func TestSymbolContextCmd_LogsGoToStderr_NotStdout(t *testing.T) {
	// In JSON mode, no log lines must appear on stdout; they go to stderr.
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"symbol-context", "--store-root", dir, "--json", "--log-level", "debug", "Marshal"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	// stdout must be parseable JSON alone — no log lines mixed in.
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), new([]symbolContextEntry)); err != nil {
		t.Errorf("stdout not clean JSON (log lines on stdout?): %v\nout=%q", err, out)
	}
}

func TestSymbolContextCmd_InvalidModuleFlag(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"symbol-context", "--store-root", dir, "--module", "notacoordinate", "Marshal"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid --module flag")
	}
}

// TestIsImportablePackage: internal/ and testdata/ path segments must be
// excluded; all other paths are importable.
func TestIsImportablePackage(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"example.com/pkg", true},
		{"example.com/pkg/sub", true},
		{"example.com/pkg/internal/helper", false},
		{"example.com/pkg/testdata/fixture", false},
		{"internal/pkg", false},
		{"testdata", false},
		{"example.com/internal", false},
		{"example.com/testdata", false},
		// internal/ as a prefix of a segment name is not a match.
		{"example.com/internalpkg", true},
	}
	for _, c := range cases {
		if got := isImportablePackage(c.path); got != c.want {
			t.Errorf("isImportablePackage(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
