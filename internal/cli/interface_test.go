package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	ifacedomain "github.com/eitanity/kanonarion/internal/iface/domain"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
)

func makeIfaceCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/iface", "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPrintInterfaceRecord_TextBasic(t *testing.T) {
	coord := makeIfaceCoord(t)
	r := ifacedomain.InterfaceRecord{
		Coordinate:    coord,
		OverallStatus: ifacedomain.InterfaceStatusExtracted,
		Packages: []ifacedomain.PackageInterface{
			{ImportPath: "example.com/iface", Funcs: []ifacedomain.FuncDecl{{Name: "Do"}}},
		},
	}
	var buf bytes.Buffer
	if err := printInterfaceRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "example.com/iface@v2.0.0") {
		t.Errorf("expected coord in output, got: %q", got)
	}
	if !strings.Contains(got, "1 package") {
		t.Errorf("expected package count, got: %q", got)
	}
	if strings.Contains(got, "(cached)") {
		t.Errorf("unexpected '(cached)'")
	}
}

func TestPrintInterfaceRecord_TextCached(t *testing.T) {
	coord := makeIfaceCoord(t)
	r := ifacedomain.InterfaceRecord{Coordinate: coord, OverallStatus: ifacedomain.InterfaceStatusExtracted}
	var buf bytes.Buffer
	if err := printInterfaceRecord(r, true, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(cached)") {
		t.Errorf("expected '(cached)', got: %q", buf.String())
	}
}

func TestPrintInterfaceRecord_TextFailure(t *testing.T) {
	coord := makeIfaceCoord(t)
	r := ifacedomain.InterfaceRecord{
		Coordinate:    coord,
		OverallStatus: ifacedomain.InterfaceStatusExtractionFailed,
		FailureDetail: "parse error",
	}
	var buf bytes.Buffer
	if err := printInterfaceRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "parse error") {
		t.Errorf("expected failure detail, got: %q", buf.String())
	}
}

func TestPrintInterfaceRecord_JSON(t *testing.T) {
	coord := makeIfaceCoord(t)
	r := ifacedomain.InterfaceRecord{Coordinate: coord, OverallStatus: ifacedomain.InterfaceStatusExtracted}
	var buf bytes.Buffer
	if err := printInterfaceRecord(r, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// curated snake_case keys, no raw PascalCase domain fields.
	for _, want := range []string{`"coordinate"`, `"schema_version"`, `"overall_status"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in JSON output, got: %q", want, out)
		}
	}
	if strings.Contains(out, `"Coordinate"`) || strings.Contains(out, `"SchemaVersion"`) {
		t.Errorf("raw PascalCase key leaked: %q", out)
	}
}

func TestInterfaceList_EmptyStore(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"interface-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no interface records found") {
		t.Errorf("expected empty message, got: %q", stdout.String())
	}
}

// TestSymbolFindCmd_EmptyStore: an empty interface store means "nothing
// analysed", which must be a non-success diagnostic, not a confident
// "no exports found".
func TestSymbolFindCmd_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := Run([]string{"symbol-find", "--store-root", dir, "symbol"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected an error for an empty store, got nil")
	}
	if !strings.Contains(err.Error(), "interface store is empty") {
		t.Errorf("expected unresolved diagnostic, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected no stdout when nothing is analysed, got: %q", stdout.String())
	}
}

func TestPrintSymbolRefs_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printSymbolRefs("NoSuch", nil, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `no exports found for symbol "NoSuch"`) {
		t.Errorf("unexpected output: %q", buf.String())
	}
}

func TestPrintSymbolRefs_ShowsPackagePathAndSignature(t *testing.T) {
	refs := []ifaceports.SymbolRef{
		{
			ModulePath:    "example.com/mod",
			ModuleVersion: "v1.0.0",
			PackagePath:   "example.com/mod/pkg",
			SymbolKind:    "func",
			SymbolName:    "New",
			Signature:     "func New() *Client",
		},
	}
	var buf bytes.Buffer
	if err := printSymbolRefs("New", refs, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/mod/pkg") {
		t.Errorf("expected package path in output, got: %q", out)
	}
	if !strings.Contains(out, "func New() *Client") {
		t.Errorf("expected signature in output, got: %q", out)
	}
}

func TestPrintSymbolRefs_MethodShowsParentType(t *testing.T) {
	refs := []ifaceports.SymbolRef{
		{
			ModulePath:    "example.com/mod",
			ModuleVersion: "v1.0.0",
			PackagePath:   "example.com/mod/pkg",
			SymbolKind:    "method",
			SymbolName:    "Do",
			ParentType:    "Client",
			Signature:     "func (c *Client) Do() error",
		},
	}
	var buf bytes.Buffer
	if err := printSymbolRefs("Do", refs, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Client.Do") {
		t.Errorf("expected Client.Do in output, got: %q", out)
	}
	if !strings.Contains(out, "func (c *Client) Do() error") {
		t.Errorf("expected signature in output, got: %q", out)
	}
}

func TestPrintSymbolRefs_MultiPackageSameModule(t *testing.T) {
	// Verify two packages in the same module produce two distinct lines,
	// not duplicates (the original display bug).
	refs := []ifaceports.SymbolRef{
		{
			ModulePath:    "example.com/multi",
			ModuleVersion: "v1.0.0",
			PackagePath:   "example.com/multi/json",
			SymbolKind:    "func",
			SymbolName:    "Marshal",
			Signature:     "func Marshal(v any) ([]byte, error)",
		},
		{
			ModulePath:    "example.com/multi",
			ModuleVersion: "v1.0.0",
			PackagePath:   "example.com/multi/xml",
			SymbolKind:    "func",
			SymbolName:    "Marshal",
			Signature:     "func Marshal(v any) ([]byte, error)",
		},
	}
	var buf bytes.Buffer
	if err := printSymbolRefs("Marshal", refs, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/multi/json") {
		t.Errorf("expected json package path in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/multi/xml") {
		t.Errorf("expected xml package path in output, got: %q", out)
	}
}

func TestPrintSymbolRefs_NoSignature(t *testing.T) {
	// Pre-migration records have empty Signature; output must not emit the signature line.
	refs := []ifaceports.SymbolRef{
		{
			ModulePath:    "example.com/mod",
			ModuleVersion: "v1.0.0",
			PackagePath:   "example.com/mod",
			SymbolKind:    "func",
			SymbolName:    "New",
			Signature:     "",
		},
	}
	var buf bytes.Buffer
	if err := printSymbolRefs("New", refs, &buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line for empty signature, got %d: %q", len(lines), buf.String())
	}
}

func TestPrintRecordText_Full(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("example.com/iface", "v1.0.0")
	r := ifacedomain.InterfaceRecord{
		Coordinate: coord,
		Packages: []ifacedomain.PackageInterface{
			{
				Name:       "mypkg",
				ImportPath: "example.com/iface/mypkg",
				Types: []ifacedomain.TypeDecl{
					{
						Name: "MyType",
						Kind: ifacedomain.TypeKindStruct,
						Methods: []ifacedomain.MethodDecl{
							{Signature: "Do() error"},
						},
					},
				},
				Funcs:  []ifacedomain.FuncDecl{{Signature: "func NewMyType() *MyType"}},
				Consts: []ifacedomain.ValueDecl{{Name: "MaxSize", Type: "int"}},
				Vars:   []ifacedomain.ValueDecl{{Name: "Default", Type: "*MyType"}},
				ParseFailures: []ifacedomain.ParseFailure{
					{File: "broken.go", Error: "syntax error"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := printRecordText(r, &buf); err != nil {
		t.Fatalf("printRecordText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"package mypkg", "type MyType", "Do() error", "NewMyType", "MaxSize", "Default", "[parse failure]"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}
