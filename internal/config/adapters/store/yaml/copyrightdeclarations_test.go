package yaml_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/adapters/store/yaml"
)

// TestParse_CopyrightDeclarations reads a complete entry back.
func TestParse_CopyrightDeclarations(t *testing.T) {
	input := `
version: "2"
copyright_declarations:
  example.com/mod:
    copyright: "Copyright SYNTHETIC-FIXTURE-HOLDER"
    declared_by: "test-operator@example.invalid"
    declared_on: "2026-08-25"
    basis: "synthetic fixture; no upstream source was read"
  example.com/other@v1.2.3:
    copyright: "Copyright SYNTHETIC-FIXTURE-HOLDER-2"
    declared_by: "test-operator@example.invalid"
    declared_on: "2026-08-24"
    basis: "synthetic fixture, version-pinned"
`
	cfg, err := yaml.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CopyrightDeclarations) != 2 {
		t.Fatalf("got %d declarations, want 2", len(cfg.CopyrightDeclarations))
	}
	d := cfg.CopyrightDeclarations["example.com/mod"]
	if d.Copyright != "Copyright SYNTHETIC-FIXTURE-HOLDER" {
		t.Errorf("copyright = %q", d.Copyright)
	}
	if d.DeclaredBy != "test-operator@example.invalid" || d.DeclaredOn != "2026-08-25" {
		t.Errorf("provenance not read back: %+v", d)
	}
	if d.Basis != "synthetic fixture; no upstream source was read" {
		t.Errorf("basis = %q", d.Basis)
	}
	if _, ok := cfg.CopyrightDeclarations["example.com/other@v1.2.3"]; !ok {
		t.Error("version-pinned key was not read")
	}
}

// TestParse_CopyrightDeclarationIncompleteIsRefused: an entry missing any of
// the four fields is refused at load, naming the coordinate and the field. A
// declaration without its provenance is unfalsifiable, and silently ignoring it
// would leave the operator with a refusal naming the module rather than the
// config line that is wrong.
func TestParse_CopyrightDeclarationIncompleteIsRefused(t *testing.T) {
	const header = "version: \"2\"\ncopyright_declarations:\n  example.com/mod:\n"
	cases := []struct {
		name      string
		body      string
		wantField string
	}{
		{
			name: "missing basis",
			body: "    copyright: \"Copyright X\"\n" +
				"    declared_by: \"a@example.invalid\"\n" +
				"    declared_on: \"2026-08-25\"\n",
			wantField: "basis",
		},
		{
			name: "missing declared_by",
			body: "    copyright: \"Copyright X\"\n" +
				"    declared_on: \"2026-08-25\"\n" +
				"    basis: \"something read\"\n",
			wantField: "declared_by",
		},
		{
			name: "missing declared_on",
			body: "    copyright: \"Copyright X\"\n" +
				"    declared_by: \"a@example.invalid\"\n" +
				"    basis: \"something read\"\n",
			wantField: "declared_on",
		},
		{
			name: "missing copyright",
			body: "    declared_by: \"a@example.invalid\"\n" +
				"    declared_on: \"2026-08-25\"\n" +
				"    basis: \"something read\"\n",
			wantField: "copyright",
		},
		{
			name: "blank basis",
			body: "    copyright: \"Copyright X\"\n" +
				"    declared_by: \"a@example.invalid\"\n" +
				"    declared_on: \"2026-08-25\"\n" +
				"    basis: \"   \"\n",
			wantField: "basis",
		},
		{
			name: "declared_on is not a date",
			body: "    copyright: \"Copyright X\"\n" +
				"    declared_by: \"a@example.invalid\"\n" +
				"    declared_on: \"last week\"\n" +
				"    basis: \"something read\"\n",
			wantField: "declared_on",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := yaml.Parse([]byte(header + tc.body))
			if err == nil {
				t.Fatal("Parse accepted an incomplete declaration")
			}
			msg := err.Error()
			if !strings.Contains(msg, "copyright_declarations.example.com/mod") {
				t.Errorf("error does not name the coordinate: %v", err)
			}
			if !strings.Contains(msg, tc.wantField) {
				t.Errorf("error does not name the field %q: %v", tc.wantField, err)
			}
		})
	}
}

// TestParse_NoCopyrightDeclarationsIsEmpty: an absent section is the default
// empty map, not an error — the same first-run behaviour every other section
// has.
func TestParse_NoCopyrightDeclarationsIsEmpty(t *testing.T) {
	cfg, err := yaml.Parse([]byte("version: \"2\"\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CopyrightDeclarations) != 0 {
		t.Errorf("got %d declarations, want none", len(cfg.CopyrightDeclarations))
	}
}
