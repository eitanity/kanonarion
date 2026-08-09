package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/iface/domain"
)

func TestInterfaceStatus_String(t *testing.T) {
	cases := []struct {
		s    domain.InterfaceStatus
		want string
	}{
		{domain.InterfaceStatusUnknown, "Unknown"},
		{domain.InterfaceStatusExtracted, "Extracted"},
		{domain.InterfaceStatusPartial, "Partial"},
		{domain.InterfaceStatusExtractionFailed, "ExtractionFailed"},
		{domain.InterfaceStatusCancelled, "Cancelled"},
		{domain.InterfaceStatus(99), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("InterfaceStatus(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestTypeKind_String(t *testing.T) {
	cases := []struct {
		k    domain.TypeKind
		want string
	}{
		{domain.TypeKindStruct, "struct"},
		{domain.TypeKindInterface, "interface"},
		{domain.TypeKindAlias, "alias"},
		{domain.TypeKindDefined, "defined"},
		{domain.TypeKindGeneric, "generic"},
		{domain.TypeKind(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("TypeKind(%d).String() = %q, want %q", tc.k, got, tc.want)
		}
	}
}

func TestInterfaceRecord_Sort_Deterministic(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")

	r := domain.InterfaceRecord{
		Coordinate: coord,
		Packages: []domain.PackageInterface{
			{
				ImportPath: "example.com/m/b",
				Types: []domain.TypeDecl{
					{Name: "Z"},
					{Name: "A"},
				},
				Funcs: []domain.FuncDecl{
					{Name: "Zfunc"},
					{Name: "Afunc"},
				},
				Consts: []domain.ValueDecl{{Name: "CB"}, {Name: "CA"}},
				Vars:   []domain.ValueDecl{{Name: "VB"}, {Name: "VA"}},
			},
			{
				ImportPath: "example.com/m/a",
			},
		},
	}

	r.Sort()

	if r.Packages[0].ImportPath != "example.com/m/a" {
		t.Errorf("packages not sorted by ImportPath: got %s", r.Packages[0].ImportPath)
	}
	b := r.Packages[1]
	if b.Types[0].Name != "A" || b.Types[1].Name != "Z" {
		t.Errorf("types not sorted: %v", []string{b.Types[0].Name, b.Types[1].Name})
	}
	if b.Funcs[0].Name != "Afunc" {
		t.Errorf("funcs not sorted: %v", []string{b.Funcs[0].Name, b.Funcs[1].Name})
	}
	if b.Consts[0].Name != "CA" {
		t.Errorf("consts not sorted: %v", []string{b.Consts[0].Name, b.Consts[1].Name})
	}
	if b.Vars[0].Name != "VA" {
		t.Errorf("vars not sorted: %v", []string{b.Vars[0].Name, b.Vars[1].Name})
	}
}

func TestInterfaceRecord_Sort_Methods(t *testing.T) {
	coord, _ := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")

	r := domain.InterfaceRecord{
		Coordinate: coord,
		Packages: []domain.PackageInterface{
			{
				ImportPath: "example.com/m",
				Types: []domain.TypeDecl{
					{
						Name: "Client",
						Methods: []domain.MethodDecl{
							{Name: "Send"},
							{Name: "Close"},
						},
						EmbeddedTypes: []string{"io.Writer", "fmt.Stringer"},
					},
				},
			},
		},
	}

	r.Sort()

	methods := r.Packages[0].Types[0].Methods
	if methods[0].Name != "Close" || methods[1].Name != "Send" {
		t.Errorf("methods not sorted: %v", []string{methods[0].Name, methods[1].Name})
	}

	embedded := r.Packages[0].Types[0].EmbeddedTypes
	if embedded[0] != "fmt.Stringer" {
		t.Errorf("embedded types not sorted: %v", embedded)
	}
}

// Every collection Sort touches is put in a canonical order, including the ones
// nested inside a type declaration. The record is hashed after this, so a
// collection left in source order would make the seal depend on the order the
// extractor happened to walk the file.
func TestInterfaceRecord_Sort_EveryNestedCollection(t *testing.T) {
	r := domain.InterfaceRecord{
		Packages: []domain.PackageInterface{{
			ImportPath: "example.com/mod",
			Types: []domain.TypeDecl{{
				Name: "Client",
				Fields: []domain.FieldDecl{
					{Name: "Zeta"}, {Name: "Alpha"},
				},
				Methods: []domain.MethodDecl{
					{Name: "Send"}, {Name: "Close"},
				},
				EmbeddedTypes: []string{"io.Writer", "io.Closer"},
				TypeParams: []domain.TypeParam{
					{Name: "V", Constraint: "any"}, {Name: "K", Constraint: "comparable"},
				},
			}},
			Funcs: []domain.FuncDecl{{
				Name: "New",
				TypeParams: []domain.TypeParam{
					{Name: "T", Constraint: "any"}, {Name: "S", Constraint: "any"},
				},
			}},
			Consts: []domain.ValueDecl{{Name: "Limit"}, {Name: "Default"}},
			Vars:   []domain.ValueDecl{{Name: "Registry"}, {Name: "Client"}},
			ParseFailures: []domain.ParseFailure{
				{File: "z.go", Error: "boom"}, {File: "a.go", Error: "boom"},
			},
		}},
	}

	r.Sort()

	p := r.Packages[0]
	tt := p.Types[0]
	if tt.Fields[0].Name != "Alpha" || tt.Fields[1].Name != "Zeta" {
		t.Errorf("fields unsorted: %+v", tt.Fields)
	}
	if tt.Methods[0].Name != "Close" || tt.Methods[1].Name != "Send" {
		t.Errorf("methods unsorted: %+v", tt.Methods)
	}
	if tt.EmbeddedTypes[0] != "io.Closer" || tt.EmbeddedTypes[1] != "io.Writer" {
		t.Errorf("embedded types unsorted: %v", tt.EmbeddedTypes)
	}
	if tt.TypeParams[0].Name != "K" || tt.TypeParams[1].Name != "V" {
		t.Errorf("type params unsorted: %+v", tt.TypeParams)
	}
	if p.Funcs[0].TypeParams[0].Name != "S" || p.Funcs[0].TypeParams[1].Name != "T" {
		t.Errorf("func type params unsorted: %+v", p.Funcs[0].TypeParams)
	}
	if p.Consts[0].Name != "Default" || p.Vars[0].Name != "Client" {
		t.Errorf("consts/vars unsorted: %+v %+v", p.Consts, p.Vars)
	}
	if p.ParseFailures[0].File != "a.go" {
		t.Errorf("parse failures unsorted: %+v", p.ParseFailures)
	}
}
