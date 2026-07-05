package domain_test

import (
	"testing"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
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
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/m", "v1.0.0")

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
	coord, _ := fetchdomain.NewModuleCoordinate("example.com/m", "v1.0.0")

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
