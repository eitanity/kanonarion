package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// TestCopyrightDeclaration_Validate: every field is required and the date must
// be a date. A declaration missing its provenance is unfalsifiable, so it is
// refused rather than carried into an attribution document nobody can audit.
func TestCopyrightDeclaration_Validate(t *testing.T) {
	complete := domain.CopyrightDeclaration{
		Copyright:  "Copyright SYNTHETIC-FIXTURE-HOLDER",
		DeclaredBy: "test-operator@example.invalid",
		DeclaredOn: "2026-08-25",
		Basis:      "synthetic fixture; no upstream source was read",
	}
	if err := complete.Validate(); err != nil {
		t.Fatalf("a complete declaration was refused: %v", err)
	}

	cases := []struct {
		name      string
		mutate    func(*domain.CopyrightDeclaration)
		wantField string
	}{
		{"no copyright", func(d *domain.CopyrightDeclaration) { d.Copyright = "" }, "copyright"},
		{"no declared_by", func(d *domain.CopyrightDeclaration) { d.DeclaredBy = "" }, "declared_by"},
		{"no declared_on", func(d *domain.CopyrightDeclaration) { d.DeclaredOn = "" }, "declared_on"},
		{"no basis", func(d *domain.CopyrightDeclaration) { d.Basis = "" }, "basis"},
		{"whitespace basis", func(d *domain.CopyrightDeclaration) { d.Basis = "  \t " }, "basis"},
		{"free-text date", func(d *domain.CopyrightDeclaration) { d.DeclaredOn = "last week" }, "declared_on"},
		{"year only", func(d *domain.CopyrightDeclaration) { d.DeclaredOn = "2026" }, "declared_on"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := complete
			c.mutate(&d)
			err := d.Validate()
			if err == nil {
				t.Fatal("Validate accepted an unusable declaration")
			}
			if !strings.Contains(err.Error(), c.wantField) {
				t.Errorf("error does not name %q: %v", c.wantField, err)
			}
		})
	}
}

// TestDefaultConfig_HasNoDeclarations: the built-in default records nothing.
// Every attribution kanonarion publishes out of the box is a measurement.
func TestDefaultConfig_HasNoDeclarations(t *testing.T) {
	if got := len(domain.DefaultConfig().CopyrightDeclarations); got != 0 {
		t.Errorf("DefaultConfig carries %d declarations, want none", got)
	}
}
