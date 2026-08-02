package domain_test

import (
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/sbom/domain"
)

func TestLicenseClause(t *testing.T) {
	cases := []struct {
		name        string
		hasLicense  bool
		primarySPDX string
		expression  string
		want        string
	}{
		{"present with spdx", true, "MIT", "", "MIT"},
		{"present with expression", true, "MIT", "MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		{"expression preferred over primary", true, "MIT", "MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		{"present empty spdx", true, "", "", ""},
		{"absent with spdx string", false, "MIT", "", ""},
		{"absent with expression", false, "MIT", "MIT OR Apache-2.0", ""},
		{"absent empty", false, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := domain.LicenseClause(c.hasLicense, c.primarySPDX, c.expression); got != c.want {
				t.Errorf("LicenseClause(%v, %q, %q) = %q, want %q", c.hasLicense, c.primarySPDX, c.expression, got, c.want)
			}
		})
	}
}

func TestAssembleComponents_OrderingAndLicense(t *testing.T) {
	in := []domain.ComponentInput{
		{Module: domain.ModuleRef{Path: "github.com/zzz/last", Version: "v1.0.0"}, HasLicense: true, PrimarySPDX: "MIT"},
		{Module: domain.ModuleRef{Path: "github.com/aaa/first", Version: "v1.0.0"}, HasLicense: false},
		{Module: domain.ModuleRef{Path: "github.com/mmm/mid", Version: "v2.0.0"}, HasLicense: true, PrimarySPDX: ""},
	}
	got, undetermined := domain.AssembleComponents(in)

	// Both the node with no record at all and the node whose record identified no
	// SPDX licence are undetermined: the document carries no licences block for
	// either, which is the only thing a reader of it can see.
	wantUndetermined := []domain.ModuleRef{
		{Path: "github.com/aaa/first", Version: "v1.0.0"},
		{Path: "github.com/mmm/mid", Version: "v2.0.0"},
	}
	if !reflect.DeepEqual(undetermined, wantUndetermined) {
		t.Errorf("undetermined = %+v, want %+v", undetermined, wantUndetermined)
	}
	want := []domain.Component{
		{Module: domain.ModuleRef{Path: "github.com/aaa/first", Version: "v1.0.0"}, License: ""},
		{Module: domain.ModuleRef{Path: "github.com/mmm/mid", Version: "v2.0.0"}, License: ""},
		{Module: domain.ModuleRef{Path: "github.com/zzz/last", Version: "v1.0.0"}, License: "MIT"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AssembleComponents() = %+v, want %+v", got, want)
	}
}

func TestAssembleComponents_AllLicensed(t *testing.T) {
	in := []domain.ComponentInput{
		{Module: domain.ModuleRef{Path: "a", Version: "v1"}, HasLicense: true, PrimarySPDX: "Apache-2.0"},
	}
	_, undetermined := domain.AssembleComponents(in)
	if len(undetermined) != 0 {
		t.Errorf("undetermined = %+v, want none", undetermined)
	}
}

// A licence record that ran and identified nothing — no licence file at the
// module root, or files matching no known SPDX text — is the case the store holds
// most of, and it produces a component with no licences block. Counting it as
// complete is what let a document ship components with no licence identity at
// exit 0.
func TestAssembleComponents_RecordWithNoSPDXIsUndetermined(t *testing.T) {
	in := []domain.ComponentInput{
		{Module: domain.ModuleRef{Path: "github.com/x/unclassified", Version: "v1"}, HasLicense: true, PrimarySPDX: "", Expression: ""},
	}
	got, undetermined := domain.AssembleComponents(in)
	if got[0].License != "" {
		t.Fatalf("License = %q, want empty (the fixture identifies no licence)", got[0].License)
	}
	if len(undetermined) != 1 || undetermined[0].Path != "github.com/x/unclassified" {
		t.Errorf("undetermined = %+v, want the single unclassified module", undetermined)
	}
}

func TestAssembleComponents_CopyrightPassthrough(t *testing.T) {
	// Copyright strings pass through from ComponentInput to Component unchanged.
	in := []domain.ComponentInput{
		{Module: domain.ModuleRef{Path: "github.com/aaa/has-copyright", Version: "v1.0.0"}, HasLicense: true, PrimarySPDX: "MIT", Copyright: "Copyright 2020 Alice"},
		{Module: domain.ModuleRef{Path: "github.com/bbb/no-copyright", Version: "v1.0.0"}, HasLicense: true, PrimarySPDX: "Apache-2.0", Copyright: ""},
	}
	got, _ := domain.AssembleComponents(in)
	want := []domain.Component{
		{Module: domain.ModuleRef{Path: "github.com/aaa/has-copyright", Version: "v1.0.0"}, License: "MIT", Copyright: "Copyright 2020 Alice"},
		{Module: domain.ModuleRef{Path: "github.com/bbb/no-copyright", Version: "v1.0.0"}, License: "Apache-2.0", Copyright: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AssembleComponents copyright passthrough: got %+v, want %+v", got, want)
	}
}
