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
	got, incomplete := domain.AssembleComponents(in)

	if !incomplete {
		t.Error("licensesIncomplete = false, want true (one node lacked license data)")
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
	_, incomplete := domain.AssembleComponents(in)
	if incomplete {
		t.Error("licensesIncomplete = true, want false")
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

func TestAggregateVulnerabilities_DedupAndOrder(t *testing.T) {
	modFoo := domain.ModuleRef{Path: "github.com/example/foo", Version: "v1.0.0"}
	modBar := domain.ModuleRef{Path: "github.com/example/bar", Version: "v2.0.0"}

	findings := []domain.FindingInput{
		{Module: modFoo, ID: "GHSA-zzz", Summary: "z summary", SeverityLabel: "HIGH"},
		{Module: modFoo, ID: "GHSA-aaa", Summary: "first summary", SeverityLabel: "CRITICAL"},
		{Module: modBar, ID: "GHSA-aaa", Summary: "second summary (ignored)", SeverityLabel: "LOW"},
		{Module: modFoo, ID: "GHSA-aaa", Summary: "dup module (ignored)", SeverityLabel: "LOW"},
	}

	got := domain.AggregateVulnerabilities(findings)

	want := []domain.AggregatedVulnerability{
		{
			ID:            "GHSA-aaa",
			Summary:       "first summary",
			SeverityLabel: "CRITICAL",
			Affected:      []domain.ModuleRef{modBar, modFoo}, // sorted by path@version
		},
		{
			ID:            "GHSA-zzz",
			Summary:       "z summary",
			SeverityLabel: "HIGH",
			Affected:      []domain.ModuleRef{modFoo},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AggregateVulnerabilities() = %+v, want %+v", got, want)
	}
}

func TestAggregateVulnerabilities_Empty(t *testing.T) {
	if got := domain.AggregateVulnerabilities(nil); len(got) != 0 {
		t.Errorf("expected empty result, got %+v", got)
	}
}
