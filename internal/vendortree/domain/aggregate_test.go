package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

func base() domain.ParseResult {
	return domain.ParseResult{
		ProjectModulePath: "example.com/proj",
		VendorDir:         "vendor",
		ModulesTxt: []domain.VendoredModule{
			{Path: "example.com/dep", Version: "v1.2.0", Explicit: true},
		},
		GoModRequires:  map[string]string{"example.com/dep": "v1.2.0"},
		GoSum:          map[string]string{"example.com/dep@v1.2.0": "h1:EXPECTED"},
		PresentDirs:    map[string]bool{"example.com/dep": true},
		ComputedHashes: map[string]string{"example.com/dep": "h1:EXPECTED"},
	}
}

func kinds(fs []domain.Finding) map[domain.FindingKind]domain.Finding {
	m := map[domain.FindingKind]domain.Finding{}
	for _, f := range fs {
		m[f.Kind] = f
	}
	return m
}

// TestAggregate_Clean: vendor matches the go.sum checksum and modules.txt
// agrees with go.mod — zero findings, confident clean.
func TestAggregate_Clean(t *testing.T) {
	mods, fs := domain.Aggregate(base())
	if len(fs) != 0 {
		t.Fatalf("want clean, got findings %+v", fs)
	}
	if domain.OverallStatus(fs) != "clean" {
		t.Errorf("status = %q, want clean", domain.OverallStatus(fs))
	}
	if mods[0].Dir != "vendor/example.com/dep" {
		t.Errorf("reachability dir = %q", mods[0].Dir)
	}
}

// TestAggregate_Drift: one vendored file differs → the recomputed hash no
// longer matches go.sum; drift is reported with both hashes (case 2).
func TestAggregate_Drift(t *testing.T) {
	in := base()
	in.ComputedHashes["example.com/dep"] = "h1:TAMPERED"
	_, fs := domain.Aggregate(in)
	d, ok := kinds(fs)[domain.FindingDrift]
	if !ok {
		t.Fatalf("want drift finding, got %+v", fs)
	}
	if d.Expected != "h1:EXPECTED" || d.Actual != "h1:TAMPERED" {
		t.Errorf("drift hashes not reported: %+v", d)
	}
	if d.Kind.PolicyCategory() != "drift" {
		t.Errorf("drift maps to %q, want drift", d.Kind.PolicyCategory())
	}
}

// TestAggregate_MissingFromVendor: modules.txt references a module absent
// from vendor/ → inconsistency reported (case 3).
func TestAggregate_MissingFromVendor(t *testing.T) {
	in := base()
	in.PresentDirs = map[string]bool{}
	_, fs := domain.Aggregate(in)
	f, ok := kinds(fs)[domain.FindingMissingFromVendor]
	if !ok {
		t.Fatalf("want missing-from-vendor, got %+v", fs)
	}
	if f.Kind.PolicyCategory() != "inconsistency" {
		t.Errorf("maps to %q, want inconsistency", f.Kind.PolicyCategory())
	}
}

// TestAggregate_Unverified: a vendored module with no go.sum entry is
// surfaced as uncertainty, never silently clean.
func TestAggregate_Unverified(t *testing.T) {
	in := base()
	in.GoSum = map[string]string{}
	_, fs := domain.Aggregate(in)
	if _, ok := kinds(fs)[domain.FindingUnverified]; !ok {
		t.Fatalf("want unverified finding, got %+v", fs)
	}
	if domain.OverallStatus(fs) == "clean" {
		t.Error("missing checksum must not be reported clean")
	}
}

// TestAggregate_VersionAndModulesTxtDisagree: go.mod and vendor disagree on
// both presence and version (case 4: both views reported).
func TestAggregate_VersionAndModulesTxtDisagree(t *testing.T) {
	in := base()
	in.GoModRequires = map[string]string{
		"example.com/dep":   "v1.3.0", // version mismatch vs modules.txt v1.2.0
		"example.com/other": "v0.1.0", // required but not vendored/listed
	}
	_, fs := domain.Aggregate(in)
	k := kinds(fs)
	if vm, ok := k[domain.FindingVersionMismatch]; !ok || vm.Expected != "v1.3.0" || vm.Actual != "v1.2.0" {
		t.Errorf("version mismatch not reported with both views: %+v", fs)
	}
	if _, ok := k[domain.FindingMissingFromModulesTxt]; !ok {
		t.Errorf("go.mod require missing from modules.txt not reported: %+v", fs)
	}
}

// TestSortDeterministic guards stable ordering for the content hash.
func TestSortDeterministic(t *testing.T) {
	ms := []domain.VendoredModule{{Path: "b"}, {Path: "a"}}
	fs := []domain.Finding{{Module: "b", Kind: domain.FindingDrift}, {Module: "a", Kind: domain.FindingUnverified}}
	domain.SortModules(ms)
	domain.SortFindings(fs)
	h1 := domain.Hash(ms, fs)

	ms2 := []domain.VendoredModule{{Path: "a"}, {Path: "b"}}
	fs2 := []domain.Finding{{Module: "a", Kind: domain.FindingUnverified}, {Module: "b", Kind: domain.FindingDrift}}
	domain.SortModules(ms2)
	domain.SortFindings(fs2)
	if domain.Hash(ms2, fs2) != h1 {
		t.Error("hash not permutation-invariant after sort")
	}
}
