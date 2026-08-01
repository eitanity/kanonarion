package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// zeroPackageTree is base() plus a module the module graph carries and no
// package of the build imports: `go mod vendor` writes its heading into
// modules.txt and vendors no directory for it.
func zeroPackageTree() domain.ParseResult {
	in := base()
	in.ModulesTxt = append(in.ModulesTxt, domain.VendoredModule{
		Path: "github.com/valyala/fasthttp", Version: "v1.35.0", Explicit: true,
	})
	return in
}

// TestAggregate_ZeroPackageModuleIsNotMissingFromVendor pins the false positive:
// a module contributing no package is correctly absent from the tree, and an
// absence that is correct must never be rendered as drift.
func TestAggregate_ZeroPackageModuleIsNotMissingFromVendor(t *testing.T) {
	_, fs, _ := domain.Aggregate(zeroPackageTree())
	for _, f := range fs {
		if f.Module == "github.com/valyala/fasthttp" {
			t.Errorf("zero-package module reported as %s: %+v", f.Kind, f)
		}
	}
	if domain.OverallStatus(fs) != "clean" {
		t.Errorf("overall status = %q, want clean — the tree is exactly as `go mod vendor` left it", domain.OverallStatus(fs))
	}
}

// TestAggregate_ScopeNamesTheExcludedModuleAndTheReason is the scope statement:
// a tree holding a module the report describes nothing of yields a statement
// naming it and why.
func TestAggregate_ScopeNamesTheExcludedModuleAndTheReason(t *testing.T) {
	_, _, scope := domain.Aggregate(zeroPackageTree())
	if scope.TreeModules != 2 || scope.Covered != 1 {
		t.Errorf("scope = %d of %d, want 1 of 2", scope.Covered, scope.TreeModules)
	}
	if len(scope.Uncovered) != 1 {
		t.Fatalf("uncovered = %+v, want exactly the zero-package module", scope.Uncovered)
	}
	u := scope.Uncovered[0]
	if u.Path != "github.com/valyala/fasthttp" || u.Version != "v1.35.0" {
		t.Errorf("uncovered names %s %s, want the zero-package module", u.Path, u.Version)
	}
	if !strings.Contains(u.Reason, "no package") {
		t.Errorf("reason = %q, want it to say the module contributes no package", u.Reason)
	}
	if scope.FullyCovered() {
		t.Error("FullyCovered must be false when a tree module is not described")
	}
}

// TestAggregate_FullyCoveredTreeStatesFullCoverage: silence is not a statement.
// A report covering the whole tree says so.
func TestAggregate_FullyCoveredTreeStatesFullCoverage(t *testing.T) {
	_, _, scope := domain.Aggregate(base())
	if scope.TreeModules != 1 || scope.Covered != 1 {
		t.Errorf("scope = %d of %d, want 1 of 1", scope.Covered, scope.TreeModules)
	}
	if !scope.FullyCovered() {
		t.Errorf("FullyCovered = false with uncovered %+v, want true", scope.Uncovered)
	}
}

// TestScopeOverTree_ReasonsStateWhatWasCountedNotBuildMembership: the two
// absences are different facts and only one of them settles build membership.
// A module with no package line under it has no vendored code under ANY build
// constraint, so it contributes nothing to this build either — that reason may
// say so. A module WITH package lines has only been shown to carry lines `go
// mod vendor` wrote across all constraints; `//go:build modhack` shims are
// vendored and never compiled, so its reason must state the lines it counted
// and not claim the build compiles them.
func TestScopeOverTree_ReasonsStateWhatWasCountedNotBuildMembership(t *testing.T) {
	mods := []domain.VendoredModule{
		{Path: "example.com/lines", Version: "v1.0.0", PackageCount: 3},
		{Path: "example.com/idle", Version: "v2.0.0", PackageCount: 0},
	}
	scope := domain.ScopeOverTree(mods, func(domain.VendoredModule) bool { return false })
	if len(scope.Uncovered) != 2 {
		t.Fatalf("uncovered = %+v, want both", scope.Uncovered)
	}
	byPath := map[string]domain.UncoveredVendoredModule{}
	for _, u := range scope.Uncovered {
		byPath[u.Path] = u
	}

	withLines := byPath["example.com/lines"]
	if withLines.Reason != domain.ReasonNotDescribed {
		t.Errorf("a module with package lines reads as %q, want the not-described reason", withLines.Reason)
	}
	if strings.Contains(withLines.Reason, "to the build") {
		t.Errorf("reason %q claims build membership, which counting modules.txt lines does not establish", withLines.Reason)
	}
	if withLines.PackageLines != 3 {
		t.Errorf("PackageLines = %d, want the 3 lines counted", withLines.PackageLines)
	}

	idle := byPath["example.com/idle"]
	if idle.Reason != domain.ReasonNoPackages {
		t.Errorf("a zero-line module reads as %q, want out-of-scope-by-construction", idle.Reason)
	}
	if idle.PackageLines != 0 {
		t.Errorf("PackageLines = %d, want 0", idle.PackageLines)
	}
}

func TestScopeOverTree_OrdersTwoVersionsOfOneModule(t *testing.T) {
	mods := []domain.VendoredModule{
		{Path: "example.com/idle", Version: "v2.0.0"},
		{Path: "example.com/idle", Version: "v1.0.0"},
	}
	scope := domain.ScopeOverTree(mods, nil)
	if len(scope.Uncovered) != 2 {
		t.Fatalf("uncovered = %+v, want both entries", scope.Uncovered)
	}
	if scope.Uncovered[0].Version != "v1.0.0" || scope.Uncovered[1].Version != "v2.0.0" {
		t.Errorf("uncovered order = %+v, want ascending by version", scope.Uncovered)
	}
}
