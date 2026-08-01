package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fakeVendorTree serves a canned vendor/modules.txt entry set.
type fakeVendorTree struct {
	mods []vendordomain.VendoredModule
	err  error
	// gotGoMod records the go.mod path the reader was pointed at, so a test can
	// assert the scope was measured against the tree the walk was rooted at.
	gotGoMod string
}

func (f *fakeVendorTree) VendorTree(_ context.Context, goModPath string) ([]vendordomain.VendoredModule, error) {
	f.gotGoMod = goModPath
	return f.mods, f.err
}

func coordOf(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("coordinate %s@%s: %v", path, version, err)
	}
	return c
}

// vendoredWalk is a project-rooted walk whose graph holds the main module, a
// plain dependency and a dependency replaced by a fork — the shape that makes
// the two module identities differ.
func vendoredWalk(t *testing.T, projectDir string) walkdomain.WalkRecord {
	t.Helper()
	main := coordOf(t, "example.com/project", coordinate.LocalVersion)
	dep := coordOf(t, "example.com/dep", "v1.2.0")
	fork := coordOf(t, "example.com/fork", "v1.2.4")
	orig := coordOf(t, "example.com/upstream", "v1.2.1")
	return walkdomain.WalkRecord{
		ID:         "walk-vendored",
		ProjectDir: projectDir,
		Graph: walkdomain.Graph{
			Target: main,
			Nodes: []walkdomain.GraphNode{
				{Coordinate: main},
				{Coordinate: dep},
				{Coordinate: fork, OriginalCoordinate: orig, ResolutionSource: walkdomain.ResolutionReplace},
			},
		},
	}
}

func generateWith(t *testing.T, walk walkdomain.WalkRecord, tree *fakeVendorTree) *fakeSBOMGenerator {
	t.Helper()
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: walk.ID}}
	uc := makeUC(&fakeWalkStore{walk: walk}, &fakeVulnStore{}, &fakeSBOMStore{}, gen)
	if tree != nil {
		uc = uc.WithVendorTree(tree)
	}
	if _, err := uc.Generate(context.Background(), application.SBOMRequest{WalkID: walk.ID}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return gen
}

// TestGenerateSBOM_VendorScopeNamesTheExcludedModuleAndItsReason: a vendored
// tree holding a module the document does not describe yields a scope statement
// naming it and why.
func TestGenerateSBOM_VendorScopeNamesTheExcludedModuleAndItsReason(t *testing.T) {
	tree := &fakeVendorTree{mods: []vendordomain.VendoredModule{
		{Path: "example.com/dep", Version: "v1.2.0", PackageCount: 2},
		{Path: "example.com/upstream", Version: "v1.2.1", PackageCount: 1},
		{Path: "example.com/idle", Version: "v9.9.9", PackageCount: 0},
	}}
	gen := generateWith(t, vendoredWalk(t, "/work/project"), tree)

	if tree.gotGoMod != "/work/project/go.mod" {
		t.Errorf("scope measured against %q, want the walk's own project go.mod", tree.gotGoMod)
	}
	scope := gen.capturedReq.VendorScope
	if scope == nil {
		t.Fatal("no scope statement was passed to the generator")
	}
	if scope.TreeModules != 3 || scope.Covered != 2 {
		t.Errorf("scope = %d of %d, want 2 of 3", scope.Covered, scope.TreeModules)
	}
	if len(scope.Uncovered) != 1 || scope.Uncovered[0].Path != "example.com/idle" {
		t.Fatalf("uncovered = %+v, want exactly the zero-package module", scope.Uncovered)
	}
	if scope.Uncovered[0].Reason != vendordomain.ReasonNoPackages {
		t.Errorf("reason = %q, want out-of-scope-by-construction", scope.Uncovered[0].Reason)
	}
}

// TestGenerateSBOM_VendorScopeMatchesAReplacedModuleUnderItsOriginalPath is the
// replace seam: `go mod vendor` files a replaced module under its ORIGINAL
// path, while the walk node carries the REPLACEMENT coordinate. Matching on the
// node coordinate alone reports every fork as absent from a document that
// describes it.
func TestGenerateSBOM_VendorScopeMatchesAReplacedModuleUnderItsOriginalPath(t *testing.T) {
	tree := &fakeVendorTree{mods: []vendordomain.VendoredModule{
		{Path: "example.com/upstream", Version: "v1.2.1", PackageCount: 1},
	}}
	gen := generateWith(t, vendoredWalk(t, "/work/project"), tree)

	scope := gen.capturedReq.VendorScope
	if scope == nil {
		t.Fatal("no scope statement was passed to the generator")
	}
	if !scope.FullyCovered() {
		t.Errorf("the replaced module reads as uncovered: %+v", scope.Uncovered)
	}
}

// TestGenerateSBOM_VendorScopeStatesFullCoverage: a fully covered tree says so
// rather than staying silent.
func TestGenerateSBOM_VendorScopeStatesFullCoverage(t *testing.T) {
	tree := &fakeVendorTree{mods: []vendordomain.VendoredModule{
		{Path: "example.com/dep", Version: "v1.2.0", PackageCount: 2},
	}}
	gen := generateWith(t, vendoredWalk(t, "/work/project"), tree)

	scope := gen.capturedReq.VendorScope
	if scope == nil {
		t.Fatal("a fully covered tree must still state its scope")
	}
	if scope.TreeModules != 1 || scope.Covered != 1 || !scope.FullyCovered() {
		t.Errorf("scope = %+v, want 1 of 1 fully covered", scope)
	}
}

// TestGenerateSBOM_NoVendorScopeWithoutSomethingToMeasure: no reader, no
// recorded project root, no vendored tree, or a tree that could not be read —
// each leaves the document silent rather than stating a scope it did not
// measure.
func TestGenerateSBOM_NoVendorScopeWithoutSomethingToMeasure(t *testing.T) {
	for name, tc := range map[string]struct {
		walk walkdomain.WalkRecord
		tree *fakeVendorTree
	}{
		"no reader wired":      {walk: vendoredWalk(t, "/work/project"), tree: nil},
		"no project root":      {walk: vendoredWalk(t, ""), tree: &fakeVendorTree{mods: []vendordomain.VendoredModule{{Path: "example.com/dep"}}}},
		"project not vendored": {walk: vendoredWalk(t, "/work/project"), tree: &fakeVendorTree{}},
		"tree unreadable":      {walk: vendoredWalk(t, "/work/project"), tree: &fakeVendorTree{err: errors.New("permission denied")}},
	} {
		t.Run(name, func(t *testing.T) {
			gen := generateWith(t, tc.walk, tc.tree)
			if gen.capturedReq.VendorScope != nil {
				t.Errorf("scope = %+v, want none: there was nothing to measure against", gen.capturedReq.VendorScope)
			}
		})
	}
}

// TestGenerateSBOM_BinaryScopedRequestIsFlaggedToTheGenerator: a --package run
// narrows the component list to one binary's import closure, so most of the
// vendored tree falls outside the document by construction. The generator is
// told, so the statement can separate that from something having gone missing —
// and the coverage arithmetic is measured against the components the document
// actually carries, not the unfiltered walk.
func TestGenerateSBOM_BinaryScopedRequestIsFlaggedToTheGenerator(t *testing.T) {
	walk := vendoredWalk(t, "/work/project")
	tree := &fakeVendorTree{mods: []vendordomain.VendoredModule{
		{Path: "example.com/dep", Version: "v1.2.0", PackageCount: 2},
		{Path: "example.com/upstream", Version: "v1.2.1", PackageCount: 1},
	}}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: walk.ID}}
	uc := makeUC(&fakeWalkStore{walk: walk}, &fakeVulnStore{}, &fakeSBOMStore{}, gen).WithVendorTree(tree)

	// Only the plain dependency is in the binary's closure; the fork is not.
	if _, err := uc.Generate(context.Background(), application.SBOMRequest{
		WalkID:    walk.ID,
		AllowList: []coordinate.ModuleCoordinate{coordOf(t, "example.com/dep", "v1.2.0")},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !gen.capturedReq.ComponentsScopedToBinary {
		t.Error("a --package request was not flagged as binary-scoped")
	}
	scope := gen.capturedReq.VendorScope
	if scope == nil {
		t.Fatal("a binary-scoped document still states its vendor scope")
	}
	if scope.Covered != 1 || len(scope.Uncovered) != 1 || scope.Uncovered[0].Path != "example.com/upstream" {
		t.Errorf("scope = %+v, want the filtered-out fork reported uncovered under its original path", scope)
	}
	if scope.Uncovered[0].PackageLines != 1 {
		t.Errorf("PackageLines = %d, want the 1 line modules.txt records", scope.Uncovered[0].PackageLines)
	}
}

// An unscoped run is not flagged: the document describes the whole build, and
// claiming a binary scope it does not have would explain away real gaps.
func TestGenerateSBOM_WholeBuildRequestIsNotFlaggedBinaryScoped(t *testing.T) {
	tree := &fakeVendorTree{mods: []vendordomain.VendoredModule{
		{Path: "example.com/dep", Version: "v1.2.0", PackageCount: 2},
	}}
	gen := generateWith(t, vendoredWalk(t, "/work/project"), tree)
	if gen.capturedReq.ComponentsScopedToBinary {
		t.Error("a whole-build request was flagged as binary-scoped")
	}
}
