package cyclonedx_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// generateWithVendorScope renders a document carrying the supplied scope
// statement and returns the annotations it emitted.
func generateWithVendorScope(t *testing.T, scope vendordomain.VendorScope) ([]byte, scopeBOM) {
	t.Helper()
	return generateWithVendorScopeScoped(t, scope, false)
}

// generateWithVendorScopeScoped renders a document carrying the supplied scope
// statement, optionally flagged as scoped to one binary's import closure.
func generateWithVendorScopeScoped(t *testing.T, scope vendordomain.VendorScope, scopedToBinary bool) ([]byte, scopeBOM) {
	t.Helper()
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	req := makeGenReq(nil)
	req.VendorScope = &scope
	req.ComponentsScopedToBinary = scopedToBinary

	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, nil, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom scopeBOM
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	return rec.Content, bom
}

// A document describing fewer modules than the vendored tree names the
// difference. Before this, a reader saw a component count and no indication
// that the tree held code the document does not list.
func TestGenerate_VendorScopeNamesEveryUndescribedModule(t *testing.T) {
	_, bom := generateWithVendorScope(t, vendordomain.VendorScope{
		TreeModules: 133,
		Covered:     126,
		Uncovered: []vendordomain.UncoveredVendoredModule{
			{Path: "github.com/valyala/fasthttp", Version: "v1.35.0", Reason: vendordomain.ReasonNoPackages},
		},
	})

	if len(bom.Annotations) != 1 {
		t.Fatalf("annotations = %d, want the vendor scope statement", len(bom.Annotations))
	}
	text := bom.Annotations[0].Text
	for _, want := range []string{
		"lists 133 module(s)",
		"describes 126 of them",
		"github.com/valyala/fasthttp v1.35.0",
		"contributes no package to the build",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("scope statement missing %q:\n%s", want, text)
		}
	}
	if bom.Annotations[0].Annotator.Component.Name != "kanonarion" {
		t.Errorf("annotator = %q, want the generator naming itself", bom.Annotations[0].Annotator.Component.Name)
	}
}

// Full coverage is stated, not left to silence: a reader cannot tell a complete
// document from a narrowed one that says nothing.
func TestGenerate_VendorScopeStatesFullCoverageExplicitly(t *testing.T) {
	_, bom := generateWithVendorScope(t, vendordomain.VendorScope{TreeModules: 12, Covered: 12})

	if len(bom.Annotations) != 1 {
		t.Fatalf("annotations = %d, want the vendor scope statement", len(bom.Annotations))
	}
	if !strings.Contains(bom.Annotations[0].Text, "Every module in the vendored tree is described here") {
		t.Errorf("full coverage was not stated:\n%s", bom.Annotations[0].Text)
	}
}

// A walk with no vendored tree behind it states no vendor scope: a statement
// about a surface that is not there is noise a reader has to rule out.
func TestGenerate_NoVendorTreeNoScopeAnnotation(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})

	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom scopeBOM
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if len(bom.Annotations) != 0 {
		t.Errorf("annotations emitted with no vendored tree and no advisories: %+v", bom.Annotations)
	}
}

// Determinism is a shipped property of this generator and the statement must
// not cost it.
func TestGenerate_VendorScopeIsByteStable(t *testing.T) {
	scope := vendordomain.VendorScope{
		TreeModules: 3, Covered: 2,
		Uncovered: []vendordomain.UncoveredVendoredModule{
			{Path: "example.com/idle", Version: "v9.9.9", Reason: vendordomain.ReasonNoPackages},
		},
	}
	first, _ := generateWithVendorScope(t, scope)
	second, _ := generateWithVendorScope(t, scope)
	if !bytes.Equal(first, second) {
		t.Error("two generations from identical inputs differ")
	}
}

// The road-tested overclaim: a module carrying package lines in modules.txt was
// reported as contributing packages to the build. `go mod vendor` writes a line
// for every package reachable under ANY build constraint, so a `//go:build
// modhack` shim is vendored and never compiled — the statement must report the
// lines it counted and say what a line is, not convert the count into a claim
// about this build's import graph.
func TestGenerate_VendorScopeDoesNotClaimBuildMembershipFromPackageLines(t *testing.T) {
	_, bom := generateWithVendorScope(t, vendordomain.VendorScope{
		TreeModules: 133,
		Covered:     119,
		Uncovered: []vendordomain.UncoveredVendoredModule{
			{
				Path: "cloud.google.com/go/compute", Version: "v1.24.0",
				Reason: vendordomain.ReasonNotDescribed, PackageLines: 1,
			},
		},
	})

	if len(bom.Annotations) != 1 {
		t.Fatalf("annotations = %d, want the vendor scope statement", len(bom.Annotations))
	}
	text := bom.Annotations[0].Text
	if strings.Contains(text, "contributes packages to the build") {
		t.Errorf("statement claims build membership it did not measure:\n%s", text)
	}
	for _, want := range []string{
		"vendor/modules.txt lists package lines under it that this document does not describe",
		"(1 package line(s))",
		"it is not a count of what this build compiles",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("statement missing %q:\n%s", want, text)
		}
	}
}

// A document asked for one binary describes fewer modules than the tree by
// construction. Saying so separates "you asked for a narrower subject" from
// "something is missing", which the uncovered list alone cannot.
func TestGenerate_VendorScopeNamesABinaryScopedComponentList(t *testing.T) {
	scope := vendordomain.VendorScope{
		TreeModules: 133, Covered: 119,
		Uncovered: []vendordomain.UncoveredVendoredModule{
			{Path: "example.com/mod", Version: "v1.0.0", Reason: vendordomain.ReasonNotDescribed, PackageLines: 2},
		},
	}
	_, scoped := generateWithVendorScopeScoped(t, scope, true)
	if !strings.Contains(scoped.Annotations[0].Text, "scoped to a single binary's import closure") {
		t.Errorf("a package-scoped document does not say so:\n%s", scoped.Annotations[0].Text)
	}

	_, whole := generateWithVendorScopeScoped(t, scope, false)
	if strings.Contains(whole.Annotations[0].Text, "scoped to a single binary") {
		t.Errorf("a whole-build document claims a binary scope it does not have:\n%s", whole.Annotations[0].Text)
	}
}
