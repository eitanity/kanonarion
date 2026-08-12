package cyclonedx_test

import (
	"encoding/json"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"

	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestStampedSubjectHasOneIdentityInTheDocument verifies that a stamped subject
// is described once, at one version, with one licence.
//
// The subject appears in two places — metadata.component and its own entry in
// the component list — and a stamp that reached only the first made one document
// assert two purls for one module: the release version on the subject and the
// synthetic "local" in the inventory. A consumer resolving those sees two
// artefacts, and only one of them carries the licence the operator supplied.
func TestStampedSubjectHasOneIdentityInTheDocument(t *testing.T) {
	main := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	dep := mustCoord(t, "example.com/dep", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{main, dep})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq()
	req.MainComponentVersion = "v9.9.9"
	req.MainComponentLicense = "Apache-2.0"

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	primary, byPURL := bomComponents(t, rec.Content)

	if primary["purl"] != "pkg:golang/example.com/project@v9.9.9" {
		t.Errorf("subject purl = %v, want the stamped coordinate", primary["purl"])
	}
	// Exactly one component names the module, and it is the stamped one.
	var named []string
	for purl, comp := range byPURL {
		if comp["name"] == "example.com/project" {
			named = append(named, purl)
		}
	}
	if len(named) != 1 || named[0] != "pkg:golang/example.com/project@v9.9.9" {
		t.Fatalf("component entries for the subject = %v, want exactly [pkg:golang/example.com/project@v9.9.9]", named)
	}
	entry := byPURL["pkg:golang/example.com/project@v9.9.9"]
	if entry["version"] != "v9.9.9" {
		t.Errorf("subject component version = %v, want v9.9.9", entry["version"])
	}
	if entry["type"] != "application" {
		t.Errorf("subject component type = %v, want application (it is the same component as the subject)", entry["type"])
	}
	if got := licenseIDs(entry); len(got) != 1 || got[0] != "Apache-2.0" {
		t.Errorf("subject component licences = %v, want [Apache-2.0]", got)
	}
}

// TestStampedSubjectIsNotCountedUnlicensed verifies the stamped licence reaches
// the copy the undetermined-licence count reads. --main-license is documented as
// the way to stop the partial exit firing on the subject; a stamp that did not
// reach the component list left the operator doing the documented thing and
// still being told their own module has no licence identity.
func TestStampedSubjectIsNotCountedUnlicensed(t *testing.T) {
	main := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	walk := makeWalk(t, []coordinate.ModuleCoordinate{main})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq()
	req.MainComponentVersion = "v9.9.9"
	req.MainComponentLicense = "Apache-2.0"

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if rec.LicensesIncomplete {
		t.Errorf("LicensesIncomplete = true; the subject carries the stamped licence in both places it is described")
	}
	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if _, present := bom["annotations"]; present {
		t.Errorf("document carries a licence-completeness annotation; nothing is undetermined")
	}
}

// TestStampedSubjectAppearsOnceInDependencies verifies the dependency graph
// names the subject once. Two entries for one module — the stamped bom-ref and
// the graph coordinate — each repeating the whole dependency set, is the same
// split identity reaching the part of the document a consumer resolves.
func TestStampedSubjectAppearsOnceInDependencies(t *testing.T) {
	main := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	dep := mustCoord(t, "example.com/dep", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{main, dep})
	walk.Graph.Edges = []walkdomain.GraphEdge{{From: main, To: dep}}
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq()
	req.MainComponentVersion = "v9.9.9"

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	deps, _ := bom["dependencies"].([]any)
	var refs []string
	var stampedDependsOn []any
	for _, d := range deps {
		dm, _ := d.(map[string]any)
		ref, _ := dm["ref"].(string)
		refs = append(refs, ref)
		if ref == "pkg:golang/example.com/project@v9.9.9" {
			stampedDependsOn, _ = dm["dependsOn"].([]any)
		}
	}
	seen := map[string]int{}
	for _, r := range refs {
		seen[r]++
	}
	if seen["pkg:golang/example.com/project@v9.9.9"] != 1 {
		t.Errorf("dependency entries for the stamped subject = %d, want 1 (refs: %v)", seen["pkg:golang/example.com/project@v9.9.9"], refs)
	}
	if seen["pkg:golang/example.com/project@local"] != 0 {
		t.Errorf("dependency array still names the subject at its graph coordinate (refs: %v)", refs)
	}
	if len(stampedDependsOn) != 1 || stampedDependsOn[0] != "pkg:golang/example.com/dep@v1.0.0" {
		t.Errorf("stamped subject dependsOn = %v, want the dependency edge to have followed the identity", stampedDependsOn)
	}
}

// licenseIDs returns the SPDX ids on a component.
func licenseIDs(comp map[string]any) []string {
	lics, _ := comp["licenses"].([]any)
	out := make([]string, 0, len(lics))
	for _, l := range lics {
		lm, _ := l.(map[string]any)
		if obj, ok := lm["license"].(map[string]any); ok {
			id, _ := obj["id"].(string)
			out = append(out, id)
		}
		if expr, ok := lm["expression"].(string); ok {
			out = append(out, expr)
		}
	}
	return out
}
