package cyclonedx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"

	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const testPipelineVersion = "0.3.0-test"

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func makeWalk(t *testing.T, nodes []coordinate.ModuleCoordinate) walkdomain.WalkRecord {
	t.Helper()
	target := nodes[0]
	graphNodes := make([]walkdomain.GraphNode, len(nodes))
	for i, c := range nodes {
		graphNodes[i] = walkdomain.GraphNode{
			Coordinate:       c,
			DirectDependency: i == 0,
			ResolutionSource: walkdomain.ResolutionTarget,
		}
	}
	return walkdomain.WalkRecord{
		ID: "walk-test-001",
		Graph: walkdomain.Graph{
			Target:     target,
			Nodes:      graphNodes,
			ResolvedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
}

func makeGenReq() ports.GenerateRequest {
	return ports.GenerateRequest{
		Format:          domain.CycloneDX16,
		PipelineVersion: testPipelineVersion,
		Operator:        "test",
	}
}

// TestGenerateOneModule verifies a walk with one module produces one component.
func TestGenerateOneModule(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	components, ok := bom["components"].([]any)
	if !ok {
		t.Fatal("expected components array")
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
}

// TestComponentsSortedByPURL verifies components are sorted lexicographically by purl.
func TestComponentsSortedByPURL(t *testing.T) {
	coords := []coordinate.ModuleCoordinate{
		mustCoord(t, "github.com/zzz/last", "v1.0.0"),
		mustCoord(t, "github.com/aaa/first", "v1.0.0"),
		mustCoord(t, "github.com/mmm/middle", "v1.0.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	components := bom["components"].([]any)
	purls := make([]string, len(components))
	for i, c := range components {
		purls[i] = c.(map[string]any)["purl"].(string)
	}
	for i := 1; i < len(purls); i++ {
		if purls[i] < purls[i-1] {
			t.Errorf("components not sorted: %q before %q", purls[i-1], purls[i])
		}
	}
}

// TestDeterminism verifies that two generations from the same inputs produce byte-identical SBOMs.
func TestDeterminism(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {PrimarySPDX: "MIT", ExtractedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)},
	}
	gen := cyclonedx.New(testPipelineVersion)
	req := makeGenReq()

	rec1, err := gen.Generate(context.Background(), walk, licenses, req)
	if err != nil {
		t.Fatalf("Generate 1: %v", err)
	}
	rec2, err := gen.Generate(context.Background(), walk, licenses, req)
	if err != nil {
		t.Fatalf("Generate 2: %v", err)
	}

	if !bytes.Equal(rec1.Content, rec2.Content) {
		t.Error("two generations from same inputs produced different content")
	}
	if rec1.ContentHash != rec2.ContentHash {
		t.Errorf("content hashes differ: %s vs %s", rec1.ContentHash, rec2.ContentHash)
	}
	if rec1.ID != rec2.ID {
		t.Errorf("IDs differ: %s vs %s", rec1.ID, rec2.ID)
	}
}

// A module with no licence record at all leaves the document with no licences
// block for it, which is incomplete licensing.
func TestMissingLicenseIncomplete(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	// No licenses provided.
	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !rec.LicensesIncomplete {
		t.Error("expected LicensesIncomplete=true when no licence data provided")
	}
}

// TestWithLicenseComplete verifies that a module with licence data does not set LicensesIncomplete.
func TestWithLicenseComplete(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {PrimarySPDX: "Apache-2.0"},
	}
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if rec.LicensesIncomplete {
		t.Error("expected LicensesIncomplete=false when all licence data provided")
	}
}

// TestValidCycloneDXStructure verifies the output has required CycloneDX 1.6 top-level fields.
func TestValidCycloneDXStructure(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	for _, field := range []string{"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"} {
		if _, ok := bom[field]; !ok {
			t.Errorf("missing required field %q in CycloneDX output", field)
		}
	}
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", bom["specVersion"])
	}
}

// TestEmptyWalkTimestampFallback verifies that an empty/failed-target walk
// (zero Graph.ResolvedAt, no licences) gets a non-zero GeneratedAt sourced
// from the walk's own clock-injected timestamps.
func TestEmptyWalkTimestampFallback(t *testing.T) {
	target := mustCoord(t, "github.com/example/failed", "v1.0.0")
	completed := time.Date(2026, 5, 17, 7, 6, 53, 0, time.UTC)
	walk := walkdomain.WalkRecord{
		ID:        "walk-failed-001",
		Target:    target,
		StartedAt: completed,
		// CompletedAt set, Graph.ResolvedAt zero, no nodes.
		CompletedAt: completed,
		Graph: walkdomain.Graph{
			Target: target,
			Nodes:  nil,
		},
	}
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if rec.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt is zero; expected fallback to walk.CompletedAt")
	}
	if !rec.GeneratedAt.Equal(completed) {
		t.Errorf("GeneratedAt = %s, want %s (walk.CompletedAt)", rec.GeneratedAt, completed)
	}
}

func TestGeneratorMetadata(t *testing.T) {
	g := cyclonedx.New(testPipelineVersion)
	meta := g.GeneratorMetadata()
	if meta.Name == "" {
		t.Error("GeneratorMetadata().Name is empty")
	}
	if meta.Version != testPipelineVersion {
		t.Errorf("GeneratorMetadata().Version = %q, want %q", meta.Version, testPipelineVersion)
	}
}

// TestCopyrightField verifies that a module with copyright statements has the
// copyright field populated in the CycloneDX output and that a module without
// copyright statements does not (omitempty).
func TestCopyrightField(t *testing.T) {
	withCopyright := mustCoord(t, "github.com/example/licensed", "v1.0.0")
	noCopyright := mustCoord(t, "github.com/example/nocopyright", "v2.0.0")

	walk := makeWalk(t, []coordinate.ModuleCoordinate{withCopyright, noCopyright})

	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		withCopyright: {
			PrimarySPDX:     "MIT",
			CopyrightStatus: licensedomain.CopyrightStatusFound,
			LicenseFiles: []licensedomain.LicenseFileEntry{
				{
					Path: "LICENSE",
					CopyrightStatements: []licensedomain.CopyrightStatement{
						{Verbatim: "Copyright 2020 Alice", Source: "LICENSE"},
						{Verbatim: "Copyright 2021 Bob", Source: "LICENSE"},
					},
				},
			},
		},
		noCopyright: {
			PrimarySPDX:     "Apache-2.0",
			CopyrightStatus: licensedomain.CopyrightStatusNoneFound,
		},
	}

	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	components := bom["components"].([]any)

	byPURL := make(map[string]map[string]any, len(components))
	for _, c := range components {
		comp := c.(map[string]any)
		byPURL[comp["purl"].(string)] = comp
	}

	withPURL := "pkg:golang/github.com/example/licensed@v1.0.0"
	noPURL := "pkg:golang/github.com/example/nocopyright@v2.0.0"

	withComp, ok := byPURL[withPURL]
	if !ok {
		t.Fatalf("component with copyright not found in SBOM")
	}
	gotCopyright, hasCopyright := withComp["copyright"]
	if !hasCopyright {
		t.Error("expected copyright field on component with statements")
	}
	wantCopyright := "Copyright 2020 Alice\nCopyright 2021 Bob"
	if gotCopyright != wantCopyright {
		t.Errorf("copyright = %q, want %q", gotCopyright, wantCopyright)
	}

	noComp, ok := byPURL[noPURL]
	if !ok {
		t.Fatalf("component without copyright not found in SBOM")
	}
	if _, hasCopyright := noComp["copyright"]; hasCopyright {
		t.Error("expected no copyright field on component with CopyrightStatusNoneFound")
	}
}

// TestCopyrightDeduplicates verifies that an identical copyright statement
// appearing in more than one licence file collapses to a single line.
func TestCopyrightDeduplicates(t *testing.T) {
	coord := mustCoord(t, "github.com/example/dup", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	dup := "Copyright 2023 Acme Inc."
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {
			PrimarySPDX:     "MIT",
			CopyrightStatus: licensedomain.CopyrightStatusFound,
			LicenseFiles: []licensedomain.LicenseFileEntry{
				{Path: "LICENSE", CopyrightStatements: []licensedomain.CopyrightStatement{{Verbatim: dup, Source: "LICENSE"}}},
				{Path: "COPYING", CopyrightStatements: []licensedomain.CopyrightStatement{{Verbatim: dup, Source: "COPYING"}}},
			},
		},
	}

	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	for _, c := range bom["components"].([]any) {
		comp := c.(map[string]any)
		if comp["purl"] == "pkg:golang/github.com/example/dup@v1.0.0" {
			if comp["copyright"] != dup {
				t.Errorf("copyright = %q, want the single deduplicated line %q", comp["copyright"], dup)
			}
			return
		}
	}
	t.Fatal("component not found in SBOM")
}

// TestCopyrightDeterminism verifies that copyright is stable across multiple generations.
func TestCopyrightDeterminism(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {
			PrimarySPDX:     "MIT",
			CopyrightStatus: licensedomain.CopyrightStatusFound,
			LicenseFiles: []licensedomain.LicenseFileEntry{
				{
					Path: "LICENSE",
					CopyrightStatements: []licensedomain.CopyrightStatement{
						{Verbatim: "Copyright 2022 Acme Inc.", Source: "LICENSE"},
					},
				},
			},
			ExtractedAt: mustTime("2026-01-01T12:00:00Z"),
		},
	}
	gen := cyclonedx.New(testPipelineVersion)
	req := makeGenReq()

	rec1, err := gen.Generate(t.Context(), walk, licenses, req)
	if err != nil {
		t.Fatalf("Generate 1: %v", err)
	}
	rec2, err := gen.Generate(t.Context(), walk, licenses, req)
	if err != nil {
		t.Fatalf("Generate 2: %v", err)
	}

	if rec1.ContentHash != rec2.ContentHash {
		t.Errorf("content hashes differ across generations: %s vs %s", rec1.ContentHash, rec2.ContentHash)
	}
}

// TestAllComponentsHaveGoPURL asserts that every component and the metadata
// primary component carry a purl starting with "pkg:golang/".
func TestAllComponentsHaveGoPURL(t *testing.T) {
	coords := []coordinate.ModuleCoordinate{
		mustCoord(t, "github.com/example/target", "v1.0.0"),
		mustCoord(t, "github.com/example/dep-a", "v0.5.0"),
		mustCoord(t, "github.com/example/dep-b", "v2.1.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	checkPURL := func(label string, purl any) {
		t.Helper()
		s, ok := purl.(string)
		if !ok || !strings.HasPrefix(s, "pkg:golang/") {
			t.Errorf("%s: purl %q does not start with pkg:golang/", label, purl)
		}
	}

	components, _ := bom["components"].([]any)
	for i, c := range components {
		comp := c.(map[string]any)
		checkPURL(fmt.Sprintf("components[%d]", i), comp["purl"])
	}

	meta, _ := bom["metadata"].(map[string]any)
	if primary, ok := meta["component"].(map[string]any); ok {
		checkPURL("metadata.component", primary["purl"])
	}
}

// TestComponentsHaveEcosystemProperty asserts that every component carries a
// "kanonarion:ecosystem" property with value "go".
func TestComponentsHaveEcosystemProperty(t *testing.T) {
	coords := []coordinate.ModuleCoordinate{
		mustCoord(t, "github.com/example/target", "v1.0.0"),
		mustCoord(t, "github.com/example/dep", "v0.1.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	checkEcosystem := func(label string, comp map[string]any) {
		t.Helper()
		props, ok := comp["properties"].([]any)
		if !ok {
			t.Errorf("%s: missing properties", label)
			return
		}
		for _, p := range props {
			prop := p.(map[string]any)
			if prop["name"] == "kanonarion:ecosystem" {
				if prop["value"] != "go" {
					t.Errorf("%s: kanonarion:ecosystem = %q, want go", label, prop["value"])
				}
				return
			}
		}
		t.Errorf("%s: no kanonarion:ecosystem property found", label)
	}

	components, _ := bom["components"].([]any)
	for i, c := range components {
		checkEcosystem(fmt.Sprintf("components[%d]", i), c.(map[string]any))
	}

	meta, _ := bom["metadata"].(map[string]any)
	if primary, ok := meta["component"].(map[string]any); ok {
		checkEcosystem("metadata.component", primary)
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// TestProjectWalkSubjectIsLocalModule verifies that for a project walk — whose
// Target is the local main module at version "local" — the SBOM metadata
// primary component is that local module, and the require closure appears in
// components. The local module's "local" purl satisfies the Go-only invariant.
func TestProjectWalkSubjectIsLocalModule(t *testing.T) {
	mainModule := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	coords := []coordinate.ModuleCoordinate{
		mainModule,
		mustCoord(t, "github.com/example/dep-a", "v0.5.0"),
		mustCoord(t, "github.com/example/dep-b", "v2.1.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}

	// metadata.component is the local main module.
	meta, _ := bom["metadata"].(map[string]any)
	primary, ok := meta["component"].(map[string]any)
	if !ok {
		t.Fatalf("metadata.component absent")
	}
	wantPURL := "pkg:golang/example.com/project@local"
	if primary["purl"] != wantPURL {
		t.Errorf("metadata.component purl = %v, want %q", primary["purl"], wantPURL)
	}
	if primary["name"] != "example.com/project" {
		t.Errorf("metadata.component name = %v, want example.com/project", primary["name"])
	}
	// The local main module is a compiled binary, not a dependency library.
	if primary["type"] != "application" {
		t.Errorf("metadata.component type = %v, want application", primary["type"])
	}

	// components carry the full require closure.
	components, _ := bom["components"].([]any)
	gotPURLs := map[string]bool{}
	for _, c := range components {
		gotPURLs[c.(map[string]any)["purl"].(string)] = true
	}
	for _, want := range []string{
		"pkg:golang/github.com/example/dep-a@v0.5.0",
		"pkg:golang/github.com/example/dep-b@v2.1.0",
	} {
		if !gotPURLs[want] {
			t.Errorf("components missing %q", want)
		}
	}
}

// TestMainComponentOverrides verifies that MainComponentVersion and
// MainComponentLicense stamp a resolvable version (version, PURL, distribution
// URL) and a licence onto the local main-module subject, which otherwise ships
// at the synthetic "local" version with no licence record.
func TestMainComponentOverrides(t *testing.T) {
	mainModule := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	walk := makeWalk(t, []coordinate.ModuleCoordinate{mainModule})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq()
	req.MainComponentVersion = "v1.2.3"
	req.MainComponentLicense = "Apache-2.0"

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	meta, _ := bom["metadata"].(map[string]any)
	primary, ok := meta["component"].(map[string]any)
	if !ok {
		t.Fatalf("metadata.component absent")
	}

	if primary["version"] != "v1.2.3" {
		t.Errorf("version = %v, want v1.2.3", primary["version"])
	}
	if primary["purl"] != "pkg:golang/example.com/project@v1.2.3" {
		t.Errorf("purl = %v, want pkg:golang/example.com/project@v1.2.3", primary["purl"])
	}
	if primary["type"] != "application" {
		t.Errorf("type = %v, want application", primary["type"])
	}
	// distribution externalReference must name the overridden version, not "local".
	refs, _ := primary["externalReferences"].([]any)
	var distURL string
	for _, r := range refs {
		rm, _ := r.(map[string]any)
		if rm["type"] == "distribution" {
			distURL, _ = rm["url"].(string)
		}
	}
	if distURL != "https://proxy.golang.org/example.com/project/@v/v1.2.3.zip" {
		t.Errorf("distribution url = %q, want .../@v/v1.2.3.zip", distURL)
	}
	// licence attached from the override.
	lics, _ := primary["licenses"].([]any)
	if len(lics) == 0 {
		t.Fatalf("licenses absent; want Apache-2.0")
	}
	lic0, _ := lics[0].(map[string]any)
	licObj, _ := lic0["license"].(map[string]any)
	if licObj["id"] != "Apache-2.0" {
		t.Errorf("license id = %v, want Apache-2.0", licObj["id"])
	}
}

// TestMainComponentOverridesIgnoredForPublishedTarget verifies the overrides
// apply only to the local main module: a walk rooted at a published module keeps
// its real version and library type, untouched by the override fields.
func TestMainComponentOverridesIgnoredForPublishedTarget(t *testing.T) {
	target := mustCoord(t, "example.com/lib", "v3.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{target})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq()
	req.MainComponentVersion = "v9.9.9"
	req.MainComponentLicense = "MIT"

	rec, err := gen.Generate(t.Context(), walk, nil, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	meta, _ := bom["metadata"].(map[string]any)
	primary, _ := meta["component"].(map[string]any)
	if primary["version"] != "v3.0.0" {
		t.Errorf("version = %v, want v3.0.0 (override must not apply)", primary["version"])
	}
	if primary["type"] != "library" {
		t.Errorf("type = %v, want library (override must not apply)", primary["type"])
	}
}

// The document carries no vulnerability list under any request. It is an
// inventory of components and their identity, hashes and licences; an advisory
// list frozen into a distributed artefact ages against a store whose answer
// keeps improving, and kanonarion supplies evidence for an assertion rather than
// authoring one.
func TestGenerate_NeverEmitsAVulnerabilityList(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, nil, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if _, has := bom["vulnerabilities"]; has {
		t.Error("the document carries a vulnerabilities array")
	}
	if strings.Contains(string(rec.Content), "kanonarion:vulnerability-scope") {
		t.Error("the vulnerability-scope annotation survives with no list to scope")
	}
}

// A licence record that identified no SPDX licence produces a component with no
// licences block. The document must report that as incomplete licensing: a
// consumer sees an absent licence either way, and the extraction having run is
// not an answer to what the component is licensed under.
func TestGenerate_RecordWithNoSPDXIsIncompleteAndNamed(t *testing.T) {
	// The target is licensed, so the subject is not what this measures: the
	// undetermined component is a dependency whose extraction ran and identified
	// nothing.
	target := mustCoord(t, "github.com/example/app", "v1.0.0")
	coord := mustCoord(t, "github.com/example/unclassified", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{target, coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		target: {PrimarySPDX: "Apache-2.0", ExtractedAt: mustTime("2026-01-02T03:04:05Z")},
		coord:  {OverallStatus: licensedomain.LicenseStatusUnclassified, ExtractedAt: mustTime("2026-01-02T03:04:05Z")},
	}
	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !rec.LicensesIncomplete {
		t.Error("LicensesIncomplete = false for a component the document gives no licence")
	}
	text := string(rec.Content)
	if !strings.Contains(text, "kanonarion:licence-completeness") {
		t.Fatalf("no licence-completeness annotation in:\n%s", text)
	}
	if !strings.Contains(text, "pkg:golang/github.com/example/unclassified@v1.0.0") {
		t.Error("the licence-completeness statement does not name the component")
	}
	if strings.Contains(text, "1 of the 2 component(s)") == false {
		t.Errorf("the statement does not count one undetermined of two components:\n%s", text)
	}
}

// metadata.timestamp is when the document was created. A caller who supplies
// that moment gets it verbatim; a caller who supplies none gets the derived
// value labelled as derived, never passed off as a creation time.
func TestGenerate_DocumentTimestampIsTheCallersCreationTime(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {PrimarySPDX: "MIT", ExtractedAt: mustTime("2026-07-29T04:44:15Z")},
	}

	created := mustTime("2026-08-01T12:00:00Z")
	req := makeGenReq()
	req.DocumentTimestamp = created
	rec, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, licenses, req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom struct {
		Metadata struct {
			Timestamp  string `json:"timestamp"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	if bom.Metadata.Timestamp != "2026-08-01T12:00:00Z" {
		t.Errorf("metadata.timestamp = %q, want the supplied creation time", bom.Metadata.Timestamp)
	}
	if !rec.GeneratedAt.Equal(created) {
		t.Errorf("record GeneratedAt = %s, want %s", rec.GeneratedAt, created)
	}
	props := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if !strings.Contains(props["kanonarion:document:timestamp_basis"], "caller-supplied") {
		t.Errorf("timestamp basis = %q, want it to state the caller supplied it", props["kanonarion:document:timestamp_basis"])
	}
	// The licence extraction time is stated separately, whichever basis applies,
	// so a reader never has to guess whether the timestamp is it.
	if props["kanonarion:licence:newest_extraction"] != "2026-07-29T04:44:15Z" {
		t.Errorf("newest licence extraction = %q, want 2026-07-29T04:44:15Z", props["kanonarion:licence:newest_extraction"])
	}

	// No supplied time: the derived value, said to be derived.
	fallback, err := cyclonedx.New(testPipelineVersion).Generate(t.Context(), walk, licenses, makeGenReq())
	if err != nil {
		t.Fatalf("Generate (no supplied time): %v", err)
	}
	if err := json.Unmarshal(fallback.Content, &bom); err != nil {
		t.Fatalf("unmarshal fallback bom: %v", err)
	}
	if bom.Metadata.Timestamp != "2026-07-29T04:44:15Z" {
		t.Errorf("fallback metadata.timestamp = %q, want the derived value", bom.Metadata.Timestamp)
	}
	for _, p := range bom.Metadata.Properties {
		if p.Name == "kanonarion:document:timestamp_basis" && !strings.Contains(p.Value, "derived") {
			t.Errorf("fallback timestamp basis = %q, want it to say the value is derived", p.Value)
		}
	}
}

// Two generations with the same supplied timestamp are byte-identical; two with
// different supplied timestamps differ, and the document that says when it was
// created is the only thing that moved.
func TestGenerate_SuppliedTimestampKeepsDeterminism(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []coordinate.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)
	at := func(ts string) []byte {
		req := makeGenReq()
		req.DocumentTimestamp = mustTime(ts)
		rec, err := gen.Generate(t.Context(), walk, nil, req)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return rec.Content
	}
	first, second := at("2026-08-01T12:00:00Z"), at("2026-08-01T12:00:00Z")
	if !bytes.Equal(first, second) {
		t.Error("two generations with the same supplied timestamp differ")
	}
	if bytes.Equal(first, at("2026-08-02T12:00:00Z")) {
		t.Error("two generations with different supplied timestamps are identical")
	}
}
