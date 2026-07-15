package cyclonedx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const testPipelineVersion = "0.3.0-test"

func mustCoord(t *testing.T, path, version string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func makeWalk(t *testing.T, nodes []fetchdomain.ModuleCoordinate) walkdomain.WalkRecord {
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

func makeGenReq(scanRunID *string) ports.GenerateRequest {
	return ports.GenerateRequest{
		WalkScanRunID:   scanRunID,
		Format:          domain.CycloneDX16,
		PipelineVersion: testPipelineVersion,
		Operator:        "test",
	}
}

// TestGenerateOneModule verifies a walk with one module produces one component.
func TestGenerateOneModule(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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
	coords := []fetchdomain.ModuleCoordinate{
		mustCoord(t, "github.com/zzz/last", "v1.0.0"),
		mustCoord(t, "github.com/aaa/first", "v1.0.0"),
		mustCoord(t, "github.com/mmm/middle", "v1.0.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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

// TestVulnerabilitiesSortedByID verifies vulnerabilities are sorted by ID.
func TestVulnerabilitiesSortedByID(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})

	vulnRecords := []vulndomain.VulnerabilityRecord{
		{
			Coordinate: coord,
			Findings: []vulndomain.VulnerabilityFinding{
				{ID: "GHSA-zzz-zzz-zzz", Summary: "last"},
				{ID: "GHSA-aaa-aaa-aaa", Summary: "first"},
				{ID: "GHSA-mmm-mmm-mmm", Summary: "middle"},
			},
		},
	}

	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, nil, vulnRecords, makeGenReq(nil))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	vulns, ok := bom["vulnerabilities"].([]any)
	if !ok {
		t.Fatal("expected vulnerabilities array")
	}
	ids := make([]string, len(vulns))
	for i, v := range vulns {
		ids[i] = v.(map[string]any)["id"].(string)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Errorf("vulnerabilities not sorted: %q before %q", ids[i-1], ids[i])
		}
	}
}

// TestDeterminism verifies that two generations from the same inputs produce byte-identical SBOMs.
func TestDeterminism(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	licenses := map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {PrimarySPDX: "MIT", ExtractedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)},
	}
	gen := cyclonedx.New(testPipelineVersion)
	req := makeGenReq(nil)

	rec1, err := gen.Generate(context.Background(), walk, licenses, nil, req)
	if err != nil {
		t.Fatalf("Generate 1: %v", err)
	}
	rec2, err := gen.Generate(context.Background(), walk, licenses, nil, req)
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

// TestMissingLicenseIncomplete verifies that a module without licence data sets LicensesIncomplete.
func TestMissingLicenseIncomplete(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	// No licenses provided.
	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	licenses := map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord{
		coord: {PrimarySPDX: "Apache-2.0"},
	}
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, licenses, nil, makeGenReq(nil))
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
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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

// TestWithAndWithoutVulnsOnlyDifferInVulnerabilities verifies that two SBOMs for the same walk
// differ only in the vulnerabilities array.
func TestWithAndWithoutVulnsOnlyDifferInVulnerabilities(t *testing.T) {
	coord := mustCoord(t, "github.com/example/foo", "v1.0.0")
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	gen := cyclonedx.New(testPipelineVersion)

	recNoVulns, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
	if err != nil {
		t.Fatalf("Generate (no vulns): %v", err)
	}

	scanRunID := "scan-001"
	vulnRecords := []vulndomain.VulnerabilityRecord{
		{Coordinate: coord, Findings: []vulndomain.VulnerabilityFinding{{ID: "GHSA-aaa-aaa-aaa", Summary: "test"}}},
	}
	recWithVulns, err := gen.Generate(t.Context(), walk, nil, vulnRecords, makeGenReq(&scanRunID))
	if err != nil {
		t.Fatalf("Generate (with vulns): %v", err)
	}

	var bomNoVulns, bomWithVulns map[string]any
	if err := json.Unmarshal(recNoVulns.Content, &bomNoVulns); err != nil {
		t.Fatalf("unmarshal no-vulns bom: %v", err)
	}
	if err := json.Unmarshal(recWithVulns.Content, &bomWithVulns); err != nil {
		t.Fatalf("unmarshal with-vulns bom: %v", err)
	}

	if _, hasVulns := bomNoVulns["vulnerabilities"]; hasVulns {
		t.Error("expected no vulnerabilities field in SBOM without scan run")
	}
	if _, hasVulns := bomWithVulns["vulnerabilities"]; !hasVulns {
		t.Error("expected vulnerabilities field in SBOM with scan run")
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

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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

func TestMapSeverity_ViaGenerate(t *testing.T) {
	coord := mustCoord(t, "github.com/example/severity", "v1.0.0")
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})

	sev := func(label string) *vulndomain.Severity { return &vulndomain.Severity{Label: label, Score: 9.0} }

	vulnRecords := []vulndomain.VulnerabilityRecord{
		{
			Coordinate: coord,
			Findings: []vulndomain.VulnerabilityFinding{
				{ID: "GHSA-crit", Summary: "critical", Severity: sev("CRITICAL")},
				{ID: "GHSA-high", Summary: "high", Severity: sev("HIGH")},
				{ID: "GHSA-med", Summary: "medium", Severity: sev("MEDIUM")},
				{ID: "GHSA-low", Summary: "low", Severity: sev("LOW")},
				{ID: "GHSA-unk", Summary: "unknown label", Severity: sev("NONE")},
				{ID: "GHSA-nil", Summary: "nil severity"},
			},
		},
	}

	gen := cyclonedx.New(testPipelineVersion)
	rec, err := gen.Generate(t.Context(), walk, nil, vulnRecords, makeGenReq(nil))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var bom map[string]any
	if err := json.Unmarshal(rec.Content, &bom); err != nil {
		t.Fatalf("unmarshal bom: %v", err)
	}
	vulns, ok := bom["vulnerabilities"].([]any)
	if !ok || len(vulns) == 0 {
		t.Fatal("expected non-empty vulnerabilities array")
	}
}

// TestCopyrightField verifies that a module with copyright statements has the
// copyright field populated in the CycloneDX output and that a module without
// copyright statements does not (omitempty).
func TestCopyrightField(t *testing.T) {
	withCopyright := mustCoord(t, "github.com/example/licensed", "v1.0.0")
	noCopyright := mustCoord(t, "github.com/example/nocopyright", "v2.0.0")

	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{withCopyright, noCopyright})

	licenses := map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord{
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
	rec, err := gen.Generate(t.Context(), walk, licenses, nil, makeGenReq(nil))
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
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	dup := "Copyright 2023 Acme Inc."
	licenses := map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord{
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
	rec, err := gen.Generate(t.Context(), walk, licenses, nil, makeGenReq(nil))
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
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{coord})
	licenses := map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord{
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
	req := makeGenReq(nil)

	rec1, err := gen.Generate(t.Context(), walk, licenses, nil, req)
	if err != nil {
		t.Fatalf("Generate 1: %v", err)
	}
	rec2, err := gen.Generate(t.Context(), walk, licenses, nil, req)
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
	coords := []fetchdomain.ModuleCoordinate{
		mustCoord(t, "github.com/example/target", "v1.0.0"),
		mustCoord(t, "github.com/example/dep-a", "v0.5.0"),
		mustCoord(t, "github.com/example/dep-b", "v2.1.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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
	coords := []fetchdomain.ModuleCoordinate{
		mustCoord(t, "github.com/example/target", "v1.0.0"),
		mustCoord(t, "github.com/example/dep", "v0.1.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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
	mainModule := mustCoord(t, "example.com/project", fetchdomain.LocalVersion)
	coords := []fetchdomain.ModuleCoordinate{
		mainModule,
		mustCoord(t, "github.com/example/dep-a", "v0.5.0"),
		mustCoord(t, "github.com/example/dep-b", "v2.1.0"),
	}
	walk := makeWalk(t, coords)
	gen := cyclonedx.New(testPipelineVersion)

	rec, err := gen.Generate(t.Context(), walk, nil, nil, makeGenReq(nil))
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
	mainModule := mustCoord(t, "example.com/project", fetchdomain.LocalVersion)
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{mainModule})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq(nil)
	req.MainComponentVersion = "v1.2.3"
	req.MainComponentLicense = "Apache-2.0"

	rec, err := gen.Generate(t.Context(), walk, nil, nil, req)
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
	walk := makeWalk(t, []fetchdomain.ModuleCoordinate{target})
	gen := cyclonedx.New(testPipelineVersion)

	req := makeGenReq(nil)
	req.MainComponentVersion = "v9.9.9"
	req.MainComponentLicense = "MIT"

	rec, err := gen.Generate(t.Context(), walk, nil, nil, req)
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
