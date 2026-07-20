package cyclonedx_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sbom/adapters/generator/cyclonedx"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestGoldenByteLock locks generator output byte-for-byte. The fixture was
// produced by the pre- generator; this test guarantees the policy
// extraction into sbom/domain did not alter a single byte and guards against
// future drift. Scenario exercises: multi-module ordering, mixed license
// states (licensed / empty-SPDX / absent), licensesIncomplete, and a
// vulnerability finding shared across two modules (cross-module dedup with
// first-occurrence summary/severity).
func TestGoldenByteLock(t *testing.T) {
	mc := func(p, v string) coordinate.ModuleCoordinate {
		c, err := coordinate.NewModuleCoordinate(p, v)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	target := mc("github.com/example/app", "v1.2.0")
	depA := mc("github.com/example/aaa", "v0.4.0")
	depB := mc("github.com/example/zzz", "v2.0.0")
	dig := func(seed string) fetchdomain.ArtifactDigests {
		return fetchdomain.ArtifactDigests{
			SHA256: seed + "256",
			SHA384: seed + "384",
			SHA512: seed + "512",
		}
	}
	gn := []walkdomain.GraphNode{
		// Target carries no digests (a subject/root component emits no <hashes>);
		// the two deps carry digests so the fixture locks the <hashes> block.
		{Coordinate: target, DirectDependency: true, ResolutionSource: walkdomain.ResolutionTarget},
		{Coordinate: depB, ResolutionSource: walkdomain.ResolutionMVS, Digests: dig("zzz")},
		{Coordinate: depA, ResolutionSource: walkdomain.ResolutionMVS, Digests: dig("aaa")},
	}
	walk := walkdomain.WalkRecord{
		ID: "walk-golden-001",
		Graph: walkdomain.Graph{
			Target: target,
			Nodes:  gn,
			// Directed edges: target → both deps, and aaa → zzz. Locks the
			// dependencies array (root entry, per-component entries, dependsOn).
			Edges: []walkdomain.GraphEdge{
				{From: target, To: depA},
				{From: target, To: depB},
				{From: depA, To: depB},
			},
			ResolvedAt: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
		},
	}
	licenses := map[coordinate.ModuleCoordinate]licensedomain.LicenseRecord{
		target: {PrimarySPDX: "Apache-2.0", ExtractedAt: time.Date(2026, 3, 2, 12, 30, 0, 0, time.UTC)},
		depA:   {PrimarySPDX: "", ExtractedAt: time.Date(2026, 3, 2, 11, 0, 0, 0, time.UTC)},
		// depB intentionally absent -> licensesIncomplete
	}
	sev := func(l string) *vulndomain.Severity { return &vulndomain.Severity{Label: l, Score: 7.5} }
	scan := "scan-golden-007"
	vulns := []vulndomain.VulnerabilityRecord{
		{Coordinate: depB, Findings: []vulndomain.VulnerabilityFinding{
			{ID: "GHSA-shared", Summary: "shared across modules", Severity: sev("HIGH")},
			{ID: "GHSA-zonly", Summary: "z only", Severity: sev("LOW")},
		}},
		{Coordinate: depA, Findings: []vulndomain.VulnerabilityFinding{
			{ID: "GHSA-shared", Summary: "second occurrence ignored", Severity: sev("CRITICAL")},
			{ID: "GHSA-aonly", Summary: "a only", Severity: nil},
		}},
	}
	gen := cyclonedx.New("0.3.0-test")
	rec, err := gen.Generate(t.Context(), walk, licenses, vulns, ports.GenerateRequest{
		WalkScanRunID: &scan, Format: domain.CycloneDX16, PipelineVersion: "0.3.0-test", Operator: "golden",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if werr := os.WriteFile("testdata/golden_sbom.json", rec.Content, 0o600); werr != nil {
			t.Fatalf("writing golden: %v", werr)
		}
		t.Log("golden file updated")
	}

	want, err := os.ReadFile("testdata/golden_sbom.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(rec.Content, want) {
		t.Errorf("generator output drifted from golden fixture (len got=%d want=%d).\n"+
			"If this change is intentional, regenerate testdata/golden_sbom.json.",
			len(rec.Content), len(want))
	}
	if !rec.LicensesIncomplete {
		t.Error("LicensesIncomplete = false, want true (depB had no license data)")
	}
}
