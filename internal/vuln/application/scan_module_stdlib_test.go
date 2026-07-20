package application_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestScanModule_Stdlib_MetadataAffected verifies that the standard-library node
// — which has no fetched artefact — resolves its advisories from OSV metadata by
// coordinate and reports Affected when the toolchain version is vulnerable.
func TestScanModule_Stdlib_MetadataAffected(t *testing.T) {
	ctx := t.Context()
	std := coordinate.ModuleCoordinate{Path: domain.StdlibModulePath, Version: "v1.26.4"}
	now := time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts() // no fetch record for stdlib — it is never fetched
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{} // must never be invoked for the stdlib node
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Version: "v1"},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			std: {
				{ID: "GO-2026-4970", FixedIn: "v1.26.5", Summary: "Root escape via symlink in os"},
				{ID: "GO-2026-5856", FixedIn: "v1.26.5", Summary: "ECH privacy leak in crypto/tls"},
			},
		},
	}
	clock := fixedClock{t: now}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: std, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusAffected {
		t.Fatalf("stdlib status = %s, want Affected", res.OverallStatus)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	if scanner.scanCalls != 0 {
		t.Errorf("scanner invoked %d times for stdlib; it must never build the standard library", scanner.scanCalls)
	}
	if res.UnscannableReason == "" {
		t.Errorf("expected a metadata-only note explaining the stdlib is toolchain-provided")
	}
}

// TestScanModule_Stdlib_MetadataClean verifies a stdlib node on a patched
// toolchain (no matching advisory) reports Clean, not Unscannable.
func TestScanModule_Stdlib_MetadataClean(t *testing.T) {
	ctx := t.Context()
	std := coordinate.ModuleCoordinate{Path: domain.StdlibModulePath, Version: "v1.26.5"}
	now := time.Date(2026, 7, 9, 0, 0, 0, 0, time.UTC)

	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), newFakeVulnStore(), nil, &fakeScanner{},
		&fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}, nil,
		fixedClock{t: now}, "v1", "v1", slog.Default(),
	)
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: std, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusClean {
		t.Errorf("stdlib status = %s, want Clean", res.OverallStatus)
	}
}
