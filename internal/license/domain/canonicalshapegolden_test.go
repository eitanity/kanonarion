package domain_test

import (
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/canonicalshape"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// TestCanonicalShape_IsPinned fails when the bytes this domain seals over
// change. It complements TestCanonicalShape_KeySetIsPinned: that one names the
// keys, this one catches everything a key set cannot — a field reordered, a type
// whose rendering differs, a tag renamed.
//
// This is the domain the guard exists because of.
func TestCanonicalShape_IsPinned(t *testing.T) {
	t.Parallel()

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	rec := domain.LicenseRecord{
		SchemaVersion:     domain.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 0.99,
		LicenseFiles: []domain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99, FileHash: "sha256:abc", FileSize: 1000},
			{Path: "vendor/x/COPYING", IsVendored: true, LowConfidenceSPDX: "GPL-3.0-only", LowConfidenceCoverage: 0.4},
		},
		OverallStatus:   domain.LicenseStatusDetected,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "1.1.0",
	}

	var h domain.LicenseRecordHasher
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	got, err := h.Marshal(sealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	canonicalshape.AssertGolden(t, "testdata/canonical_shape.json", got)
}
