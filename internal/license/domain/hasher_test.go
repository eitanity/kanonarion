package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
)

func TestRoundTrip(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.2.3")
	now := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)

	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 0.98,
		LicenseFiles: []domain2.LicenseFileEntry{
			{
				Path:       "LICENSE",
				SPDX:       "MIT",
				Confidence: 0.98,
				FileHash:   "sha256:abc123",
				FileSize:   1073,
				IsVendored: false,
			},
			{
				Path:       "vendor/dep/COPYING",
				SPDX:       "Apache-2.0",
				Confidence: 0.95,
				FileHash:   "sha256:def456",
				FileSize:   2384,
				IsVendored: true,
				AltMatches: []domain2.AltMatch{
					{SPDX: "Apache-1.1", Confidence: 0.30},
				},
			},
		},
		OverallStatus:   domain2.LicenseStatusDetected,
		ExtractedAt:     now,
		PipelineVersion: "0.1.0",
	}
	r.SortFiles()

	var h domain2.LicenseRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if r.ContentHash == "" {
		t.Fatal("ContentHash is empty after SetContentHash")
	}

	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if err := h.VerifyContentHash(got); err != nil {
		t.Fatalf("VerifyContentHash after round-trip: %v", err)
	}

	if got.PrimarySPDX != r.PrimarySPDX {
		t.Errorf("PrimarySPDX: got %q, want %q", got.PrimarySPDX, r.PrimarySPDX)
	}
	if got.OverallStatus != r.OverallStatus {
		t.Errorf("OverallStatus: got %v, want %v", got.OverallStatus, r.OverallStatus)
	}
	if len(got.LicenseFiles) != len(r.LicenseFiles) {
		t.Fatalf("LicenseFiles length: got %d, want %d", len(got.LicenseFiles), len(r.LicenseFiles))
	}
}

// TestRoundTrip_LowConfidenceFieldsHashedAndPreserved verifies the per-file
// low-confidence fragment survives marshal/unmarshal and participates in the
// content hash (mutating it changes the digest), so the surfaced caveat is
// integrity-protected like every other extracted fact.
func TestRoundTrip_LowConfidenceFieldsHashedAndPreserved(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	now := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)

	base := domain2.LicenseRecord{
		SchemaVersion: domain2.LicenseSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		LicenseFiles: []domain2.LicenseFileEntry{
			{
				Path:                  "LICENSE",
				FileHash:              "sha256:abc",
				FileSize:              26863,
				LowConfidenceSPDX:     "AGPL-3.0-or-later",
				LowConfidenceCoverage: 0.0279,
			},
		},
		OverallStatus:   domain2.LicenseStatusUnclassified,
		ExtractedAt:     now,
		PipelineVersion: "1.1.0",
	}
	base.SortFiles()

	var h domain2.LicenseRecordHasher
	hashed, err := h.SetContentHash(base)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := h.VerifyContentHash(got); err != nil {
		t.Fatalf("VerifyContentHash after round-trip: %v", err)
	}
	if got.LicenseFiles[0].LowConfidenceSPDX != "AGPL-3.0-or-later" {
		t.Errorf("LowConfidenceSPDX not preserved: got %q", got.LicenseFiles[0].LowConfidenceSPDX)
	}
	if got.LicenseFiles[0].LowConfidenceCoverage != 0.0279 {
		t.Errorf("LowConfidenceCoverage not preserved: got %f", got.LicenseFiles[0].LowConfidenceCoverage)
	}

	// A different fragment must yield a different content hash.
	mutated := base
	mutated.LicenseFiles = []domain2.LicenseFileEntry{{
		Path:                  "LICENSE",
		FileHash:              "sha256:abc",
		FileSize:              26863,
		LowConfidenceSPDX:     "GPL-3.0-or-later",
		LowConfidenceCoverage: 0.0279,
	}}
	mutatedHashed, err := h.SetContentHash(mutated)
	if err != nil {
		t.Fatalf("SetContentHash (mutated): %v", err)
	}
	if mutatedHashed.ContentHash == hashed.ContentHash {
		t.Error("content hash unchanged after mutating the low-confidence fragment; field is not hashed")
	}
}

func TestRoundTripIdempotent(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v2.0.0")
	now := time.Date(2025, 3, 1, 8, 0, 0, 0, time.UTC)

	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       "Apache-2.0",
		PrimaryConfidence: 0.99,
		LicenseFiles: []domain2.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "Apache-2.0", Confidence: 0.99, FileHash: "sha256:aaa", FileSize: 11357},
		},
		OverallStatus:   domain2.LicenseStatusDetected,
		ExtractedAt:     now,
		PipelineVersion: "0.1.0",
	}

	var h domain2.LicenseRecordHasher
	r1, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("first SetContentHash: %v", err)
	}
	r2, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("second SetContentHash: %v", err)
	}
	if r1.ContentHash != r2.ContentHash {
		t.Errorf("SetContentHash not idempotent: %q vs %q", r1.ContentHash, r2.ContentHash)
	}
}

func TestVerifyContentHashDetectsTampering(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 0.9,
		LicenseFiles:      []domain2.LicenseFileEntry{{Path: "LICENSE", SPDX: "MIT", Confidence: 0.9, FileHash: "sha256:x"}},
		OverallStatus:     domain2.LicenseStatusDetected,
		ExtractedAt:       time.Now().UTC(),
		PipelineVersion:   "0.1.0",
	}

	var h domain2.LicenseRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	r.PrimarySPDX = "GPL-3.0-or-later"
	if err := h.VerifyContentHash(r); err == nil {
		t.Error("VerifyContentHash should have failed after tampering")
	} else if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeterminism(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	buildRecord := func() domain2.LicenseRecord {
		r := domain2.LicenseRecord{
			SchemaVersion:     domain2.LicenseSchemaVersion,
			Ecosystem:         fetchdomain.EcosystemGo,
			Coordinate:        coord,
			PrimarySPDX:       "MIT",
			PrimaryConfidence: 0.97,
			LicenseFiles: []domain2.LicenseFileEntry{
				{Path: "LICENSE", SPDX: "MIT", Confidence: 0.97, FileHash: "sha256:abc"},
				{Path: "vendor/x/LICENSE", SPDX: "BSD-3-Clause", Confidence: 0.9, IsVendored: true, FileHash: "sha256:def"},
			},
			OverallStatus:   domain2.LicenseStatusDetected,
			ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			PipelineVersion: "0.1.0",
		}
		r.SortFiles()
		return r
	}

	var h domain2.LicenseRecordHasher
	r1, err := h.SetContentHash(buildRecord())
	if err != nil {
		t.Fatalf("first hash: %v", err)
	}
	r2, err := h.SetContentHash(buildRecord())
	if err != nil {
		t.Fatalf("second hash: %v", err)
	}
	if r1.ContentHash != r2.ContentHash {
		t.Errorf("hash not deterministic: %q vs %q", r1.ContentHash, r2.ContentHash)
	}
}

func TestUnorderedFilesHashIdentically(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	files := []domain2.LicenseFileEntry{
		{Path: "z_file", SPDX: "MIT", Confidence: 0.9, FileHash: "sha256:z"},
		{Path: "a_file", SPDX: "Apache-2.0", Confidence: 0.95, FileHash: "sha256:a"},
	}
	reversed := []domain2.LicenseFileEntry{files[1], files[0]}

	make := func(fs []domain2.LicenseFileEntry) domain2.LicenseRecord {
		return domain2.LicenseRecord{
			SchemaVersion:   domain2.LicenseSchemaVersion,
			Ecosystem:       fetchdomain.EcosystemGo,
			Coordinate:      coord,
			LicenseFiles:    fs,
			ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			PipelineVersion: "0.1.0",
		}
	}

	var h domain2.LicenseRecordHasher
	r1, err := h.SetContentHash(make(files))
	if err != nil {
		t.Fatalf("hash 1: %v", err)
	}
	r2, err := h.SetContentHash(make(reversed))
	if err != nil {
		t.Fatalf("hash 2: %v", err)
	}
	if r1.ContentHash != r2.ContentHash {
		t.Error("records with same files in different order should hash identically")
	}
}

func TestHasher_EcosystemPresentAfterRoundTrip(t *testing.T) {
	r := domain2.LicenseRecord{
		SchemaVersion:   domain2.LicenseSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      mustCoord(t, "example.com/mod", "v1.0.0"),
		PrimarySPDX:     "MIT",
		OverallStatus:   domain2.LicenseStatusDetected,
		PipelineVersion: "0.1.0",
	}
	var h domain2.LicenseRecordHasher
	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"ecosystem":"go"`) {
		t.Errorf("canonical JSON missing ecosystem field: %s", blob)
	}
	got, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Ecosystem != fetchdomain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, fetchdomain.EcosystemGo)
	}
}

func TestHasher_RejectsForeignEcosystem(t *testing.T) {
	r := domain2.LicenseRecord{
		SchemaVersion:   domain2.LicenseSchemaVersion,
		Ecosystem:       "npm",
		Coordinate:      mustCoord(t, "example.com/mod", "v1.0.0"),
		PrimarySPDX:     "MIT",
		OverallStatus:   domain2.LicenseStatusDetected,
		PipelineVersion: "0.1.0",
	}
	var h domain2.LicenseRecordHasher
	hashed, _ := h.SetContentHash(r)
	blob, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := h.Unmarshal(blob); !errors.Is(err, fetchdomain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}

// Role joined the canonical serialisation after records already existed in
// stores. It must be omitted when empty, so every pre-existing dependency
// record keeps its stored content hash verifiable.
func TestHasher_EmptyRoleKeepsLegacyHashStable(t *testing.T) {
	rec := domain2.LicenseRecord{
		SchemaVersion: domain2.LicenseSchemaVersion,
		Ecosystem:     "go",
		Coordinate:    mustCoord(t, "example.com/dep", "v1.0.0"),
		PrimarySPDX:   "MIT",
		OverallStatus: domain2.LicenseStatusDetected,
		ExtractedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	var h domain2.LicenseRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(data), `"role"`) {
		t.Error("canonical JSON contains a role key for an empty Role; legacy hashes would break")
	}
	if err := h.VerifyContentHash(rec); err != nil {
		t.Errorf("VerifyContentHash: %v", err)
	}
}

// A root-declaration record's Role must survive the canonical round-trip and
// be covered by the content hash.
func TestHasher_RoleRoundTripsAndIsHashed(t *testing.T) {
	rec := domain2.LicenseRecord{
		SchemaVersion: domain2.LicenseSchemaVersion,
		Ecosystem:     "go",
		Coordinate:    mustCoord(t, "example.com/project", "local"),
		Role:          domain2.LicenseRoleRootDeclaration,
		OverallStatus: domain2.LicenseStatusUnclassified,
		ExtractedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	var h domain2.LicenseRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	data, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := h.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Role != domain2.LicenseRoleRootDeclaration {
		t.Errorf("Role = %q, want %q after round-trip", got.Role, domain2.LicenseRoleRootDeclaration)
	}
	if err := h.VerifyContentHash(got); err != nil {
		t.Errorf("VerifyContentHash after round-trip: %v", err)
	}

	// Tampering with Role must break the hash.
	got.Role = ""
	if err := h.VerifyContentHash(got); err == nil {
		t.Error("VerifyContentHash passed after clearing Role; Role is not covered by the hash")
	}
}
