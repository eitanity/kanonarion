package domain_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// The hashed shape of a licence record, written down. Every key the canonical
// JSON emits unconditionally appears here exactly once.
//
// This is the guard the store did not have, and its absence cost a whole
// generation of records. LowConfidenceCoverage and LowConfidenceSPDX were added
// to the file entry without omitempty and without a pipeline bump, so every
// record carrying a licence file silently gained two hashed keys. The rows
// written before that change kept a hash computed over the old shape and stopped
// verifying: measured through the store's own read path, 638 of the 643 rows at
// pipeline 1.0.0 fail with ErrLicenceIntegrity, and the only five that survive
// are the five carrying no licence file at all.
//
// A green suite did not notice, because every existing test hashed and verified
// within one process, where both sides of the comparison see the same shape. The
// shape is only observable against a record written by a DIFFERENT generation,
// which no unit test holds. Pinning the key set is how a unit test can see it:
// the lists below are what the persisted records on disk were hashed over.
//
// If a change to this file's expectations is needed, that is the signal — not a
// formality. Adding a key to a hashed shape is one of exactly two changes:
//
//   - the field is omitempty AND absent from every record already written, so
//     pre-existing records marshal to the bytes they always did (artefact_identity,
//     source_content_hash and role are the worked examples); or
//   - the shape genuinely changed, which owes a PipelineVersion bump and a
//     migration purging the generation it leaves behind.
//
// Retrofitting omitempty to a field that is already being hashed is NEITHER, and
// is not a repair. Measured against the maintainer's store, giving these two
// fields omitempty today makes the 638 broken rows verify and breaks 2,187 of the
// 2,206 records at 1.1.0 — it moves the damage rather than undoing it.
var (
	wantRecordKeys = []string{
		"content_hash",
		"coordinate",
		"copyright_status",
		"ecosystem",
		"expression",
		"extracted_at",
		"failure_detail",
		"license_files",
		"overall_status",
		"pipeline_version",
		"primary_confidence",
		"primary_spdx",
		"provenance",
		"schema_version",
	}
	wantFileEntryKeys = []string{
		"alt_matches",
		"confidence",
		"copyright_statements",
		"file_hash",
		"file_size",
		"is_per_file",
		"is_vendored",
		"low_confidence_coverage",
		"low_confidence_spdx",
		"path",
		"spdx",
	}
)

// TestCanonicalShape_KeySetIsPinned fails when a field joins or leaves the
// hashed shape of a licence record. See the comment on wantRecordKeys for what
// to do when it fires.
func TestCanonicalShape_KeySetIsPinned(t *testing.T) {
	t.Parallel()

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	// Every value is the zero value, because zero values are what an omitempty
	// field hides. A record built from non-zero values would emit every key
	// regardless and prove nothing about the shape.
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "1.1.0",
		LicenseFiles:    []domain.LicenseFileEntry{{Path: "LICENSE"}},
	}

	var h domain.LicenseRecordHasher
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshalling canonical JSON: %v", err)
	}
	assertKeySet(t, "licence record", top, wantRecordKeys)

	var files []map[string]json.RawMessage
	if err := json.Unmarshal(top["license_files"], &files); err != nil {
		t.Fatalf("unmarshalling license_files: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("license_files holds %d entries, want 1", len(files))
	}
	assertKeySet(t, "licence file entry", files[0], wantFileEntryKeys)
}

func assertKeySet(t *testing.T, what string, got map[string]json.RawMessage, want []string) {
	t.Helper()

	wanted := make(map[string]bool, len(want))
	for _, k := range want {
		wanted[k] = true
	}
	for k := range got {
		if !wanted[k] {
			t.Errorf("the hashed shape of a %s gained the key %q. Every record already"+
				" written was hashed without it and will stop verifying — see the comment"+
				" on wantRecordKeys before changing this list", what, k)
		}
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("the hashed shape of a %s lost the key %q. Every record already"+
				" written was hashed with it and will stop verifying — see the comment"+
				" on wantRecordKeys before changing this list", what, k)
		}
	}
}

// TestCanonicalShape_FileEntriesRoundTripAndVerify pins the two shapes the
// purged generation split on: a record with no licence file emits no file entry
// at all and was never affected, while a record carrying several is the shape
// whose hash the added keys changed. Both must survive a round trip and verify.
func TestCanonicalShape_FileEntriesRoundTripAndVerify(t *testing.T) {
	t.Parallel()

	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	base := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		Coordinate:      coord,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "1.1.0",
	}

	cases := map[string][]domain.LicenseFileEntry{
		"no licence files": nil,
		"several licence files": {
			{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
			{Path: "vendor/x/COPYING", IsVendored: true, LowConfidenceSPDX: "GPL-3.0-only", LowConfidenceCoverage: 0.4},
			{Path: "internal/LICENSE.txt", IsPerFile: true, SPDX: "Apache-2.0", Confidence: 0.87},
		},
	}

	var h domain.LicenseRecordHasher
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := base
			rec.LicenseFiles = files
			sealed, err := h.SetContentHash(rec)
			if err != nil {
				t.Fatalf("SetContentHash: %v", err)
			}
			raw, err := h.Marshal(sealed)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := h.Unmarshal(raw)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if err := h.VerifyContentHash(got); err != nil {
				t.Errorf("VerifyContentHash after a round trip: %v", err)
			}
			if len(got.LicenseFiles) != len(files) {
				t.Errorf("round trip returned %d licence files, want %d", len(got.LicenseFiles), len(files))
			}
		})
	}
}
