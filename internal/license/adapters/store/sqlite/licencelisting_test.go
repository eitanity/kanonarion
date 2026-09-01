package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// chromaShapedRecord is a record whose STORED identity names a licence covering
// something other than the module's code: one root COPYING carrying the
// library's MIT grant and an embedded font's OFL-1.1 at the identical
// confidence, with the font licence the most-covered match.
//
// The columns a listing is built from are exactly what the ledger holds here,
// so this is the record shape that made `license-list` and `license` disagree.
func chromaShapedRecord(t *testing.T, coord coordinate.ModuleCoordinate) domain2.LicenseRecord {
	t.Helper()
	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       "OFL-1.1",
		Expression:        "MIT AND OFL-1.1",
		ExpressionBasis:   "split: is licensed under",
		PrimaryConfidence: 0.977983777520278,
		LicenseFiles: []domain2.LicenseFileEntry{{
			Path:       "COPYING",
			SPDX:       "OFL-1.1",
			Confidence: 0.977983777520278,
			FileHash:   "sha256:abc",
			FileSize:   5569,
			AltMatches: []domain2.AltMatch{{SPDX: "MIT", Confidence: 0.977983777520278}},
		}},
		OverallStatus:    domain2.LicenseStatusMultiple,
		ExtractedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "0.1.0",
		ArtefactIdentity: fetchtest.ZipArtefact("chroma-zip=").String(),
	}
	var h domain2.LicenseRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// TestListLicenseRecords_IdentityIsReadThroughCoverage is the store half of the
// cross-surface control.
//
// A listing used to be assembled from the indexed `primary_spdx` and
// `spdx_expression` columns, which hold what extraction measured. For a record
// written before coverage existed those name a licence covering an embedded
// asset, so the listing served OFL-1.1 for a Go library while `license` on the
// same coordinate served MIT. The row is now projected from the record.
func TestListLicenseRecords_IdentityIsReadThroughCoverage(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "github.com/alecthomas/chroma/v2", "v2.27.0")
	rec := chromaShapedRecord(t, coord)
	if err := s.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{})
	if err != nil {
		t.Fatalf("ListLicenseRecords: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("listed %d rows, want 1", len(sums))
	}
	if sums[0].PrimarySPDX != "MIT" {
		t.Errorf("listed primary = %q, want MIT — the listing must not serve the "+
			"embedded font's licence that the stored column names", sums[0].PrimarySPDX)
	}
	if sums[0].Expression != "MIT" {
		t.Errorf("listed expression = %q, want MIT", sums[0].Expression)
	}
	// The row is a projection, never a rewrite: the ledger still holds what was
	// measured, and the row still names the record it came from.
	if sums[0].ContentHash != rec.ContentHash {
		t.Errorf("row content hash = %q, want the stored record's %q", sums[0].ContentHash, rec.ContentHash)
	}
	stored, found, err := s.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if err != nil || !found {
		t.Fatalf("GetLicenseRecord: %v found=%v", err, found)
	}
	if stored.PrimarySPDX != "OFL-1.1" || stored.Expression != "MIT AND OFL-1.1" {
		t.Errorf("the stored record was rewritten: primary=%q expression=%q",
			stored.PrimarySPDX, stored.Expression)
	}
}

// TestListLicenseRecords_OrdinaryRecordIsUnchanged is the control by volume:
// 1,809 of the maintainer's 1,828 records carry one root licence over their own
// code, and no listing row for one of them may move.
func TestListLicenseRecords_OrdinaryRecordIsUnchanged(t *testing.T) {
	s := openTestStore(t)
	for _, spdx := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "CC0-1.0"} {
		coord := mustCoord(t, "example.com/"+spdx, "v1.0.0")
		if err := s.PutLicenseRecord(context.Background(),
			buildRecord(t, coord, spdx, domain2.LicenseStatusDetected)); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}
	sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{})
	if err != nil {
		t.Fatalf("ListLicenseRecords: %v", err)
	}
	if len(sums) != 4 {
		t.Fatalf("listed %d rows, want 4", len(sums))
	}
	for _, sum := range sums {
		want := sum.ModulePath[len("example.com/"):]
		if sum.PrimarySPDX != want {
			t.Errorf("%s listed as %q, want %q", sum.ModulePath, sum.PrimarySPDX, want)
		}
	}
}
