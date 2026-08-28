package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	licensesqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// ledgerRecord builds a sealed record with the fields composition ladders on.
func ledgerRecord(t *testing.T, coord coordinate.ModuleCoordinate, spdx string, confidence float64, at time.Time, artefact string) domain2.LicenseRecord {
	t.Helper()
	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		PrimaryConfidence: confidence,
		LicenseFiles: []domain2.LicenseFileEntry{
			{Path: "LICENSE", SPDX: spdx, Confidence: confidence, FileHash: "sha256:abc", FileSize: 1000},
		},
		OverallStatus:    domain2.LicenseStatusDetected,
		ExtractedAt:      at,
		PipelineVersion:  "1.1.0",
		ArtefactIdentity: artefact,
	}
	var h domain2.LicenseRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// TestLedger_ReExtractionAppendsAndBothSurvive is the observable the conversion
// exists for. Before it, the second extraction destroyed the first and the store
// could not say what it had previously held.
func TestLedger_ReExtractionAppendsAndBothSurvive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	march := ledgerRecord(t, coord, "MIT", 0.90, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	july := ledgerRecord(t, coord, "Apache-2.0", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.LicenseRecord{march, july} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	history, err := s.ListLicenseRecordsFor(ctx, coord, "1.1.0")
	if err != nil {
		t.Fatalf("ListLicenseRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("ledger holds %d generations, want 2 — the earlier finding was destroyed", len(history))
	}
	if history[0].ContentHash != march.ContentHash {
		t.Errorf("history[0] is not the earliest record; generations are not in append order")
	}
	if history[0].PrimarySPDX != "MIT" {
		t.Errorf("the March finding reads back as %q, want MIT", history[0].PrimarySPDX)
	}
	// Each generation names the artefact it was computed from, which is what makes
	// "on what evidence" answerable rather than merely "when".
	for i, r := range history {
		if r.ArtefactIdentity != artefact {
			t.Errorf("generation %d names artefact %q, want %q", i, r.ArtefactIdentity, artefact)
		}
	}

	served, found, err := s.GetLicenseRecord(ctx, coord, "1.1.0")
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found {
		t.Fatal("GetLicenseRecord found nothing after two appends")
	}
	if served.PrimarySPDX != "Apache-2.0" {
		t.Errorf("composed read serves %q, want Apache-2.0 (the higher-confidence detection)", served.PrimarySPDX)
	}
}

// TestLedger_ConfidenceOutranksRecency is the rule the epic corrected five
// tickets for. A later, weaker measurement must not displace a stronger earlier
// one merely by being newer.
func TestLedger_ConfidenceOutranksRecency(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	confident := ledgerRecord(t, coord, "MIT", 0.99, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	regressed := ledgerRecord(t, coord, "Apache-2.0", 0.40, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.LicenseRecord{confident, regressed} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	served, found, err := s.GetLicenseRecord(ctx, coord, "1.1.0")
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found {
		t.Fatal("GetLicenseRecord found nothing")
	}
	if served.PrimarySPDX != "MIT" {
		t.Errorf("composed read serves %q; a classifier regression displaced a confident detection by being newer", served.PrimarySPDX)
	}
}

// TestLedger_EqualConfidenceDisagreementIsReported pins the case the ticket says
// must not be composed away: two equally confident detections of one artefact
// naming different licences is a relicensing or a misdetection, and picking one
// makes it invisible.
func TestLedger_EqualConfidenceDisagreementIsReported(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	for _, r := range []domain2.LicenseRecord{
		ledgerRecord(t, coord, "MIT", 0.99, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, coord, "AGPL-3.0-only", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	_, _, err := s.GetLicenseRecord(ctx, coord, "1.1.0")
	if !errors.Is(err, ports.ErrLicenceConflict) {
		t.Fatalf("GetLicenseRecord returned %v, want ErrLicenceConflict", err)
	}
	var conflict domain2.LicenceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("the conflict does not carry a domain2.LicenceConflict: %v", err)
	}
	if conflict.Field != "primary_spdx" {
		t.Errorf("conflict names field %q, want primary_spdx", conflict.Field)
	}
	if len(conflict.Values) != 2 || len(conflict.ContentHashes) != 2 {
		t.Errorf("conflict reports %d values and %d records, want 2 of each", len(conflict.Values), len(conflict.ContentHashes))
	}

	// The ledger still holds both. A conflict is a refusal to pick, not a loss.
	history, err := s.ListLicenseRecordsFor(ctx, coord, "1.1.0")
	if err != nil {
		t.Fatalf("ListLicenseRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("ledger holds %d generations after a conflict, want 2", len(history))
	}
}

// TestLedger_LowerConfidenceDisagreementIsARefinement is the other half of the
// same rule: a classifier that resolves a previously uncertain file is a
// refinement of one answer, not a contradiction, and composition serves it.
func TestLedger_LowerConfidenceDisagreementIsARefinement(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	for _, r := range []domain2.LicenseRecord{
		ledgerRecord(t, coord, "MIT", 0.55, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, coord, "BSD-3-Clause", 0.98, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	served, found, err := s.GetLicenseRecord(ctx, coord, "1.1.0")
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found || served.PrimarySPDX != "BSD-3-Clause" {
		t.Errorf("composed read serves %q (found=%v), want the refined BSD-3-Clause", served.PrimarySPDX, found)
	}
}

// TestLedger_IdenticalRecordWrittenTwiceIsOneRow pins that the append is
// idempotent for the same measurement. A retried write must not fail a run that
// had already succeeded, nor invent a second measurement.
func TestLedger_IdenticalRecordWrittenTwiceIsOneRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := ledgerRecord(t, coord, "MIT", 0.99, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("same-bytes=").String())

	for range 2 {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	history, err := s.ListLicenseRecordsFor(ctx, coord, "1.1.0")
	if err != nil {
		t.Fatalf("ListLicenseRecordsFor: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("ledger holds %d rows for one measurement written twice, want 1", len(history))
	}
}

// TestLedger_ListCollapsesGenerations pins that the ledger does not reintroduce
// the duplicate listing migration 6 removed. An operator reading license-list
// must not see a re-extracted module twice and have no way to tell that from two
// modules.
func TestLedger_ListCollapsesGenerations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	a := mustCoord(t, "example.com/a", "v1.0.0")
	b := mustCoord(t, "example.com/b", "v1.0.0")
	for _, r := range []domain2.LicenseRecord{
		ledgerRecord(t, a, "MIT", 0.90, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, a, "Apache-2.0", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, b, "MIT", 0.95, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	sums, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{})
	if err != nil {
		t.Fatalf("ListLicenseRecords: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("license list returned %d rows for 2 modules holding 3 generations", len(sums))
	}
	byModule := map[string]string{}
	for _, s := range sums {
		byModule[s.ModulePath] = s.PrimarySPDX
	}
	// The collapsed summary must be the SERVED generation, not whichever row the
	// database happened to return first.
	if byModule["example.com/a"] != "Apache-2.0" {
		t.Errorf("module a lists %q, want the composed answer Apache-2.0", byModule["example.com/a"])
	}
	if byModule["example.com/b"] != "MIT" {
		t.Errorf("module b lists %q, want MIT", byModule["example.com/b"])
	}

	// Limit counts modules, not rows: a module with three generations must not
	// consume three places of the caller's page.
	page, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListLicenseRecords with a limit: %v", err)
	}
	if len(page) != 1 {
		t.Errorf("limit 1 returned %d rows, want 1", len(page))
	}
}

// seedPreLedgerRow writes a record straight into the pre-ledger table, the way
// the generation being carried in was written: before the ledger key existed and
// before the write leg required an artefact identity.
func seedPreLedgerRow(t *testing.T, db sqlitestore.DB, r domain2.LicenseRecord) {
	t.Helper()
	var h domain2.LicenseRecordHasher
	raw, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = db.DB().Exec(`INSERT INTO licence_records (
        module_path, module_version, pipeline_version,
        primary_spdx, spdx_expression, overall_status, copyright_status,
        provenance_confidence, extracted_at, content_hash, serialised
    ) VALUES (?, ?, ?, ?, '', ?, 0, 0, ?, ?, ?)`,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		r.PrimarySPDX, int(r.OverallStatus),
		r.ExtractedAt.UTC().Format(time.RFC3339), r.ContentHash, blobcodec.Encode(raw))
	if err != nil {
		t.Fatalf("seeding legacy row for %s: %v", r.Coordinate, err)
	}
}

// TestLedger_ConflictIsReportedOnItsRowNotAsTheListsError pins that one module
// in dispute does not delete the answers for every other module. Measured on the
// maintainer's store, a single conflicting module made all 2,206 unlistable
// before this — a denial of 2,205 correct answers in the name of surfacing one
// problem.
func TestLedger_ConflictIsReportedOnItsRowNotAsTheListsError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	disputed := mustCoord(t, "example.com/disputed", "v1.0.0")
	fine := mustCoord(t, "example.com/fine", "v1.0.0")
	for _, r := range []domain2.LicenseRecord{
		ledgerRecord(t, disputed, "MIT", 0.99, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, disputed, "AGPL-3.0-only", 0.99, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, fine, "Apache-2.0", 0.95, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutLicenseRecord(ctx, r); err != nil {
			t.Fatalf("PutLicenseRecord: %v", err)
		}
	}

	sums, err := s.ListLicenseRecords(ctx, ports.LicenseFilter{})
	if err != nil {
		t.Fatalf("ListLicenseRecords returned an error; one disputed module took the whole list down: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("list returned %d rows, want 2", len(sums))
	}
	var sawConflict, sawFine bool
	for _, sum := range sums {
		switch sum.ModulePath {
		case "example.com/disputed":
			if sum.Conflict == nil {
				t.Error("the disputed module is listed with no conflict recorded; the dispute is invisible")
			}
			if !errors.Is(sum.Conflict, ports.ErrLicenceConflict) {
				t.Errorf("conflict is %v, want ErrLicenceConflict", sum.Conflict)
			}
			if sum.PrimarySPDX != "" {
				t.Errorf("the disputed module reports SPDX %q; composition refused to pick, so there is no answer to project", sum.PrimarySPDX)
			}
			sawConflict = true
		case "example.com/fine":
			if sum.Conflict != nil {
				t.Errorf("the healthy module carries a conflict: %v", sum.Conflict)
			}
			if sum.PrimarySPDX != "Apache-2.0" {
				t.Errorf("the healthy module lists %q, want Apache-2.0", sum.PrimarySPDX)
			}
			sawFine = true
		}
	}
	if !sawConflict || !sawFine {
		t.Errorf("list is missing rows: sawConflict=%v sawFine=%v", sawConflict, sawFine)
	}
}

// TestMigration7_CarriesExistingRowsInUnpurged is the epic's acceptance shape:
// the first generation carries in, nothing is purged, and every carried-in
// record still verifies its content hash afterwards.
func TestMigration7_CarriesExistingRowsInUnpurged(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "mirror.db")
	all := licensesqlite.Migrations()

	// Open at migration 6 — after the broken generation is purged, before the
	// ledger — and seal rows through the store as it stood then.
	pre, err := sqlitestore.Open(dsn, all[:6], sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at migration 6: %v", err)
	}
	identified := mustCoord(t, "example.com/a", "v1.0.0")
	legacy := mustCoord(t, "example.com/b", "v2.0.0")
	coords := []coordinate.ModuleCoordinate{identified, legacy}
	want := map[string]string{} // coordinate -> content hash

	// One row of each shape the maintainer's store actually holds: 176 rows carry
	// a real zip identity, and 2,030 predate the field and carry none.
	//
	// Both are seeded through SQL rather than through the store. The store's code
	// is always at HEAD while only the schema is old, so its append already names
	// the ledger key that migration 7 has not created yet — and the unidentified
	// row could not go through the write leg in any case, which is precisely why
	// those rows are legacy.
	withID := ledgerRecord(t, identified, "MIT", 0.9,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("carried-in=").String())
	seedPreLedgerRow(t, pre, withID)
	want[identified.String()] = withID.ContentHash

	noID := ledgerRecord(t, legacy, "Apache-2.0", 0.8, time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC), "")
	seedPreLedgerRow(t, pre, noID)
	want[legacy.String()] = noID.ContentHash
	if err := pre.Close(); err != nil {
		t.Fatalf("closing at migration 6: %v", err)
	}

	store, err := licensesqlite.Open(dsn)
	if err != nil {
		t.Fatalf("migrating to head: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	var total int
	if err := store.InternalDB().DB().QueryRow(`SELECT count(*) FROM licence_records`).Scan(&total); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if total != len(coords) {
		t.Errorf("ledger holds %d rows after the conversion, want %d — rows were purged", total, len(coords))
	}

	// Readable through the store's own path, which is what verifies the hash.
	// Counting rows would pass on a table full of records nobody can check.
	for _, c := range coords {
		got, found, gerr := store.GetLicenseRecord(context.Background(), c, "1.1.0")
		if gerr != nil {
			t.Errorf("carried-in record for %s does not verify after the conversion: %v", c, gerr)
			continue
		}
		if !found {
			t.Errorf("carried-in record for %s is gone", c)
			continue
		}
		if got.ContentHash != want[c.String()] {
			t.Errorf("carried-in record for %s has content hash %q, want %q", c, got.ContentHash, want[c.String()])
		}
	}
}
