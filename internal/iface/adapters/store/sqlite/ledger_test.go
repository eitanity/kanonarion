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
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	ifacesqlite "github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

const ledgerPipeline = "0.3.0"

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

// ledgerRecord builds a sealed record with the fields composition ladders on:
// the extraction status and the time. funcNames drives the exported API, so two
// records can be made to agree or disagree about it deliberately.
func ledgerRecord(
	t *testing.T,
	coord coordinate.ModuleCoordinate,
	status domain2.InterfaceStatus,
	funcNames []string,
	at time.Time,
	artefact string,
) domain2.InterfaceRecord {
	t.Helper()
	funcs := make([]domain2.FuncDecl, 0, len(funcNames))
	for _, n := range funcNames {
		funcs = append(funcs, domain2.FuncDecl{Name: n, Signature: "func " + n + "()"})
	}
	r := domain2.InterfaceRecord{
		SchemaVersion: domain2.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Packages: []domain2.PackageInterface{{
			ImportPath: coord.Path(),
			Name:       "mod",
			Funcs:      funcs,
		}},
		OverallStatus:    status,
		ExtractedAt:      at,
		PipelineVersion:  ledgerPipeline,
		ArtefactIdentity: artefact,
	}
	var h domain2.InterfaceRecordHasher
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
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	march := ledgerRecord(t, coord, domain2.InterfaceStatusPartial,
		[]string{"New"}, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	july := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted,
		[]string{"New", "Close"}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.InterfaceRecord{march, july} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	history, err := s.ListInterfaceRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListInterfaceRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("ledger holds %d generations, want 2 — the earlier extraction was destroyed", len(history))
	}
	if history[0].ContentHash != march.ContentHash {
		t.Errorf("history[0] is not the earliest record; generations are not in append order")
	}
	for i, r := range history {
		if r.ArtefactIdentity != artefact {
			t.Errorf("generation %d names artefact %q, want %q", i, r.ArtefactIdentity, artefact)
		}
	}

	served, found, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetInterfaceRecord: %v", err)
	}
	if !found {
		t.Fatal("GetInterfaceRecord found nothing after two appends")
	}
	if served.ContentHash != july.ContentHash {
		t.Errorf("composed read does not serve the complete extraction")
	}
}

// TestLedger_CompleteOutranksPartialRegardlessOfOrder is the ticket's stated
// rule. A Partial extraction appended after a complete one must not become the
// answer: it missed at least one package to a parse failure, so it is a weaker
// measurement of the same API rather than a newer one.
func TestLedger_CompleteOutranksPartialRegardlessOfOrder(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	complete := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted,
		[]string{"New", "Close"}, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	partial := ledgerRecord(t, coord, domain2.InterfaceStatusPartial,
		[]string{"New"}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.InterfaceRecord{complete, partial} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	served, found, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetInterfaceRecord: %v", err)
	}
	if !found || served.ContentHash != complete.ContentHash {
		t.Errorf("composed read serves the Partial extraction; a run that lost a package to a parse failure displaced a complete one by being newer")
	}
}

// TestLedger_EqualStatusDisagreementIsReported is the narrow case worth
// surfacing rather than absorbing: two records describing the SAME artefact
// at the SAME status that disagree about the exported API. Nothing about the
// bytes or the resolution differs, so the extractor did.
func TestLedger_EqualStatusDisagreementIsReported(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	for _, r := range []domain2.InterfaceRecord{
		ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	_, _, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if !errors.Is(err, ports.ErrInterfaceConflict) {
		t.Fatalf("GetInterfaceRecord returned %v, want ErrInterfaceConflict", err)
	}
	var conflict domain2.InterfaceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("the conflict does not carry a domain2.InterfaceConflict: %v", err)
	}
	if conflict.Field != "public_api" {
		t.Errorf("conflict names field %q, want public_api", conflict.Field)
	}
	if len(conflict.Values) != 2 || len(conflict.ContentHashes) != 2 {
		t.Errorf("conflict reports %d values and %d records, want 2 of each",
			len(conflict.Values), len(conflict.ContentHashes))
	}
}

// TestLedger_EqualStatusAgreementIsNotAConflict is the other half of that rule,
// and it is the one that would fire spuriously if the check compared content
// hashes. Two runs producing the identical API a second apart carry DIFFERENT
// content hashes, because the time of measurement is inside the hashed shape.
func TestLedger_EqualStatusAgreementIsNotAConflict(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	first := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	second := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
		time.Date(2026, 3, 1, 0, 0, 1, 0, time.UTC), artefact)
	if first.ContentHash == second.ContentHash {
		t.Fatal("the two records share a content hash; this test no longer covers what it claims")
	}
	for _, r := range []domain2.InterfaceRecord{first, second} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	served, found, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("two runs that agree about the API were reported as a conflict: %v", err)
	}
	if !found || served.ContentHash != second.ContentHash {
		t.Errorf("composed read serves %q, want the more recent of two agreeing records", served.ContentHash)
	}
}

// TestLedger_PartialDisagreementIsARefinementNotAConflict pins the distinction
// the correction on the ticket turns on: a Partial extraction disagreeing with a
// complete one is what the ladder exists to resolve, not evidence of
// non-determinism.
func TestLedger_PartialDisagreementIsARefinementNotAConflict(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	for _, r := range []domain2.InterfaceRecord{
		ledgerRecord(t, coord, domain2.InterfaceStatusPartial, []string{"New"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	served, found, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("a Partial and a complete extraction were reported as a conflict: %v", err)
	}
	if !found || served.OverallStatus != domain2.InterfaceStatusExtracted {
		t.Errorf("composed read serves a %v extraction, want the complete one", served.OverallStatus)
	}
}

// TestLedger_FailedExtractionCannotContradictACompletedOne pins that a run which
// never reached a package makes no claim about the API, so it cannot disagree
// with one that does.
func TestLedger_FailedExtractionCannotContradictACompletedOne(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	failed := ledgerRecord(t, coord, domain2.InterfaceStatusExtractionFailed, nil,
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)
	extracted := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New"},
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	for _, r := range []domain2.InterfaceRecord{extracted, failed} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	served, found, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("a failed extraction was reported as contradicting a successful one: %v", err)
	}
	if !found || served.ContentHash != extracted.ContentHash {
		t.Errorf("composed read serves the failed extraction; a run that reached no package must not outrank one that did")
	}
}

// TestLedger_TwoArtefactsForOnePinnedVersionIsReported pins the disagreement
// that has no ladder at all: two identities for one pinned version means the
// same module at the same version yielded two different sets of bytes.
func TestLedger_TwoArtefactsForOnePinnedVersionIsReported(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	for _, r := range []domain2.InterfaceRecord{
		ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-one=").String()),
		ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New"},
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-two=").String()),
	} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	_, _, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	var conflict domain2.InterfaceConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("GetInterfaceRecord returned %v, want an InterfaceConflict", err)
	}
	if conflict.Field != "artefact_identity" {
		t.Errorf("conflict names field %q, want artefact_identity", conflict.Field)
	}
}

// TestLedger_UnidentifiedRecordIsSupersededByAnIdentifiedOne pins the upgrade
// path. 1,669 of the 1,850 rows on the maintainer's store name no artefact, and
// the first re-extraction of any of them names one; without this rule every one
// of those modules would report a conflict.
func TestLedger_UnidentifiedRecordIsSupersededByAnIdentifiedOne(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	legacy := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New"},
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "")
	// Seeded straight into the table: the write leg refuses a record naming no
	// artefact, which is exactly why such rows are legacy.
	seedPreLedgerRow(t, s.InternalDB(), legacy)

	identified := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("real-bytes=").String())
	if err := s.PutInterfaceRecord(ctx, identified); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}

	served, found, err := s.GetInterfaceRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetInterfaceRecord: %v", err)
	}
	if !found || served.ContentHash != identified.ContentHash {
		t.Errorf("composed read serves the record naming no artefact; a measurement that says which bytes it read is the better-evidenced answer")
	}
	history, err := s.ListInterfaceRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListInterfaceRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("ledger holds %d generations, want 2 — the legacy row was dropped", len(history))
	}
}

// TestLedger_IdenticalRecordWrittenTwiceIsOneRow pins that the append is
// idempotent for the same measurement, in the parent AND in the satellite.
func TestLedger_IdenticalRecordWrittenTwiceIsOneRow(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("same-bytes=").String())

	for range 2 {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	history, err := s.ListInterfaceRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListInterfaceRecordsFor: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("ledger holds %d rows for one measurement written twice, want 1", len(history))
	}
	if n := countSymbolRows(t, s); n != 2 {
		t.Errorf("interface_symbols holds %d rows for one measurement written twice, want 2", n)
	}
}

// TestLedger_SatelliteIsKeyedOnTheParentRecord is the half of this conversion
// the licence one did not have to do, at the scale this ticket exists to reach.
//
// Two generations of one coordinate must produce two DISJOINT sets of symbol
// rows, each resolving to exactly one parent, and a symbol lookup must return the
// composed generation's rows only.
func TestLedger_SatelliteIsKeyedOnTheParentRecord(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	partial := ledgerRecord(t, coord, domain2.InterfaceStatusPartial, []string{"New"},
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	complete := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)
	for _, r := range []domain2.InterfaceRecord{partial, complete} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	if n := countSymbolRows(t, s); n != 3 {
		t.Errorf("interface_symbols holds %d rows across two generations, want 3 — symbols collided across generations", n)
	}
	byParent := symbolRowsByParent(t, s)
	if got := byParent[partial.ContentHash]; got != 1 {
		t.Errorf("the Partial generation owns %d symbol rows, want 1", got)
	}
	if got := byParent[complete.ContentHash]; got != 2 {
		t.Errorf("the complete generation owns %d symbol rows, want 2", got)
	}
	var orphans int
	if err := s.InternalDB().DB().QueryRow(`SELECT count(*) FROM interface_symbols s
        WHERE NOT EXISTS (SELECT 1 FROM interface_records r WHERE r.content_hash = s.record_content_hash)`).
		Scan(&orphans); err != nil {
		t.Fatalf("counting orphans: %v", err)
	}
	if orphans != 0 {
		t.Errorf("%d symbol rows name no record in the ledger", orphans)
	}

	// A symbol present in BOTH generations must come back once, from the served
	// generation.
	refs, err := s.FindSymbol(ctx, "New", ledgerPipeline, coordinate.ModuleSet{})
	if err != nil {
		t.Fatalf("FindSymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("FindSymbol returned %d refs for a symbol in two generations, want 1", len(refs))
	}
}

// TestLedger_SymbolLookupFollowsTheComposedParentNotTheNewest is the sharpest
// consequence of the ladder. Composition can serve an OLDER parent than the
// newest, so taking the newest rows for the coordinate would answer "does this
// module export X" from a Partial extraction while the composed read serves a
// complete one — the two would disagree about the same module in one build.
func TestLedger_SymbolLookupFollowsTheComposedParentNotTheNewest(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	complete := ledgerRecord(t, coord, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	partial := ledgerRecord(t, coord, domain2.InterfaceStatusPartial, []string{"New"},
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)
	for _, r := range []domain2.InterfaceRecord{complete, partial} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	// Close exists only in the older, complete generation — the one composition
	// serves. Resolving symbols from the newest parent would lose it.
	refs, err := s.FindSymbol(ctx, "Close", ledgerPipeline, coordinate.ModuleSet{})
	if err != nil {
		t.Fatalf("FindSymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("FindSymbol returned %d refs for a symbol in the served generation, want 1 — symbols were taken from the newest parent", len(refs))
	}
	if refs[0].SymbolName != "Close" {
		t.Errorf("FindSymbol returned %q, want Close", refs[0].SymbolName)
	}
}

// TestLedger_ListCollapsesGenerations pins that the ledger does not reintroduce a
// duplicate listing.
func TestLedger_ListCollapsesGenerations(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	a := mustCoord(t, "example.com/a", "v1.0.0")
	b := mustCoord(t, "example.com/b", "v1.0.0")
	for _, r := range []domain2.InterfaceRecord{
		ledgerRecord(t, a, domain2.InterfaceStatusPartial, []string{"New"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, a, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, b, domain2.InterfaceStatusExtracted, []string{"Open"},
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	sums, err := s.ListInterfaceRecords(ctx, ports.InterfaceFilter{})
	if err != nil {
		t.Fatalf("ListInterfaceRecords: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("interface list returned %d rows for 2 modules holding 3 generations", len(sums))
	}
	byModule := map[string]domain2.InterfaceStatus{}
	for _, sum := range sums {
		byModule[sum.ModulePath] = sum.OverallStatus
	}
	// The collapsed summary must be the SERVED generation, not whichever row the
	// database happened to return first.
	if byModule["example.com/a"] != domain2.InterfaceStatusExtracted {
		t.Errorf("module a lists %v, want the composed answer Extracted", byModule["example.com/a"])
	}

	page, err := s.ListInterfaceRecords(ctx, ports.InterfaceFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListInterfaceRecords with a limit: %v", err)
	}
	if len(page) != 1 {
		t.Errorf("limit 1 returned %d rows, want 1", len(page))
	}
}

// TestLedger_ConflictIsReportedOnItsRowNotAsTheListsError pins that one module in
// dispute does not delete the answers for every other module.
func TestLedger_ConflictIsReportedOnItsRowNotAsTheListsError(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	disputed := mustCoord(t, "example.com/disputed", "v1.0.0")
	fine := mustCoord(t, "example.com/fine", "v1.0.0")
	for _, r := range []domain2.InterfaceRecord{
		ledgerRecord(t, disputed, domain2.InterfaceStatusExtracted, []string{"New"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, disputed, domain2.InterfaceStatusExtracted, []string{"New", "Close"},
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, fine, domain2.InterfaceStatusExtracted, []string{"Open"},
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	sums, err := s.ListInterfaceRecords(ctx, ports.InterfaceFilter{})
	if err != nil {
		t.Fatalf("ListInterfaceRecords returned an error; one disputed module took the whole list down: %v", err)
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
			if !errors.Is(sum.Conflict, ports.ErrInterfaceConflict) {
				t.Errorf("conflict is %v, want ErrInterfaceConflict", sum.Conflict)
			}
			if sum.PackageCount != 0 {
				t.Errorf("the disputed module reports %d packages; composition refused to pick, so there is no answer to project", sum.PackageCount)
			}
			sawConflict = true
		case "example.com/fine":
			if sum.Conflict != nil {
				t.Errorf("the healthy module carries a conflict: %v", sum.Conflict)
			}
			sawFine = true
		}
	}
	if !sawConflict || !sawFine {
		t.Errorf("list is missing rows: sawConflict=%v sawFine=%v", sawConflict, sawFine)
	}
}

// TestLedger_ConflictedModuleDoesNotDeleteOtherModulesSymbolAnswers is the same
// rule at the satellite, and it matters more here than anywhere: a symbol lookup
// spans every module in the store, so failing the whole query for one disputed
// module denies thousands of correct answers. The omission is still reported.
func TestLedger_ConflictedModuleDoesNotDeleteOtherModulesSymbolAnswers(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	disputed := mustCoord(t, "example.com/disputed", "v1.0.0")
	fine := mustCoord(t, "example.com/fine", "v1.0.0")
	for _, r := range []domain2.InterfaceRecord{
		ledgerRecord(t, disputed, domain2.InterfaceStatusExtracted, []string{"Shared"},
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, disputed, domain2.InterfaceStatusExtracted, []string{"Shared", "Other"},
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, fine, domain2.InterfaceStatusExtracted, []string{"Shared"},
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}

	refs, err := s.FindSymbol(ctx, "Shared", ledgerPipeline, coordinate.ModuleSet{})
	if !errors.Is(err, ports.ErrInterfaceConflict) {
		t.Errorf("FindSymbol reported %v; the omitted module is invisible", err)
	}
	if len(refs) != 1 {
		t.Fatalf("FindSymbol returned %d refs, want 1 — one disputed module deleted the healthy module's answer", len(refs))
	}
	if refs[0].ModulePath != "example.com/fine" {
		t.Errorf("FindSymbol returned a ref from %q, want example.com/fine", refs[0].ModulePath)
	}
}

func countSymbolRows(t *testing.T, s *ifacesqlite.Store) int {
	t.Helper()
	var n int
	if err := s.InternalDB().DB().QueryRow(`SELECT count(*) FROM interface_symbols`).Scan(&n); err != nil {
		t.Fatalf("counting symbol rows: %v", err)
	}
	return n
}

func symbolRowsByParent(t *testing.T, s *ifacesqlite.Store) map[string]int {
	t.Helper()
	rows, err := s.InternalDB().DB().Query(
		`SELECT record_content_hash, count(*) FROM interface_symbols GROUP BY 1`)
	if err != nil {
		t.Fatalf("grouping symbol rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var h string
		var n int
		if err := rows.Scan(&h, &n); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		out[h] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating: %v", err)
	}
	return out
}

// seedPreLedgerRow writes a record straight into the records table, the way the
// generation being carried in was written: before the write leg required an
// artefact identity.
func seedPreLedgerRow(t *testing.T, db sqlitestore.DB, r domain2.InterfaceRecord) {
	t.Helper()
	var h domain2.InterfaceRecordHasher
	raw, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = db.DB().Exec(`INSERT INTO interface_records (
        module_path, module_version, pipeline_version,
        overall_status, package_count, extracted_at, content_hash, serialised
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		int(r.OverallStatus), len(r.Packages),
		r.ExtractedAt.UTC().Format(time.RFC3339), r.ContentHash, blobcodec.Encode(raw))
	if err != nil {
		t.Fatalf("seeding legacy row for %s: %v", r.Coordinate, err)
	}
}

// seedPreLedgerSymbols writes a record's symbol rows in the pre-rekey shape:
// keyed on the coordinate, with no reference to the parent record at all.
func seedPreLedgerSymbols(t *testing.T, db sqlitestore.DB, r domain2.InterfaceRecord) {
	t.Helper()
	for _, pkg := range r.Packages {
		for _, f := range pkg.Funcs {
			if _, err := db.DB().Exec(`INSERT INTO interface_symbols (
                module_path, module_version, pipeline_version,
                package_path, symbol_kind, symbol_name, parent_type, signature
            ) VALUES (?, ?, ?, ?, 'func', ?, '', ?)`,
				r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
				pkg.ImportPath, f.Name, f.Signature); err != nil {
				t.Fatalf("seeding legacy symbol row %s: %v", f.Name, err)
			}
		}
	}
}

// TestMigration4_CarriesRowsInAndRekeysTheSatellite is the epic's acceptance
// shape plus the one licence did not have to meet: the first generation carries
// in unpurged, every carried-in record still verifies, and every symbol row is
// rekeyed onto its parent record with none orphaned and none duplicated.
func TestMigration4_CarriesRowsInAndRekeysTheSatellite(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "mirror.db")
	all := ifacesqlite.Migrations()

	// Open at migration 3: the schema as it stood before the ledger. Seeding
	// through the store instead is impossible — its code is always at HEAD, so
	// its append already names the ledger key migration 4 has not created yet.
	pre, err := sqlitestore.Open(dsn, all[:3], sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at migration 3: %v", err)
	}
	identified := mustCoord(t, "example.com/a", "v1.0.0")
	legacy := mustCoord(t, "example.com/b", "v2.0.0")
	coords := []coordinate.ModuleCoordinate{identified, legacy}
	want := map[string]string{}  // coordinate -> content hash
	wantKids := map[string]int{} // content hash -> symbol rows

	// One row of each shape the maintainer's store actually holds: measured
	// read-only before this change, 181 of 1,850 rows carry a real zip identity
	// in their blob and 1,669 predate the field and carry none.
	withID := ledgerRecord(t, identified, domain2.InterfaceStatusExtracted,
		[]string{"New", "Close"}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		fetchtest.ZipArtefact("carried-in=").String())
	seedPreLedgerRow(t, pre, withID)
	seedPreLedgerSymbols(t, pre, withID)
	want[identified.String()] = withID.ContentHash
	wantKids[withID.ContentHash] = 2

	noID := ledgerRecord(t, legacy, domain2.InterfaceStatusExtracted,
		[]string{"Open"}, time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC), "")
	seedPreLedgerRow(t, pre, noID)
	seedPreLedgerSymbols(t, pre, noID)
	want[legacy.String()] = noID.ContentHash
	wantKids[noID.ContentHash] = 1

	if err := pre.Close(); err != nil {
		t.Fatalf("closing at migration 3: %v", err)
	}

	store, err := ifacesqlite.Open(dsn)
	if err != nil {
		t.Fatalf("migrating to head: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	var total int
	if err := store.InternalDB().DB().QueryRow(`SELECT count(*) FROM interface_records`).Scan(&total); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if total != len(coords) {
		t.Errorf("ledger holds %d rows after the conversion, want %d — rows were purged", total, len(coords))
	}

	// Readable through the store's own path, which is what verifies the seal.
	for _, c := range coords {
		got, found, gerr := store.GetInterfaceRecord(context.Background(), c, ledgerPipeline)
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

	gotKids := symbolRowsByParent(t, store)
	if len(gotKids) != len(wantKids) {
		t.Errorf("symbol rows resolve to %d parents, want %d", len(gotKids), len(wantKids))
	}
	for hash, n := range wantKids {
		if gotKids[hash] != n {
			t.Errorf("record %s owns %d symbol rows after the rekey, want %d", hash, gotKids[hash], n)
		}
	}
	if n := countSymbolRows(t, store); n != 3 {
		t.Errorf("interface_symbols holds %d rows after the rekey, want 3 — symbols were lost or duplicated", n)
	}

	// And the rekeyed symbols resolve through the read path.
	refs, err := store.FindSymbol(context.Background(), "Close", ledgerPipeline, coordinate.ModuleSet{})
	if err != nil {
		t.Fatalf("FindSymbol after the rekey: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("FindSymbol returned %d refs after the rekey, want 1", len(refs))
	}
}
