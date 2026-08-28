package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	examplesqlite "github.com/eitanity/kanonarion/internal/example/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/example/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

const ledgerPipeline = "0.3.0"

// ledgerRecord builds a sealed record with the fields composition ladders on:
// the completion of the extraction, the number of parse failures, and the time.
func ledgerRecord(
	t *testing.T,
	coord coordinate.ModuleCoordinate,
	status domain2.ExampleStatus,
	exampleNames []string,
	parseFailures int,
	at time.Time,
	artefact string,
) domain2.ExampleRecord {
	t.Helper()
	examples := make([]domain2.ExampleEntry, 0, len(exampleNames))
	for _, n := range exampleNames {
		symbol, sub := domain2.DeriveAssociatedSymbol(n)
		examples = append(examples, domain2.ExampleEntry{
			Name:             n,
			Package:          "mod_test",
			AssociatedSymbol: symbol,
			SubExample:       sub,
			Body:             "{}",
			Validates:        true,
		})
	}
	failures := make([]domain2.ParseFailure, 0, parseFailures)
	for i := range parseFailures {
		failures = append(failures, domain2.ParseFailure{
			File:  fmt.Sprintf("broken%d_test.go", i),
			Error: "expected declaration",
		})
	}
	r := domain2.ExampleRecord{
		SchemaVersion:    domain2.ExampleSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Examples:         examples,
		ParseFailures:    failures,
		OverallStatus:    status,
		ExtractedAt:      at,
		PipelineVersion:  ledgerPipeline,
		ArtefactIdentity: artefact,
	}
	var h domain2.ExampleRecordHasher
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

	march := ledgerRecord(t, coord, domain2.ExampleStatusFound,
		[]string{"ExampleAlpha"}, 3, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	july := ledgerRecord(t, coord, domain2.ExampleStatusFound,
		[]string{"ExampleAlpha", "ExampleBeta"}, 0, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.ExampleRecord{march, july} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	history, err := s.ListExampleRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListExampleRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("ledger holds %d generations, want 2 — the earlier extraction was destroyed", len(history))
	}
	if history[0].ContentHash != march.ContentHash {
		t.Errorf("history[0] is not the earliest record; generations are not in append order")
	}
	if len(history[0].ParseFailures) != 3 {
		t.Errorf("the March extraction reads back with %d parse failures, want 3", len(history[0].ParseFailures))
	}
	// Each generation names the artefact it was computed from, which is what makes
	// "on what evidence" answerable rather than merely "when".
	for i, r := range history {
		if r.ArtefactIdentity != artefact {
			t.Errorf("generation %d names artefact %q, want %q", i, r.ArtefactIdentity, artefact)
		}
	}

	served, found, err := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if !found {
		t.Fatal("GetExampleRecord found nothing after two appends")
	}
	if served.ContentHash != july.ContentHash {
		t.Errorf("composed read serves the March record; the clean July extraction should win on parse failures")
	}
}

// TestLedger_FewestParseFailuresOutranksRecency is the rule the ticket states.
// A later extraction that regresses to more parse failures must not displace a
// cleaner earlier one merely by being newer.
func TestLedger_FewestParseFailuresOutranksRecency(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	clean := ledgerRecord(t, coord, domain2.ExampleStatusFound,
		[]string{"ExampleAlpha"}, 0, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	regressed := ledgerRecord(t, coord, domain2.ExampleStatusNone,
		nil, 4, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.ExampleRecord{clean, regressed} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	served, found, err := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if !found {
		t.Fatal("GetExampleRecord found nothing")
	}
	if served.ContentHash != clean.ContentHash {
		t.Errorf("composed read serves the degraded extraction; a run that lost 4 files to parse errors displaced a clean one by being newer")
	}
}

// TestLedger_CleanZeroIsNotABrokenZero is the distinction the ticket says must
// not be conflated: "found 0 examples, every file parsed" is a fact about the
// module, and "found 0 examples, 3 files failed to parse" is a failed
// measurement of it. Under an overwriting store the second silently replaced the
// first.
func TestLedger_CleanZeroIsNotABrokenZero(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	cleanZero := ledgerRecord(t, coord, domain2.ExampleStatusNone,
		nil, 0, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	brokenZero := ledgerRecord(t, coord, domain2.ExampleStatusNone,
		nil, 3, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.ExampleRecord{cleanZero, brokenZero} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	served, _, err := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if len(served.ParseFailures) != 0 {
		t.Errorf("composed read serves the broken measurement of zero examples; the clean one is indistinguishable from it")
	}
}

// TestLedger_FailedExtractionNeverOutranksACompletedOne is the trap in the
// ticket's own ladder. A failed extraction never reaches a file, so it records NO
// parse failures at all; ordering on the failure count alone would therefore rank
// a total failure above a partial success and invert exactly the distinction the
// count exists to draw.
func TestLedger_FailedExtractionNeverOutranksACompletedOne(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	partial := ledgerRecord(t, coord, domain2.ExampleStatusFound,
		[]string{"ExampleAlpha"}, 2, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	failed := ledgerRecord(t, coord, domain2.ExampleStatusExtractionFailed,
		nil, 0, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)

	for _, r := range []domain2.ExampleRecord{partial, failed} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	served, _, err := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if served.OverallStatus != domain2.ExampleStatusFound {
		t.Errorf("composed read serves a %v extraction; a run that never parsed a file records zero parse failures and must not outrank a partial success",
			served.OverallStatus)
	}
}

// TestLedger_TwoArtefactsForOnePinnedVersionIsReported pins the one disagreement
// composition must not resolve by picking. Two identities for one pinned version
// means the same module at the same version yielded two different sets of bytes,
// and there is no ladder between answers about different bytes.
func TestLedger_TwoArtefactsForOnePinnedVersionIsReported(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	for _, r := range []domain2.ExampleRecord{
		ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-one=").String()),
		ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleBeta"}, 0,
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-two=").String()),
	} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	_, _, err := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	if !errors.Is(err, ports.ErrExampleConflict) {
		t.Fatalf("GetExampleRecord returned %v, want ErrExampleConflict", err)
	}
	var conflict domain2.ExampleConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("the conflict does not carry a domain2.ExampleConflict: %v", err)
	}
	if conflict.Field != "artefact_identity" {
		t.Errorf("conflict names field %q, want artefact_identity", conflict.Field)
	}
	if len(conflict.Values) != 2 || len(conflict.ContentHashes) != 2 {
		t.Errorf("conflict reports %d values and %d records, want 2 of each",
			len(conflict.Values), len(conflict.ContentHashes))
	}

	// The ledger still holds both. A conflict is a refusal to pick, not a loss.
	history, err := s.ListExampleRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListExampleRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("ledger holds %d generations after a conflict, want 2", len(history))
	}
}

// TestLedger_UnidentifiedRecordIsSupersededByAnIdentifiedOne pins the upgrade
// path. Every existing row names no artefact, and the first re-extraction of any
// module names one; without this rule every one of them would report a conflict.
func TestLedger_UnidentifiedRecordIsSupersededByAnIdentifiedOne(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")

	legacy := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "")
	// Seeded straight into the table: the write leg refuses a record naming no
	// artefact, which is exactly why such rows are legacy.
	seedPreLedgerRow(t, s.InternalDB(), legacy)

	identified := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleBeta"}, 2,
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("real-bytes=").String())
	if err := s.PutExampleRecord(ctx, identified); err != nil {
		t.Fatalf("PutExampleRecord: %v", err)
	}

	served, found, err := s.GetExampleRecord(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("GetExampleRecord: %v", err)
	}
	if !found || served.ContentHash != identified.ContentHash {
		t.Errorf("composed read serves the record naming no artefact; a measurement that says which bytes it read is the better-evidenced answer")
	}
	// The legacy row stays in the ledger; composition decides what is served, not
	// what is kept.
	history, err := s.ListExampleRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListExampleRecordsFor: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("ledger holds %d generations, want 2 — the legacy row was dropped", len(history))
	}
}

// TestLedger_IdenticalRecordWrittenTwiceIsOneRow pins that the append is
// idempotent for the same measurement, in the parent AND in the satellite. A
// retried write must not fail a run that had already succeeded, nor invent a
// second measurement, nor duplicate its index rows.
func TestLedger_IdenticalRecordWrittenTwiceIsOneRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha", "ExampleBeta"}, 0,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("same-bytes=").String())

	for range 2 {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	history, err := s.ListExampleRecordsFor(ctx, coord, ledgerPipeline)
	if err != nil {
		t.Fatalf("ListExampleRecordsFor: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("ledger holds %d rows for one measurement written twice, want 1", len(history))
	}
	if n := countIndexRows(t, s); n != 2 {
		t.Errorf("example_index holds %d rows for one measurement written twice, want 2", n)
	}
}

// TestLedger_SatelliteIsKeyedOnTheParentRecord is the half of this conversion the
// licence one did not have to do.
//
// Two generations of one coordinate must produce two DISJOINT sets of index rows,
// each resolving to exactly one parent — and a symbol lookup must return the
// composed generation's rows, not every generation's, or the ledger reintroduces
// a duplicate listing at the satellite.
func TestLedger_SatelliteIsKeyedOnTheParentRecord(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	// The partial extraction found one example and lost two files; the clean one
	// found both. Composition therefore serves the CLEAN record, which here is
	// also the newer — the older-wins case is covered by the next test.
	partial := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 2,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	clean := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha", "ExampleBeta"}, 0,
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)
	for _, r := range []domain2.ExampleRecord{partial, clean} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	// Three index rows in total: one for the partial generation, two for the
	// clean one. They are disjoint because they carry different parent hashes.
	if n := countIndexRows(t, s); n != 3 {
		t.Errorf("example_index holds %d rows across two generations, want 3 — children collided across generations", n)
	}
	byParent := indexRowsByParent(t, s)
	if got := byParent[partial.ContentHash]; got != 1 {
		t.Errorf("the partial generation owns %d index rows, want 1", got)
	}
	if got := byParent[clean.ContentHash]; got != 2 {
		t.Errorf("the clean generation owns %d index rows, want 2", got)
	}
	// No child is orphaned: every index row names a record the ledger holds.
	var orphans int
	if err := s.InternalDB().DB().QueryRow(`SELECT count(*) FROM example_index i
        WHERE NOT EXISTS (SELECT 1 FROM example_records r WHERE r.content_hash = i.record_content_hash)`).
		Scan(&orphans); err != nil {
		t.Fatalf("counting orphans: %v", err)
	}
	if orphans != 0 {
		t.Errorf("%d index rows name no record in the ledger", orphans)
	}

	// A symbol present in BOTH generations must come back once, from the served
	// generation. Returning it twice is the duplicate listing at the satellite.
	refs, err := s.FindBySymbolInModule(ctx, coord, "Alpha", ledgerPipeline)
	if err != nil {
		t.Fatalf("FindBySymbolInModule: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("FindBySymbolInModule returned %d refs for a symbol in two generations, want 1", len(refs))
	}
	// A symbol present only in the served generation is still found.
	refs, err = s.FindBySymbol(ctx, "Beta", ledgerPipeline, coordinate.ModuleSet{})
	if err != nil {
		t.Fatalf("FindBySymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("FindBySymbol returned %d refs for a symbol only the served generation has, want 1", len(refs))
	}
}

// TestLedger_SymbolLookupFollowsTheComposedParentNotTheNewest is the sharpest
// consequence of the ladder. Composition can serve an OLDER parent than the
// newest, so taking the newest rows for the coordinate would let a degraded
// extraction's examples be read as though they were the served answer's.
func TestLedger_SymbolLookupFollowsTheComposedParentNotTheNewest(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	clean := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha", "ExampleBeta"}, 0,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact)
	degraded := ledgerRecord(t, coord, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 5,
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact)
	for _, r := range []domain2.ExampleRecord{clean, degraded} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	// Beta exists only in the older, cleaner generation — the one composition
	// serves. Resolving children from the newest parent would lose it.
	refs, err := s.FindBySymbol(ctx, "Beta", ledgerPipeline, coordinate.ModuleSet{})
	if err != nil {
		t.Fatalf("FindBySymbol: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("FindBySymbol returned %d refs for a symbol in the served generation, want 1 — children were taken from the newest parent", len(refs))
	}
	if refs[0].ExampleName != "ExampleBeta" {
		t.Errorf("FindBySymbol returned %q, want ExampleBeta", refs[0].ExampleName)
	}
}

// TestLedger_ListCollapsesGenerations pins that the ledger does not reintroduce a
// duplicate listing. An operator reading examples-list must not see a
// re-extracted module twice and have no way to tell that from two modules.
func TestLedger_ListCollapsesGenerations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	artefact := fetchtest.ZipArtefact("same-bytes=").String()

	a := mustCoord(t, "example.com/a", "v1.0.0")
	b := mustCoord(t, "example.com/b", "v1.0.0")
	for _, r := range []domain2.ExampleRecord{
		ledgerRecord(t, a, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 4,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, a, domain2.ExampleStatusFound, []string{"ExampleAlpha", "ExampleBeta"}, 0,
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), artefact),
		ledgerRecord(t, b, domain2.ExampleStatusFound, []string{"ExampleGamma"}, 0,
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), artefact),
	} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	sums, err := s.ListExampleRecords(ctx, ports.ExampleFilter{})
	if err != nil {
		t.Fatalf("ListExampleRecords: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("examples list returned %d rows for 2 modules holding 3 generations", len(sums))
	}
	byModule := map[string]int{}
	for _, sum := range sums {
		byModule[sum.ModulePath] = sum.ExampleCount
	}
	// The collapsed summary must be the SERVED generation, not whichever row the
	// database happened to return first.
	if byModule["example.com/a"] != 2 {
		t.Errorf("module a lists %d examples, want the composed answer's 2", byModule["example.com/a"])
	}
	if byModule["example.com/b"] != 1 {
		t.Errorf("module b lists %d examples, want 1", byModule["example.com/b"])
	}

	// Limit counts modules, not rows: a module with two generations must not
	// consume two places of the caller's page.
	page, err := s.ListExampleRecords(ctx, ports.ExampleFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListExampleRecords with a limit: %v", err)
	}
	if len(page) != 1 {
		t.Errorf("limit 1 returned %d rows, want 1", len(page))
	}
}

// TestLedger_ConflictIsReportedOnItsRowNotAsTheListsError pins that one module in
// dispute does not delete the answers for every other module.
func TestLedger_ConflictIsReportedOnItsRowNotAsTheListsError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	disputed := mustCoord(t, "example.com/disputed", "v1.0.0")
	fine := mustCoord(t, "example.com/fine", "v1.0.0")
	for _, r := range []domain2.ExampleRecord{
		ledgerRecord(t, disputed, domain2.ExampleStatusFound, []string{"ExampleAlpha"}, 0,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-one=").String()),
		ledgerRecord(t, disputed, domain2.ExampleStatusFound, []string{"ExampleBeta"}, 0,
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-two=").String()),
		ledgerRecord(t, fine, domain2.ExampleStatusFound, []string{"ExampleGamma"}, 0,
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-three=").String()),
	} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	sums, err := s.ListExampleRecords(ctx, ports.ExampleFilter{})
	if err != nil {
		t.Fatalf("ListExampleRecords returned an error; one disputed module took the whole list down: %v", err)
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
			if !errors.Is(sum.Conflict, ports.ErrExampleConflict) {
				t.Errorf("conflict is %v, want ErrExampleConflict", sum.Conflict)
			}
			if sum.ExampleCount != 0 {
				t.Errorf("the disputed module reports %d examples; composition refused to pick, so there is no answer to project", sum.ExampleCount)
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
// rule at the satellite. A symbol lookup spans every module in the store, so
// failing the whole query for one disputed module denies every correct answer —
// but the omission must still be reported rather than silently short.
func TestLedger_ConflictedModuleDoesNotDeleteOtherModulesSymbolAnswers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	disputed := mustCoord(t, "example.com/disputed", "v1.0.0")
	fine := mustCoord(t, "example.com/fine", "v1.0.0")
	for _, r := range []domain2.ExampleRecord{
		ledgerRecord(t, disputed, domain2.ExampleStatusFound, []string{"ExampleShared"}, 0,
			time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-one=").String()),
		ledgerRecord(t, disputed, domain2.ExampleStatusFound, []string{"ExampleShared"}, 0,
			time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-two=").String()),
		ledgerRecord(t, fine, domain2.ExampleStatusFound, []string{"ExampleShared"}, 0,
			time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("bytes-three=").String()),
	} {
		if err := s.PutExampleRecord(ctx, r); err != nil {
			t.Fatalf("PutExampleRecord: %v", err)
		}
	}

	refs, err := s.FindBySymbol(ctx, "Shared", ledgerPipeline, coordinate.ModuleSet{})
	if !errors.Is(err, ports.ErrExampleConflict) {
		t.Errorf("FindBySymbol reported %v; the omitted module is invisible", err)
	}
	if len(refs) != 1 {
		t.Fatalf("FindBySymbol returned %d refs, want 1 — one disputed module deleted the healthy module's answer", len(refs))
	}
	if refs[0].ModulePath != "example.com/fine" {
		t.Errorf("FindBySymbol returned a ref from %q, want example.com/fine", refs[0].ModulePath)
	}
}

func countIndexRows(t *testing.T, s *examplesqlite.Store) int {
	t.Helper()
	var n int
	if err := s.InternalDB().DB().QueryRow(`SELECT count(*) FROM example_index`).Scan(&n); err != nil {
		t.Fatalf("counting index rows: %v", err)
	}
	return n
}

func indexRowsByParent(t *testing.T, s *examplesqlite.Store) map[string]int {
	t.Helper()
	rows, err := s.InternalDB().DB().Query(
		`SELECT record_content_hash, count(*) FROM example_index GROUP BY 1`)
	if err != nil {
		t.Fatalf("grouping index rows: %v", err)
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
func seedPreLedgerRow(t *testing.T, db sqlitestore.DB, r domain2.ExampleRecord) {
	t.Helper()
	var h domain2.ExampleRecordHasher
	raw, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = db.DB().Exec(`INSERT INTO example_records (
        module_path, module_version, pipeline_version,
        overall_status, example_count, extracted_at, content_hash, serialised
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
		int(r.OverallStatus), len(r.Examples),
		r.ExtractedAt.UTC().Format(time.RFC3339), r.ContentHash, blobcodec.Encode(raw))
	if err != nil {
		t.Fatalf("seeding legacy row for %s: %v", r.Coordinate, err)
	}
}

// TestMigration3_CarriesRowsInAndRekeysTheSatellite is the epic's acceptance
// shape plus the one licence did not have to meet: the first generation carries
// in unpurged, every carried-in record still verifies, and every index row is
// rekeyed onto its parent record with none orphaned and none duplicated.
func TestMigration3_CarriesRowsInAndRekeysTheSatellite(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "mirror.db")
	all := examplesqlite.Migrations()

	// Open at migration 2: the schema as it stood before the ledger. Seeding
	// through the store instead is impossible — its code is always at HEAD, so
	// its append already names the ledger key migration 3 has not created yet.
	pre, err := sqlitestore.Open(dsn, all[:2], sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at migration 2: %v", err)
	}
	identified := mustCoord(t, "example.com/a", "v1.0.0")
	legacy := mustCoord(t, "example.com/b", "v2.0.0")
	coords := []coordinate.ModuleCoordinate{identified, legacy}
	want := map[string]string{}  // coordinate -> content hash
	wantKids := map[string]int{} // content hash -> index rows

	// One row of each shape the maintainer's store actually holds: measured
	// read-only before this change, 177 of 1,847 rows carry a real zip identity
	// in their blob and 1,670 predate the field and carry none.
	withID := ledgerRecord(t, identified, domain2.ExampleStatusFound,
		[]string{"ExampleAlpha", "ExampleBeta"}, 0,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), fetchtest.ZipArtefact("carried-in=").String())
	seedPreLedgerRow(t, pre, withID)
	seedPreLedgerIndex(t, pre, withID)
	want[identified.String()] = withID.ContentHash
	wantKids[withID.ContentHash] = 2

	noID := ledgerRecord(t, legacy, domain2.ExampleStatusFound,
		[]string{"ExampleGamma"}, 0, time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC), "")
	seedPreLedgerRow(t, pre, noID)
	seedPreLedgerIndex(t, pre, noID)
	want[legacy.String()] = noID.ContentHash
	wantKids[noID.ContentHash] = 1

	if err := pre.Close(); err != nil {
		t.Fatalf("closing at migration 2: %v", err)
	}

	store, err := examplesqlite.Open(dsn)
	if err != nil {
		t.Fatalf("migrating to head: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	var total int
	if err := store.InternalDB().DB().QueryRow(`SELECT count(*) FROM example_records`).Scan(&total); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if total != len(coords) {
		t.Errorf("ledger holds %d rows after the conversion, want %d — rows were purged", total, len(coords))
	}

	// Readable through the store's own path, which is what verifies the hash.
	// Counting rows would pass on a table full of records nobody can check.
	for _, c := range coords {
		got, found, gerr := store.GetExampleRecord(context.Background(), c, ledgerPipeline)
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

	// The satellite: every child rekeyed onto its parent, none orphaned, none
	// duplicated.
	gotKids := indexRowsByParent(t, store)
	if len(gotKids) != len(wantKids) {
		t.Errorf("index rows resolve to %d parents, want %d", len(gotKids), len(wantKids))
	}
	for hash, n := range wantKids {
		if gotKids[hash] != n {
			t.Errorf("record %s owns %d index rows after the rekey, want %d", hash, gotKids[hash], n)
		}
	}
	if n := countIndexRows(t, store); n != 3 {
		t.Errorf("example_index holds %d rows after the rekey, want 3 — children were lost or duplicated", n)
	}

	// And the rekeyed children resolve through the read path.
	refs, err := store.FindBySymbolInModule(context.Background(), identified, "Beta", ledgerPipeline)
	if err != nil {
		t.Fatalf("FindBySymbolInModule after the rekey: %v", err)
	}
	if len(refs) != 1 {
		t.Errorf("FindBySymbolInModule returned %d refs after the rekey, want 1", len(refs))
	}
}

// seedPreLedgerIndex writes a record's index rows in the pre-rekey shape: keyed
// on the coordinate, with no reference to the parent record at all.
func seedPreLedgerIndex(t *testing.T, db sqlitestore.DB, r domain2.ExampleRecord) {
	t.Helper()
	for _, e := range r.Examples {
		validates := 0
		if e.Validates {
			validates = 1
		}
		if _, err := db.DB().Exec(`INSERT INTO example_index (
            module_path, module_version, pipeline_version,
            package_path, associated_symbol, example_name, validates
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			r.Coordinate.Path(), r.Coordinate.Version(), r.PipelineVersion,
			e.Package, e.AssociatedSymbol, e.Name, validates); err != nil {
			t.Fatalf("seeding legacy index row %s: %v", e.Name, err)
		}
	}
}
