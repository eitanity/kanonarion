package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The dates the analyser pin history turns on, and the versions either side of
// them. They are restated here rather than imported so a change to the history
// has to be made twice, deliberately, instead of a test tracking a store's
// mistake.
const (
	analyserPinBefore = "2026-07-05" // v0.47.0 from here
	analyserPinLater  = "2026-08-15" // v0.49.0 from here
)

// datedRecord is a minimal record at a chosen coordinate and extraction time.
func datedRecord(t *testing.T, path, version, pipelineVersion string, at time.Time) domain2.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	r := domain2.CallGraphRecord{
		SchemaVersion:    domain2.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		Algorithm:        domain2.AlgorithmCHA,
		OverallStatus:    domain2.CallGraphStatusExtracted,
		Completeness:     domain2.CompletenessBuiltWithBodies,
		ExtractedAt:      at,
		PipelineVersion:  pipelineVersion,
		AnalysisSource:   domain2.AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:" + path + "@" + version,
		Nodes: []domain2.CallNode{{
			ID: path + ".Foo", Module: path, Package: path, Symbol: "Foo", IsExportedAPI: true,
		}},
		NodeCount: 1,
	}
	var h domain2.CallGraphRecordHasher
	hashed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return hashed
}

func mustParseDay(t *testing.T, day string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, day+"T12:00:00Z")
	if err != nil {
		t.Fatalf("parsing %q: %v", day, err)
	}
	return at
}

// TestAnalyserColumn_WriteLegRecordsWhatTheRecordStates pins that the store
// writes the identity the record carries, and never invents one.
func TestAnalyserColumn_WriteLegRecordsWhatTheRecordStates(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	stated := makeRecord(testCoord, "0.1.0")
	stated.Analyser = domain2.ObservedAnalyser("v0.49.0")
	if err := s.PutCallGraphRecord(ctx, stated); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	columns, err := s.AnalyserColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("AnalyserColumnsForTest: %v", err)
	}
	if got := columns[stated.ContentHash]; got != "observed:v0.49.0" {
		t.Errorf("analyser column = %q, want %q", got, "observed:v0.49.0")
	}

	got, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: %v (found=%v)", err, found)
	}
	if got.Analyser != domain2.ObservedAnalyser("v0.49.0") {
		t.Errorf("read back %+v, want an observed v0.49.0", got.Analyser)
	}
	if got.Analyser.IsInferred() {
		t.Error("a version the extracting binary named came back as inferred")
	}
}

// TestAnalyserColumn_UnstatedStaysUnstated pins the other half of the write
// leg. A binary that could not read its own build info states nothing, and the
// store must record that rather than reaching for the back-fill's inference:
// the inference exists for rows written before the axis, not for a row written
// now by a producer that declined to say.
func TestAnalyserColumn_UnstatedStaysUnstated(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	columns, err := s.AnalyserColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("AnalyserColumnsForTest: %v", err)
	}
	if got := columns[rec.ContentHash]; got != "" {
		t.Errorf("analyser column = %q, want the empty column", got)
	}
	got, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: %v (found=%v)", err, found)
	}
	if got.Analyser.Recorded() {
		t.Errorf("read back %+v, want the zero identity", got.Analyser)
	}
}

// TestAnalyserColumn_MalformedStopsTheRead pins that a column value no reader
// understands is an error rather than an absence. Only two things write this
// column and both write a provenance; a third value is a hand-edited row, and
// reading it as "not recorded" would silently drop a claim the store carries.
func TestAnalyserColumn_MalformedStopsTheRead(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if err := s.SetAnalyserColumnForTest(ctx, rec.ContentHash, "v0.49.0"); err != nil {
		t.Fatalf("SetAnalyserColumnForTest: %v", err)
	}

	_, _, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if !errors.Is(err, domain2.ErrMalformedAnalyserColumn) {
		t.Errorf("GetCallGraphRecord = %v, want ErrMalformedAnalyserColumn", err)
	}
}

// analyserPopulation is the shape of the store this migration meets, measured
// on the maintainer's own: 811 records serving at one pipeline version, 413
// extracted before the pin moved and 398 on or after it.
const (
	populationBefore = 413
	populationAfter  = 398
	populationTotal  = populationBefore + populationAfter
)

// seedAnalyserPopulation writes populationTotal rows the way every row written
// before migration 15 exists: an empty analyser column, spanning the date the
// pin moved.
func seedAnalyserPopulation(t *testing.T, s *sqlite.Store) []domain2.CallGraphRecord {
	t.Helper()
	ctx := context.Background()
	before, after := mustParseDay(t, analyserPinBefore), mustParseDay(t, analyserPinLater)

	seeded := make([]domain2.CallGraphRecord, 0, populationTotal)
	for i := range populationTotal {
		at := before
		if i >= populationBefore {
			at = after
		}
		r := datedRecord(t, fmt.Sprintf("example.com/m%03d", i), "v1.0.0", "0.5.0", at)
		if err := s.SeedDatedRowForTest(ctx, r); err != nil {
			t.Fatalf("SeedDatedRowForTest: %v", err)
		}
		seeded = append(seeded, r)
	}
	return seeded
}

// TestBackfillAnalyser_IsABackfillNotAPurge is the migration control.
//
// It states rows in and rows out, and it checks the one thing a fact outside the
// seal must never disturb: every row's content_hash is exactly what it was. The
// column is not part of the canonical encoding, so a record's integrity check is
// the same computation after the migration as before it — and this is what makes
// that a measurement rather than a claim in a comment.
func TestBackfillAnalyser_IsABackfillNotAPurge(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	seeded := seedAnalyserPopulation(t, s)

	before, err := s.AnalyserColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("AnalyserColumnsForTest: %v", err)
	}
	if len(before) != populationTotal {
		t.Fatalf("rows in = %d, want %d", len(before), populationTotal)
	}
	for hash, value := range before {
		if value != "" {
			t.Fatalf("row %s already states %q before the back-fill", hash, value)
		}
	}

	if err := s.BackfillAnalyserForTest(ctx); err != nil {
		t.Fatalf("BackfillAnalyserForTest: %v", err)
	}

	after, err := s.AnalyserColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("AnalyserColumnsForTest: %v", err)
	}
	if len(after) != populationTotal {
		t.Errorf("rows out = %d, want %d — a back-fill removes nothing", len(after), populationTotal)
	}
	// Addressed by content hash: a row that survived under a different hash would
	// be a rewritten record, which is the outcome the seal exists to prevent.
	for i, r := range seeded {
		value, present := after[r.ContentHash]
		if !present {
			t.Fatalf("record %s is gone, or its content_hash moved", r.ContentHash)
		}
		want := "inferred:v0.47.0"
		if i >= populationBefore {
			want = "inferred:v0.49.0"
		}
		if value != want {
			t.Errorf("record %d (%s) attributed %q, want %q", i, r.ExtractedAt.Format(time.DateOnly), value, want)
		}
	}
}

// TestBackfillAnalyser_WritesNothingObserved is decision 3 measured at the
// store. Every value the back-fill writes is reconstructed from a date, and a
// reader must be able to see that on every one of them.
func TestBackfillAnalyser_WritesNothingObserved(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	seedAnalyserPopulation(t, s)

	if err := s.BackfillAnalyserForTest(ctx); err != nil {
		t.Fatalf("BackfillAnalyserForTest: %v", err)
	}
	columns, err := s.AnalyserColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("AnalyserColumnsForTest: %v", err)
	}
	observed := domain2.ObservedAnalyser("v0.49.0")
	for hash, value := range columns {
		id, perr := domain2.ParseAnalyserColumn(value)
		if perr != nil {
			t.Fatalf("row %s holds an unreadable value %q: %v", hash, value, perr)
		}
		if !id.IsInferred() {
			t.Errorf("row %s was back-filled as %q, which is not an inferred value", hash, value)
		}
		if id.String() == observed.String() {
			t.Errorf("row %s renders identically to an observed value: %q", hash, id.String())
		}
	}
}

// TestBackfillAnalyser_LeavesWhatItCannotAttribute pins walk migration 9's rule
// on the two rows this back-fill cannot speak for.
//
// A row already stating an analyser is not re-attributed: an observed value must
// never be overwritten by a guess. A row extracted before the pin history begins
// is left empty: there is no version to infer, and inventing one would be the
// fabrication the whole axis exists to stop.
func TestBackfillAnalyser_LeavesWhatItCannotAttribute(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	observed := datedRecord(t, "example.com/observed", "v1.0.0", "0.5.0", mustParseDay(t, analyserPinBefore))
	observed.Analyser = domain2.ObservedAnalyser("v0.49.0")
	if err := s.PutCallGraphRecord(ctx, observed); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	// A day before the line first appeared in this repository's go.mod.
	ancient := datedRecord(t, "example.com/ancient", "v1.0.0", "0.5.0", mustParseDay(t, "2026-07-04"))
	if err := s.SeedDatedRowForTest(ctx, ancient); err != nil {
		t.Fatalf("SeedDatedRowForTest: %v", err)
	}

	if err := s.BackfillAnalyserForTest(ctx); err != nil {
		t.Fatalf("BackfillAnalyserForTest: %v", err)
	}
	columns, err := s.AnalyserColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("AnalyserColumnsForTest: %v", err)
	}
	// Presence is asserted before the value on both rows. A map lookup returns the
	// empty string for a row that is GONE, so "left at the empty column" and
	// "deleted by the migration" would otherwise read identically here — and the
	// second is the outcome a back-fill must never produce.
	if got, present := columns[observed.ContentHash]; !present || got != "observed:v0.49.0" {
		t.Errorf("an observed row is %q (present=%v) — a guess overwrote or removed a measurement", got, present)
	}
	got, present := columns[ancient.ContentHash]
	if !present {
		t.Error("a row predating the pin history was removed — a back-fill deletes nothing")
	}
	if got != "" {
		t.Errorf("a row predating the pin history was attributed %q, want the empty column", got)
	}
	if len(columns) != 2 {
		t.Errorf("rows out = %d, want 2", len(columns))
	}
}

// TestBackfillAnalyser_ServedAnswerIsByteIdentical is the control decision 2
// rests on: every record servable before the migration is servable after, with
// the identical bytes.
//
// The comparison is over the CANONICAL bytes and the content hash, which is what
// "servable" means here — the record the store hands back and the seal it hands
// it back under. The analyser is deliberately not in those bytes, and this is
// where that is measured rather than asserted.
func TestBackfillAnalyser_ServedAnswerIsByteIdentical(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// One coordinate holding two generations, so the composition that picks
	// between them is exercised rather than a single-row read.
	coord, err := coordinate.NewModuleCoordinate("example.com/served", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	older := datedRecord(t, coord.Path(), coord.Version(), "0.5.0", mustParseDay(t, analyserPinBefore))
	newer := datedRecord(t, coord.Path(), coord.Version(), "0.5.0", mustParseDay(t, analyserPinLater))
	for _, r := range []domain2.CallGraphRecord{older, newer} {
		if err := s.SeedDatedRowForTest(ctx, r); err != nil {
			t.Fatalf("SeedDatedRowForTest: %v", err)
		}
	}

	var h domain2.CallGraphRecordHasher
	servedBytes := func() ([]byte, string) {
		t.Helper()
		rec, found, gerr := s.GetCallGraphRecord(ctx, coord, "0.5.0")
		if gerr != nil || !found {
			t.Fatalf("GetCallGraphRecord: %v (found=%v)", gerr, found)
		}
		data, merr := h.Marshal(rec)
		if merr != nil {
			t.Fatalf("Marshal: %v", merr)
		}
		// The seal is re-checked, not merely compared: a record whose canonical
		// bytes matched but whose hash no longer verified would be servable in name
		// only.
		if verr := h.VerifyContentHash(rec); verr != nil {
			t.Fatalf("VerifyContentHash: %v", verr)
		}
		return data, rec.ContentHash
	}

	wantBytes, wantHash := servedBytes()

	if err := s.BackfillAnalyserForTest(ctx); err != nil {
		t.Fatalf("BackfillAnalyserForTest: %v", err)
	}

	gotBytes, gotHash := servedBytes()
	if string(gotBytes) != string(wantBytes) {
		t.Errorf("the served record's canonical bytes changed:\nbefore %s\nafter  %s", wantBytes, gotBytes)
	}
	if gotHash != wantHash {
		t.Errorf("the served record's content hash changed: before %s, after %s", wantHash, gotHash)
	}
	// And the ladder's choice is untouched: the same generation answers.
	if gotHash != newer.ContentHash {
		t.Errorf("the served generation changed: got %s, want %s", gotHash, newer.ContentHash)
	}
}

// TestBackfillAnalyser_LadderIsUnchangedForAMixedCoordinate is the second half
// of that control, aimed at the coordinates the ticket counted: those holding
// generations from both sides of the pin.
//
// The analyser ranks nothing. The completeness ladder decides which generation
// answers, and a weaker generation built by a NEWER analyser must not win.
func TestBackfillAnalyser_LadderIsUnchangedForAMixedCoordinate(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	coord, err := coordinate.NewModuleCoordinate("example.com/mixed", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	// The stronger measurement is the OLDER one, built by the older analyser.
	strong := datedRecord(t, coord.Path(), coord.Version(), "0.5.0", mustParseDay(t, analyserPinBefore))
	weak := datedRecord(t, coord.Path(), coord.Version(), "0.5.0", mustParseDay(t, analyserPinLater))
	weak.Completeness = domain2.CompletenessMetadataOnly
	weak.Nodes = nil
	weak.NodeCount = 0
	var h domain2.CallGraphRecordHasher
	weak, err = h.SetContentHash(weak)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	for _, r := range []domain2.CallGraphRecord{strong, weak} {
		if err := s.SeedDatedRowForTest(ctx, r); err != nil {
			t.Fatalf("SeedDatedRowForTest: %v", err)
		}
	}

	rec, found, err := s.GetCallGraphRecord(ctx, coord, "0.5.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: %v (found=%v)", err, found)
	}
	if rec.ContentHash != strong.ContentHash {
		t.Fatalf("before the migration the ladder served %s, want %s", rec.ContentHash, strong.ContentHash)
	}

	if err := s.BackfillAnalyserForTest(ctx); err != nil {
		t.Fatalf("BackfillAnalyserForTest: %v", err)
	}

	rec, found, err = s.GetCallGraphRecord(ctx, coord, "0.5.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: %v (found=%v)", err, found)
	}
	if rec.ContentHash != strong.ContentHash {
		t.Errorf("the newer analyser won the ladder: served %s, want %s", rec.ContentHash, strong.ContentHash)
	}
	if !rec.Analyser.IsInferred() || rec.Analyser.Version != "v0.47.0" {
		t.Errorf("served record states %+v, want an inferred v0.47.0", rec.Analyser)
	}
}

// TestBackfillAnalyser_ReportsAMixedCoordinate closes decision 4 at the store:
// after the back-fill, the generations of a mixed coordinate state two analysers
// and a composed read has something to say. A coordinate whose generations agree
// has nothing.
func TestBackfillAnalyser_ReportsAMixedCoordinate(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	mixed, err := coordinate.NewModuleCoordinate("example.com/mixed", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	agreed, err := coordinate.NewModuleCoordinate("example.com/agreed", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	for _, day := range []string{analyserPinBefore, analyserPinLater} {
		r := datedRecord(t, mixed.Path(), mixed.Version(), "0.5.0", mustParseDay(t, day))
		if err := s.SeedDatedRowForTest(ctx, r); err != nil {
			t.Fatalf("SeedDatedRowForTest: %v", err)
		}
	}
	for _, at := range []time.Time{mustParseDay(t, analyserPinLater), mustParseDay(t, analyserPinLater).Add(time.Hour)} {
		r := datedRecord(t, agreed.Path(), agreed.Version(), "0.5.0", at)
		if err := s.SeedDatedRowForTest(ctx, r); err != nil {
			t.Fatalf("SeedDatedRowForTest: %v", err)
		}
	}
	if err := s.BackfillAnalyserForTest(ctx); err != nil {
		t.Fatalf("BackfillAnalyserForTest: %v", err)
	}

	for _, tc := range []struct {
		coord coordinate.ModuleCoordinate
		want  bool
	}{{mixed, true}, {agreed, false}} {
		recs, lerr := s.ListCallGraphRecordsFor(ctx, tc.coord, "0.5.0")
		if lerr != nil {
			t.Fatalf("ListCallGraphRecordsFor(%s): %v", tc.coord, lerr)
		}
		served, found, gerr := s.GetCallGraphRecord(ctx, tc.coord, "0.5.0")
		if gerr != nil || !found {
			t.Fatalf("GetCallGraphRecord(%s): %v (found=%v)", tc.coord, gerr, found)
		}
		if _, got := domain2.AnalyserDisagreementAmong(recs, served); got != tc.want {
			t.Errorf("%s: disagreement reported = %v, want %v", tc.coord, got, tc.want)
		}
	}
}
