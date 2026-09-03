package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// nestedLoader is the shape the store actually holds: a record about a parent
// module that also built a separately published module nested under its path.
var nestedLoader = domain2.ForeignModule{Path: "example.com/mod/nested", Version: "v0.5.1"}

// foreignControlCoord is the zero-paired control's coordinate: a second module
// in the same store whose record names no foreign module at all.
var foreignControlCoord, _ = coordinate.NewModuleCoordinate("example.com/other", "v2.0.0")

// TestForeignModulesColumn_WriteLegCopiesWhatTheRecordStates: the column is a
// derived copy of the sealed blob, written in the same transaction, so a row
// whose column disagrees with its own record is the defect migration 9 exists
// because of — on a new field.
func TestForeignModulesColumn_WriteLegCopiesWhatTheRecordStates(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	rec := makeRecord(testCoord, "0.1.0")
	rec.ForeignModulesBuilt = []domain2.ForeignModule{nestedLoader}
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, sealed); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	columns, err := s.ForeignModulesColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("ForeignModulesColumnsForTest: %v", err)
	}
	if got, want := columns[sealed.ContentHash], "example.com/mod/nested@v0.5.1"; got != want {
		t.Errorf("foreign_modules_built column = %q, want %q", got, want)
	}

	// And the seal is untouched by the denormalisation: the record still verifies
	// against the hash it was written with.
	back, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: %v (found=%v)", err, found)
	}
	if len(back.ForeignModulesBuilt) != 1 || back.ForeignModulesBuilt[0] != nestedLoader {
		t.Errorf("record read back states %+v, want %+v", back.ForeignModulesBuilt, nestedLoader)
	}
	if back.ContentHash != sealed.ContentHash {
		t.Errorf("content hash moved: stored %q, read %q", sealed.ContentHash, back.ContentHash)
	}
}

// TestForeignModulesBuilt_IsReadFromTheColumnNotTheRecord is the read the column
// exists for. The edge table is hidden and the blobs are corrupted, so anything
// that decodes a record or reconstructs its edges fails loudly — which is what
// makes "this read decodes nothing" something a test can establish rather than
// time.
func TestForeignModulesBuilt_IsReadFromTheColumnNotTheRecord(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	rec := makeRecord(testCoord, "0.1.0")
	rec.ForeignModulesBuilt = []domain2.ForeignModule{nestedLoader}
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, sealed); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if err := s.CorruptSerialisedBlobsForTest(ctx); err != nil {
		t.Fatalf("CorruptSerialisedBlobsForTest: %v", err)
	}
	if err := s.HideEdgeTableForTest(ctx); err != nil {
		t.Fatalf("HideEdgeTableForTest: %v", err)
	}

	mods, found, err := s.ForeignModulesBuilt(ctx, testCoord, "0.1.0", gotoolchain.Version(""))
	if err != nil {
		t.Fatalf("ForeignModulesBuilt read a record: %v", err)
	}
	if !found {
		t.Fatal("the served coordinate reported no row")
	}
	if len(mods) != 1 || mods[0] != nestedLoader {
		t.Errorf("ForeignModulesBuilt = %+v, want %+v", mods, nestedLoader)
	}
}

// TestForeignModulesBuilt_UnknownCoordinateIsNotAnEmptySet: nothing was
// consulted, so nothing is claimed. A caller that read false as "built none"
// would qualify an answer on a record it never saw.
func TestForeignModulesBuilt_UnknownCoordinateIsNotAnEmptySet(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	mods, found, err := s.ForeignModulesBuilt(ctx, testCoord, "0.1.0", gotoolchain.Version(""))
	if err != nil {
		t.Fatalf("ForeignModulesBuilt: %v", err)
	}
	if found {
		t.Error("a coordinate the ledger does not hold reported a served row")
	}
	if mods != nil {
		t.Errorf("an unconsulted coordinate returned %+v, want nil", mods)
	}
}

// TestForeignModulesBuilt_RefusesAColumnItCannotRead: only the write leg and the
// back-fill write this column. A value neither produced is a hand-edited row, and
// reading it as "no foreign modules" would drop a qualification the store is
// carrying.
func TestForeignModulesBuilt_RefusesAColumnItCannotRead(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if err := s.SetForeignModulesColumnForTest(ctx, rec.ContentHash, "not-a-pair"); err != nil {
		t.Fatalf("SetForeignModulesColumnForTest: %v", err)
	}

	_, _, err := s.ForeignModulesBuilt(ctx, testCoord, "0.1.0", gotoolchain.Version(""))
	if err == nil {
		t.Fatal("an unreadable column was served as an answer")
	}
	if !errors.Is(err, domain2.ErrMalformedForeignModulesColumn) {
		t.Errorf("error = %v, want ErrMalformedForeignModulesColumn", err)
	}
}

// TestBackfillForeignModulesBuilt_ReadsEveryRowsOwnBlob is migration 16's Go
// step. Every row is visited, not only the ones that hold something: the empty
// column means the empty SET, and it only means that because this pass decided
// it from the record rather than leaving a DEFAULT unexamined.
func TestBackfillForeignModulesBuilt_ReadsEveryRowsOwnBlob(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	var h domain2.CallGraphRecordHasher
	holds := makeRecord(testCoord, "0.1.0")
	holds.ForeignModulesBuilt = []domain2.ForeignModule{
		nestedLoader,
		// Resolution named no version: the pair still renders, with nothing after
		// the "@", so the reader gets an empty version rather than no entry.
		{Path: "example.com/mod/replaced"},
	}
	holds, err := h.SetContentHash(holds)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, holds); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	// The zero-paired control, and the population the back-fill mostly meets: a
	// record naming no foreign module at all.
	none := makeRecord(foreignControlCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, none); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	// Put the store back into the state the ALTER TABLE leaves it in.
	if err := s.ClearForeignModulesColumnForTest(ctx); err != nil {
		t.Fatalf("ClearForeignModulesColumnForTest: %v", err)
	}
	if err := s.BackfillForeignModulesBuiltForTest(ctx); err != nil {
		t.Fatalf("BackfillForeignModulesBuiltForTest: %v", err)
	}

	columns, err := s.ForeignModulesColumnsForTest(ctx)
	if err != nil {
		t.Fatalf("ForeignModulesColumnsForTest: %v", err)
	}
	want := "example.com/mod/nested@v0.5.1 example.com/mod/replaced@"
	if got := columns[holds.ContentHash]; got != want {
		t.Errorf("back-filled column = %q, want %q", got, want)
	}
	if got := columns[none.ContentHash]; got != "" {
		t.Errorf("a record naming no foreign module back-filled to %q, want the empty string", got)
	}

	// The back-fill wrote a column and touched nothing else: every record still
	// verifies against the hash it was sealed with.
	for _, tc := range []struct {
		coord coordinate.ModuleCoordinate
		hash  string
	}{{testCoord, holds.ContentHash}, {foreignControlCoord, none.ContentHash}} {
		rec, found, gerr := s.GetCallGraphRecord(ctx, tc.coord, "0.1.0")
		if gerr != nil || !found {
			t.Fatalf("GetCallGraphRecord(%s): %v (found=%v)", tc.coord, gerr, found)
		}
		if rec.ContentHash != tc.hash {
			t.Errorf("%s: content hash moved from %q to %q", tc.coord, tc.hash, rec.ContentHash)
		}
	}
}

// TestForeignModulesBuilt_AgreeingGenerationsDecodeNothing is the short-circuit
// that makes the column worth having on the coordinates it matters for.
//
// A coordinate with many generations — the local working tree, one per ingest —
// would otherwise pay a composition to decide WHICH generation answers before its
// column could be read, and a composition decodes every generation. When all of
// them state the same set, whichever one composition would serve states that set,
// so the answer is known without deciding. The blobs are corrupted and the edge
// table hidden, so any decode fails loudly rather than merely costing time.
func TestForeignModulesBuilt_AgreeingGenerationsDecodeNothing(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	var h domain2.CallGraphRecordHasher
	for _, at := range []string{"2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z"} {
		when, perr := time.Parse(time.RFC3339, at)
		if perr != nil {
			t.Fatalf("parsing %q: %v", at, perr)
		}
		gen := makeRecord(testCoord, "0.1.0")
		gen.ExtractedAt = when
		gen.ForeignModulesBuilt = []domain2.ForeignModule{nestedLoader}
		sealed, serr := h.SetContentHash(gen)
		if serr != nil {
			t.Fatalf("SetContentHash: %v", serr)
		}
		if perr := s.PutCallGraphRecord(ctx, sealed); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}
	if err := s.CorruptSerialisedBlobsForTest(ctx); err != nil {
		t.Fatalf("CorruptSerialisedBlobsForTest: %v", err)
	}
	if err := s.HideEdgeTableForTest(ctx); err != nil {
		t.Fatalf("HideEdgeTableForTest: %v", err)
	}

	mods, found, err := s.ForeignModulesBuilt(ctx, testCoord, "0.1.0", gotoolchain.Version(""))
	if err != nil {
		t.Fatalf("three agreeing generations still decoded a record: %v", err)
	}
	if !found || len(mods) != 1 || mods[0] != nestedLoader {
		t.Errorf("ForeignModulesBuilt = %+v (found=%v), want %+v", mods, found, nestedLoader)
	}
}

// TestForeignModulesBuilt_DisagreeingGenerationsAskComposition is the other half:
// when the generations were built over genuinely different foreign modules, which
// one answers decides the set, and that is composition's question. Reading any
// generation's column would qualify the answer against a record that did not
// produce it.
func TestForeignModulesBuilt_DisagreeingGenerationsAskComposition(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	var h domain2.CallGraphRecordHasher
	older := makeRecord(testCoord, "0.1.0")
	older.ExtractedAt = testTime.Add(-24 * time.Hour)
	older.ForeignModulesBuilt = []domain2.ForeignModule{{Path: "example.com/mod/nested", Version: "v0.1.0"}}
	older, err := h.SetContentHash(older)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	newer := makeRecord(testCoord, "0.1.0")
	newer.ForeignModulesBuilt = []domain2.ForeignModule{nestedLoader}
	newer, err = h.SetContentHash(newer)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	for _, r := range []domain2.CallGraphRecord{older, newer} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	mods, found, err := s.ForeignModulesBuilt(ctx, testCoord, "0.1.0", gotoolchain.Version(""))
	if err != nil {
		t.Fatalf("ForeignModulesBuilt: %v", err)
	}
	if !found {
		t.Fatal("the coordinate reported no served row")
	}
	// Composition serves the newer of two records at equal completeness, so the
	// set is that record's — not the older one's, and not a union of both.
	if len(mods) != 1 || mods[0] != nestedLoader {
		t.Errorf("ForeignModulesBuilt = %+v, want the served generation's %+v", mods, nestedLoader)
	}
}
