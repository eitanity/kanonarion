package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

const testPipeline = "0.3.0"

// ledgerSpec describes one generation to append during a ledger test.
type ledgerSpec struct {
	coord        coordinate.ModuleCoordinate
	source       domain2.AnalysisSource
	completeness domain2.CompletenessLevel
	artefact     string
	worktree     string
	at           time.Time
	// callee varies the edge set, which is what makes two generations hold
	// different satellite rows.
	callee string
	status domain2.CallGraphStatus
}

func ledgerRecord(t *testing.T, spec ledgerSpec) domain2.CallGraphRecord {
	t.Helper()
	coord := spec.coord
	if coord.IsZero() {
		coord = testCoord
	}
	at := spec.at
	if at.IsZero() {
		at = testTime
	}
	callee := spec.callee
	if callee == "" {
		callee = "example.com/mod.Bar"
	}
	status := spec.status
	if status == domain2.CallGraphStatusUnknown {
		status = domain2.CallGraphStatusExtracted
	}
	r := domain2.CallGraphRecord{
		SchemaVersion:  domain2.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Coordinate:     coord,
		Algorithm:      domain2.AlgorithmCHA,
		Completeness:   spec.completeness,
		AnalysisSource: spec.source,
		Nodes: []domain2.CallNode{
			{ID: "example.com/mod.Foo", Package: "example.com/mod", Symbol: "Foo"},
		},
		Edges: []domain2.CallEdge{
			{
				FromID:     "example.com/mod.Foo",
				ToID:       callee,
				CallSite:   domain2.SourcePosition{File: "foo.go", Line: 10},
				Confidence: domain2.ConfidenceDirect,
			},
		},
		OverallStatus:    status,
		NodeCount:        1,
		EdgeCount:        1,
		ExtractedAt:      at,
		PipelineVersion:  testPipeline,
		ArtefactIdentity: spec.artefact,
		WorktreeDigest:   spec.worktree,
	}
	r.Sort()
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

func countRows(t *testing.T, s *sqlite.Store, q string) int {
	t.Helper()
	var n int
	if err := s.InternalDB().DB().QueryRowContext(context.Background(), q).Scan(&n); err != nil {
		t.Fatalf("counting rows (%s): %v", q, err)
	}
	return n
}

// TestLedger_ReAnalysisAppendsAndBothSurvive is the ticket's observable: re-analyse
// one artefact twice and both records, and both edge sets, persist.
//
// Before the conversion the second write overwrote the first and deleted its
// edges, so there was nothing to compare and no way to see that a re-analysis had
// happened at all.
func TestLedger_ReAnalysisAppendsAndBothSurvive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime, callee: "example.com/mod.Bar",
	})
	second := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime.Add(time.Hour), callee: "example.com/mod.Baz",
	})
	for _, r := range []domain2.CallGraphRecord{first, second} {
		if err := s.PutCallGraphRecord(ctx, r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}

	if n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_records`); n != 2 {
		t.Fatalf("callgraph_records holds %d rows, want 2 — the second analysis overwrote the first", n)
	}
	// Two parents, one edge each. The old store deleted the previous generation's
	// edges on every write.
	if n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_edges`); n != 2 {
		t.Fatalf("callgraph_edges holds %d rows, want 2", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_edges e
		WHERE NOT EXISTS (SELECT 1 FROM callgraph_records r WHERE r.content_hash = e.record_content_hash)`); n != 0 {
		t.Fatalf("%d orphaned edge rows", n)
	}

	gens, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipeline)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(gens) != 2 {
		t.Fatalf("history returned %d generations, want 2", len(gens))
	}
	// Each generation resolves to ITS OWN edges. A coordinate-keyed edge fetch
	// would hand both records the union, and the hash verification over the
	// reconstructed record would then fail on a record nothing had tampered with.
	if len(gens[0].Edges) != 1 || gens[0].Edges[0].ToID != "example.com/mod.Bar" {
		t.Errorf("first generation resolved the wrong edges: %+v", gens[0].Edges)
	}
	if len(gens[1].Edges) != 1 || gens[1].Edges[0].ToID != "example.com/mod.Baz" {
		t.Errorf("second generation resolved the wrong edges: %+v", gens[1].Edges)
	}
}

// TestLedger_WritingTheSameRecordTwiceIsANoOp: one measurement written twice is
// still one measurement, and must not fail a run that had already succeeded.
func TestLedger_WritingTheSameRecordTwiceIsANoOp(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	for i := range 2 {
		if err := s.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_records`); n != 1 {
		t.Fatalf("callgraph_records holds %d rows, want 1", n)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_edges`); n != 1 {
		t.Fatalf("callgraph_edges holds %d rows, want 1", n)
	}
}

// TestLedger_ComposedReadServesTheBuiltGraph is the ledger conversion's
// acceptance observable: BUILT_WITH_BODIES versus METADATA_ONLY, the two levels
// production actually writes.
//
// The metadata-only record is written LAST, so a store that served the newest
// generation would return it.
func TestLedger_ComposedReadServesTheBuiltGraph(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	built := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime, callee: "example.com/mod.Built",
	})
	metadata := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessMetadataOnly,
		at:           testTime.Add(time.Hour), callee: "example.com/mod.Sparse",
		status: domain2.CallGraphStatusLoadFailed,
	})
	for _, r := range []domain2.CallGraphRecord{built, metadata} {
		if err := s.PutCallGraphRecord(ctx, r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}

	got, found, err := s.GetCallGraphRecord(ctx, testCoord, testPipeline)
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: found=%v err=%v", found, err)
	}
	if got.ContentHash != built.ContentHash {
		t.Fatal("the composed read served the METADATA_ONLY graph written last")
	}

	// The weaker record remains retrievable as the earlier, less complete
	// measurement rather than being overwritten by, or displacing, its better.
	gens, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipeline)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(gens) != 2 {
		t.Fatalf("history returned %d generations, want 2", len(gens))
	}
}

// TestLedger_EdgeQueriesAnswerFromTheServedGeneration is the read half of the
// satellite rekey.
//
// Without it a module holding two generations returns each edge once per
// generation, and — worse — a METADATA_ONLY analysis's edges are indistinguishable
// from a BUILT_WITH_BODIES one's, which is the distinction the whole ladder is
// built on.
func TestLedger_EdgeQueriesAnswerFromTheServedGeneration(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	built := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime, callee: "example.com/mod.Built",
	})
	metadata := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessMetadataOnly,
		at:           testTime.Add(time.Hour), callee: "example.com/mod.Sparse",
		status: domain2.CallGraphStatusLoadFailed,
	})
	for _, r := range []domain2.CallGraphRecord{built, metadata} {
		if err := s.PutCallGraphRecord(ctx, r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}

	callees, err := s.FindCallees(ctx, "example.com/mod.Foo", testPipeline, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallees: %v", err)
	}
	if len(callees) != 1 {
		t.Fatalf("FindCallees returned %d edges, want 1 — the query spans generations", len(callees))
	}
	if callees[0].ToID != "example.com/mod.Built" {
		t.Fatalf("FindCallees answered from the METADATA_ONLY generation: %s", callees[0].ToID)
	}

	callers, err := s.FindCallers(ctx, "example.com/mod.Built", testPipeline, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(callers) != 1 {
		t.Fatalf("FindCallers returned %d edges, want 1", len(callers))
	}
	// The superseded generation's callee is still IN the table — nothing was
	// deleted — but it is not an answer.
	sparse, err := s.FindCallers(ctx, "example.com/mod.Sparse", testPipeline, coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallers(sparse): %v", err)
	}
	if len(sparse) != 0 {
		t.Fatalf("an edge from a superseded generation answered a query: %+v", sparse)
	}
}

// TestLedger_ListReportsEachModuleOnce: the ledger holds a row per analysis, so
// listing rows would show a re-analysed module once per generation and an
// operator could not tell a second generation from a second module.
func TestLedger_ListReportsEachModuleOnce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for i := range 3 {
		rec := ledgerRecord(t, ledgerSpec{
			source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
			completeness: domain2.CompletenessBuiltWithBodies,
			at:           testTime.Add(time.Duration(i) * time.Hour),
		})
		if err := s.PutCallGraphRecord(ctx, rec); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}

	sums, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphRecords: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("listing returned %d summaries for one module with three generations", len(sums))
	}
	if sums[0].Completeness != domain2.CompletenessBuiltWithBodies {
		t.Errorf("summary omits the fidelity: %q", sums[0].Completeness)
	}
	if sums[0].AnalysisSource != domain2.AnalysisSourceModuleZip {
		t.Errorf("summary omits the analysis source: %q", sums[0].AnalysisSource)
	}
}

// TestLedger_ListReportsAConflictOnItsOwnRow: a listing spans every module in the
// store, so one disputed module must not delete every correct row.
func TestLedger_ListReportsAConflictOnItsOwnRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	other, err := coordinate.NewModuleCoordinate("example.com/other", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	ok := ledgerRecord(t, ledgerSpec{
		coord: other, source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:x",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	// Two analyses of one pinned version that read different bytes.
	a := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies, at: testTime,
	})
	b := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:b",
		completeness: domain2.CompletenessBuiltWithBodies, at: testTime.Add(time.Hour),
	})
	for _, r := range []domain2.CallGraphRecord{ok, a, b} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	sums, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("one disputed module failed the whole listing: %v", err)
	}
	if len(sums) != 2 {
		t.Fatalf("listing returned %d summaries, want 2", len(sums))
	}
	var conflicted, clean int
	for _, s := range sums {
		if s.Conflict != nil {
			conflicted++
			continue
		}
		clean++
	}
	if conflicted != 1 || clean != 1 {
		t.Fatalf("conflicted=%d clean=%d, want 1 and 1", conflicted, clean)
	}

	if _, _, gerr := s.GetCallGraphRecord(ctx, testCoord, testPipeline); !errors.Is(gerr, ports.ErrCallGraphConflict) {
		t.Fatalf("GetCallGraphRecord err = %v, want ErrCallGraphConflict", gerr)
	}
}

// TestLedger_WorktreeRecordNeedsNoArtefactButNeedsADigest pins both halves of the
// write-leg refusal.
//
// A worktree analysis has no artefact identity — nothing was fetched, so there is
// nothing to name — and refusing it for that would make `kanonarion local`
// impossible. What it must carry instead is the tree digest, without which two
// checkouts of one module path are one row.
func TestLedger_WorktreeRecordNeedsNoArtefactButNeedsADigest(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}

	withDigest := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	if perr := s.PutCallGraphRecord(ctx, withDigest); perr != nil {
		t.Fatalf("a worktree record naming no artefact was refused: %v", perr)
	}

	noDigest := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree,
		completeness: domain2.CompletenessBuiltWithBodies, at: testTime.Add(time.Hour),
	})
	if perr := s.PutCallGraphRecord(ctx, noDigest); !errors.Is(perr, ports.ErrUnidentifiedWorktree) {
		t.Fatalf("put err = %v, want ErrUnidentifiedWorktree", perr)
	}
}

// TestLedger_ZipRecordNamingNoArtefactIsRefused: composition reads the identity to
// decide which records describe the same bytes, so a zero identity does not merely
// record nothing — it groups together every record that also recorded nothing.
func TestLedger_ZipRecordNamingNoArtefactIsRefused(t *testing.T) {
	s := openTestStore(t)
	rec := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, completeness: domain2.CompletenessBuiltWithBodies,
	})
	if err := s.PutCallGraphRecord(context.Background(), rec); !errors.Is(err, fetchdomain.ErrZeroIdentity) {
		t.Fatalf("put err = %v, want ErrZeroIdentity", err)
	}
}

// TestLedger_TwoWorktreesAreTwoRecords is the defect the worktree digest exists to
// prevent, and the one the old key made invisible: two checkouts of one module
// path collided on a single row, so the second silently replaced the first and the
// store looked consistent.
func TestLedger_TwoWorktreesAreTwoRecords(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	treeA := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime, callee: "example.com/mod.FromTreeA",
	})
	treeB := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree, worktree: "sha256:tree-b",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime.Add(time.Hour), callee: "example.com/mod.FromTreeB",
	})
	for _, r := range []domain2.CallGraphRecord{treeA, treeB} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	gens, err := s.ListCallGraphRecordsFor(ctx, local, testPipeline)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(gens) != 2 {
		t.Fatalf("two checkouts produced %d records, want 2", len(gens))
	}
	digests := map[string]bool{}
	for _, g := range gens {
		digests[g.WorktreeDigest] = true
	}
	if len(digests) != 2 {
		t.Fatalf("the two records do not distinguish the trees: %v", digests)
	}

	// The composed read serves the LAST observation, because a tree mutates and the
	// earlier record describes code that is no longer there.
	got, found, err := s.GetCallGraphRecordFrom(ctx, local, testPipeline, domain2.AnalysisSourceWorktree)
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecordFrom: found=%v err=%v", found, err)
	}
	if got.WorktreeDigest != "sha256:tree-b" {
		t.Fatalf("served tree %q, want the most recently ingested one", got.WorktreeDigest)
	}
}

// TestLedger_SourceScopedReadSeparatesTheDimension: a coordinate can legitimately
// carry both a zip analysis (a walk over a local-path replace target) and a
// worktree analysis (`kanonarion local`). They are different questions, and the
// unscoped read must not merge them.
func TestLedger_SourceScopedReadSeparatesTheDimension(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	zip := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime, callee: "example.com/mod.FromZip",
	})
	tree := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain2.CompletenessBuiltWithBodies,
		at:           testTime.Add(time.Hour), callee: "example.com/mod.FromTree",
	})
	for _, r := range []domain2.CallGraphRecord{zip, tree} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	unscoped, found, err := s.GetCallGraphRecord(ctx, local, testPipeline)
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: found=%v err=%v", found, err)
	}
	if unscoped.ContentHash != zip.ContentHash {
		t.Fatal("the unscoped read served the worktree graph; the stated default is the module zip")
	}

	scoped, found, err := s.GetCallGraphRecordFrom(ctx, local, testPipeline, domain2.AnalysisSourceWorktree)
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecordFrom: found=%v err=%v", found, err)
	}
	if scoped.ContentHash != tree.ContentHash {
		t.Fatal("naming the worktree source did not select the worktree record")
	}
}

// TestLedger_SourceScopedReadReportsAbsenceNotError: the ledger holding no record
// from the requested source is an absence of an answer to THAT question, not a
// failure.
func TestLedger_SourceScopedReadReportsAbsenceNotError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	got, found, err := s.GetCallGraphRecordFrom(ctx, testCoord, testPipeline, domain2.AnalysisSourceWorktree)
	if err != nil {
		t.Fatalf("GetCallGraphRecordFrom: %v", err)
	}
	if found {
		t.Fatalf("a worktree-scoped read was answered from a zip record: %+v", got)
	}
}

// TestLedger_ListFilterScopesBySource makes the analysis source queryable, which
// is the observable the field was added for: for any record written after the
// change, the store can be asked which source produced it without consulting the
// code path that wrote it.
func TestLedger_ListFilterScopesBySource(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	zip := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	tree := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree, worktree: "sha256:tree-a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	for _, r := range []domain2.CallGraphRecord{zip, tree} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	worktrees, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{AnalysisSource: domain2.AnalysisSourceWorktree})
	if err != nil {
		t.Fatalf("ListCallGraphRecords: %v", err)
	}
	if len(worktrees) != 1 || worktrees[0].ModuleVersion != coordinate.LocalVersion {
		t.Fatalf("source-scoped listing returned %+v", worktrees)
	}

	all, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphRecords: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered listing returned %d summaries, want 2", len(all))
	}
}

// TestLedger_LegacyRecordVerifiesUnchanged is the "existing rows carry in and all
// still verify" acceptance, in the only form a unit test can state it: a record
// sealed WITHOUT the new fields must still verify its own content hash after they
// exist.
//
// That is the whole omitempty argument, and it is worth pinning rather than
// asserting: if either field ever loses its omitempty tag, every stored record
// fails its integrity check at once.
func TestLedger_LegacyRecordVerifiesUnchanged(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	legacy := domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    testCoord,
		Algorithm:     domain2.AlgorithmCHA,
		Nodes:         []domain2.CallNode{{ID: "example.com/mod.Foo", Symbol: "Foo"}},
		OverallStatus: domain2.CallGraphStatusExtracted,
		NodeCount:     1,
		ExtractedAt:   testTime,
		// No AnalysisSource, no WorktreeDigest, no Completeness: the pre-field shape.
		PipelineVersion:  testPipeline,
		ArtefactIdentity: "zip:h1:a",
	}
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(legacy)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, sealed); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	got, found, err := s.GetCallGraphRecord(ctx, testCoord, testPipeline)
	if err != nil || !found {
		t.Fatalf("a record predating the new fields failed to read back: found=%v err=%v", found, err)
	}
	if got.ContentHash != sealed.ContentHash {
		t.Fatalf("content hash changed on round-trip: %s -> %s", sealed.ContentHash, got.ContentHash)
	}
	if got.AnalysisSource != domain2.AnalysisSourceUnrecorded {
		t.Errorf("an absent analysis source read back as %q, not as unrecorded", got.AnalysisSource)
	}
}

// TestMigration_BackfillsCompletenessFromTheRecord pins the fix for a defect the
// ledger migration introduced and a post-implementation review caught.
//
// Migration 8 added three columns and back-filled all three with ”. That is
// correct for the two facts that were never recorded, and wrong for completeness,
// which has been inside the serialised record since schema v8 — so every carried-in
// row held a column saying "unknown fidelity" next to a record saying
// BUILT_WITH_BODIES. Nothing read the column into a wrong answer, because
// composition reads the decoded record; but a denormalised column that contradicts
// what it denormalises is worse than no column, since the next reader will not know
// to distrust it.
//
// The guard is written against the store's own read path rather than the column, so
// it fails if the two ever disagree again in either direction.
func TestMigration_BackfillsCompletenessFromTheRecord(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Simulate a carried-in row: written normally, then its column blanked, which
	// is exactly the state migration 8 left every pre-existing row in.
	rec := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if _, err := s.InternalDB().DB().ExecContext(ctx,
		`UPDATE callgraph_records SET completeness = '' WHERE content_hash = ?`, rec.ContentHash); err != nil {
		t.Fatalf("blanking the column: %v", err)
	}

	if err := s.BackfillCompletenessForTest(ctx); err != nil {
		t.Fatalf("back-fill: %v", err)
	}

	var col string
	if err := s.InternalDB().DB().QueryRowContext(ctx,
		`SELECT completeness FROM callgraph_records WHERE content_hash = ?`, rec.ContentHash).Scan(&col); err != nil {
		t.Fatalf("reading the column back: %v", err)
	}
	if col != string(domain2.CompletenessBuiltWithBodies) {
		t.Fatalf("completeness column = %q, want %q — it still contradicts the record it copies",
			col, domain2.CompletenessBuiltWithBodies)
	}

	// And the summary, which is the only consumer of the column, now reports what
	// the record says.
	sums, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphRecords: %v", err)
	}
	if len(sums) != 1 || sums[0].Completeness != domain2.CompletenessBuiltWithBodies {
		t.Fatalf("summary reports completeness %q", sums[0].Completeness)
	}
}

// TestMigration_BackfillLeavesAnUnrecordedLevelAlone: a record that genuinely
// states no fidelity must keep an empty column. Writing something there would
// invent a measurement, which is the mirror of the defect being fixed.
func TestMigration_BackfillLeavesAnUnrecordedLevelAlone(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		// No completeness at all.
		status: domain2.CallGraphStatusCancelled,
	})
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
	if err := s.BackfillCompletenessForTest(ctx); err != nil {
		t.Fatalf("back-fill: %v", err)
	}
	var col string
	if err := s.InternalDB().DB().QueryRowContext(ctx,
		`SELECT completeness FROM callgraph_records WHERE content_hash = ?`, rec.ContentHash).Scan(&col); err != nil {
		t.Fatalf("reading the column back: %v", err)
	}
	if col != "" {
		t.Fatalf("completeness column = %q for a record that states none", col)
	}
}
