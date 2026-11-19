package sqlite_test

import (
	"context"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
)

// The dispatch rows are migration 19, a table of their own, the last callgraph
// migration and with no back-fill.
func TestMigrations_DependencyDispatchIsMigrationNineteen(t *testing.T) {
	t.Parallel()
	migs := sqlite.Migrations()
	if n := len(migs); n != 19 {
		t.Fatalf("callgraph migrations = %d, want 19", n)
	}
	if last := migs[len(migs)-1]; last.Version != 19 || last.Fn != nil {
		t.Errorf("last callgraph migration is %d (back-fill %v), want 19 with no back-fill", last.Version, last.Fn != nil)
	}
	s := openTestStore(t)
	if n := countRows(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'callgraph_dependency_dispatch'`); n != 1 {
		t.Errorf("%d tables named callgraph_dependency_dispatch, want 1", n)
	}
}

// TestDependencyDispatchOf_ReadsTheServedRecordsRows: the fact is written as a
// row beside the blob, read back by node, and only a served record's rows
// answer. Without the write, or with the read keyed on any record, the read
// would be empty or would answer for a generation nothing serves.
func TestDependencyDispatchOf_ReadsTheServedRecordsRows(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()

	const (
		read  = "example.com/mod.(*T).Read"
		plain = "example.com/mod.(*T).Close"
	)
	fact := domain2.DependencyDispatch{
		Escape:     domain2.DispatchEscape{Kind: domain2.EscapeConversion, Type: "*T", Via: "io.Reader", Function: "example.com/mod.New", Site: domain2.SourcePosition{File: "t.go", Line: 4}},
		Interfaces: []string{"io.Reader"},
	}
	rec := domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    testCoord,
		Algorithm:     domain2.AlgorithmCHA,
		Completeness:  domain2.CompletenessBuiltWithBodies,
		Nodes: []domain2.CallNode{
			{ID: read, Module: "example.com/mod", Package: "example.com/mod", Symbol: "Read", Receiver: "*T", DependencyDispatch: fact},
			{ID: plain, Module: "example.com/mod", Package: "example.com/mod", Symbol: "Close", Receiver: "*T"},
		},
		OverallStatus:    domain2.CallGraphStatusExtracted,
		NodeCount:        2,
		ExtractedAt:      testTime,
		PipelineVersion:  "0.16.0",
		ArtefactIdentity: "zip:h1:" + testCoord.Path() + "@" + testCoord.Version(),
	}
	rec, err := domain2.CallGraphRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if perr := s.PutCallGraphRecord(ctx, rec); perr != nil {
		t.Fatalf("PutCallGraphRecord: %v", perr)
	}

	got, err := s.DependencyDispatchOf(ctx, []string{read, plain, read}, "0.16.0", coordinate.ModuleSet{}, "")
	if err != nil {
		t.Fatalf("DependencyDispatchOf: %v", err)
	}
	if len(got) != 1 || got[read] != fact.Describe() {
		t.Errorf("DependencyDispatchOf = %v, want only %s with %q", got, read, fact.Describe())
	}
	if other, oerr := s.DependencyDispatchOf(ctx, []string{read}, "0.15.0", coordinate.ModuleSet{}, ""); oerr != nil || len(other) != 0 {
		t.Errorf("another pipeline's read = %v, %v; want nothing", other, oerr)
	}

	back, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.16.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: found=%v err=%v", found, err)
	}
	for _, n := range back.Nodes {
		if n.ID == read && (n.DependencyDispatch.Escape != fact.Escape || !slices.Equal(n.DependencyDispatch.Interfaces, fact.Interfaces)) {
			t.Errorf("the sealed fact came back as %+v, want %+v", n.DependencyDispatch, fact)
		}
	}
}
