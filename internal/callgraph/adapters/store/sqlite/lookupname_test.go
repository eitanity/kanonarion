package sqlite_test

import (
	"context"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "code.eitanity.com/kanonarion/internal/callgraph/domain"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
)

// The lookup name is migration 18, one column on callgraph_edges, the last
// callgraph migration.
func TestMigrations_LookupNameIsMigrationEighteen(t *testing.T) {
	t.Parallel()
	migs := sqlite.Migrations()
	if n := len(migs); n != 18 {
		t.Fatalf("callgraph migrations = %d, want 18", n)
	}
	if last := migs[len(migs)-1]; last.Version != 18 || last.Fn != nil {
		t.Errorf("last callgraph migration is %d (back-fill %v), want 18 with no back-fill", last.Version, last.Fn != nil)
	}
	s := openTestStore(t)
	if n := countRows(t, s, `SELECT COUNT(*) FROM pragma_table_info('callgraph_edges') WHERE name = 'lookup_name'`); n != 1 {
		t.Errorf("callgraph_edges has %d column(s) named lookup_name, want 1", n)
	}
}

// TestLookupNameSurvivesTheStore: edges are rebuilt from callgraph_edges, so a
// name the writer stores and the reader does not select comes back empty, the
// lookup binds every method, and the seal over the rebuilt record breaks.
func TestLookupNameSurvivesTheStore(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	ctx := context.Background()

	const (
		caller = "example.com/mod.Bind"
		value  = "reflect.(Value).MethodByName"
		rtype  = "reflect.(*rtype).MethodByName"
	)
	rec := domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    testCoord,
		Algorithm:     domain2.AlgorithmCHA,
		Completeness:  domain2.CompletenessBuiltWithBodies,
		Nodes: []domain2.CallNode{
			{ID: caller, Module: "example.com/mod", Package: "example.com/mod", Symbol: "Bind"},
		},
		Edges: []domain2.CallEdge{
			{FromID: caller, ToID: value, Confidence: domain2.ConfidenceUnknown, ReflectDispatch: true, LookupName: "Run",
				CallSite: domain2.SourcePosition{File: "bind.go", Line: 3}},
			{FromID: caller, ToID: rtype, Confidence: domain2.ConfidenceCHAOverapprox,
				CallSite: domain2.SourcePosition{File: "bind.go", Line: 4}},
		},
		OverallStatus:    domain2.CallGraphStatusExtracted,
		NodeCount:        1,
		EdgeCount:        2,
		ExtractedAt:      testTime,
		PipelineVersion:  "0.14.0",
		ArtefactIdentity: "zip:h1:" + testCoord.Path() + "@" + testCoord.Version(),
	}
	rec, err := domain2.CallGraphRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if perr := s.PutCallGraphRecord(ctx, rec); perr != nil {
		t.Fatalf("PutCallGraphRecord: %v", perr)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_edges WHERE lookup_name = 'Run' AND to_id = '`+value+`'`); n != 1 {
		t.Errorf("%d edge rows carry the name, want 1", n)
	}

	got, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.14.0")
	if err != nil || !found {
		t.Fatalf("GetCallGraphRecord: found=%v err=%v", found, err)
	}
	names := map[string]string{}
	for _, e := range got.Edges {
		names[e.ToID] = e.LookupName
	}
	if names[value] != "Run" || names[rtype] != "" {
		t.Errorf("lookup names after the round trip = %v, want Run on %s and none on %s", names, value, rtype)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("content hash moved over the round trip: %s, want %s", got.ContentHash, rec.ContentHash)
	}
}
