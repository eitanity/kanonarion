package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

var (
	testCoord, _ = fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	testTime     = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
)

func openTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func makeRecord(coord fetchdomain.ModuleCoordinate, pv string) domain2.CallGraphRecord {
	var h domain2.CallGraphRecordHasher
	r := domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain2.AlgorithmCHA,
		Nodes: []domain2.CallNode{
			{
				ID:            "example.com/mod.Foo",
				Module:        "example.com/mod",
				Package:       "example.com/mod",
				Symbol:        "Foo",
				IsExportedAPI: true,
			},
		},
		Edges: []domain2.CallEdge{
			{
				FromID:     "example.com/mod.Foo",
				ToID:       "example.com/mod.Bar",
				CallSite:   domain2.SourcePosition{File: "foo.go", Line: 10},
				Confidence: domain2.ConfidenceDirect,
			},
			{
				FromID:          "example.com/mod.Foo",
				ToID:            "example.com/mod.Baz",
				CallSite:        domain2.SourcePosition{File: "foo.go", Line: 12},
				Confidence:      domain2.ConfidenceUnknown,
				ReflectDispatch: true,
			},
		},
		OverallStatus:   domain2.CallGraphStatusExtracted,
		NodeCount:       1,
		EdgeCount:       2,
		ExtractedAt:     testTime,
		PipelineVersion: pv,
	}
	hashed, err := h.SetContentHash(r)
	if err != nil {
		panic("SetContentHash: " + err.Error())
	}
	return hashed
}

func TestPutAndGet(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	got, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if err != nil {
		t.Fatalf("GetCallGraphRecord: %v", err)
	}
	if !found {
		t.Fatal("record not found after put")
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash mismatch: got %q, want %q", got.ContentHash, rec.ContentHash)
	}
	if len(got.Nodes) != 1 {
		t.Errorf("node count: got %d, want 1", len(got.Nodes))
	}
	if len(got.Edges) != 2 {
		t.Errorf("edge count: got %d, want 2", len(got.Edges))
	}
	// The reflect-dispatched edge's provenance must survive the round trip
	// through the callgraph_edges table.
	var reflectEdge *domain2.CallEdge
	for i := range got.Edges {
		if got.Edges[i].ToID == "example.com/mod.Baz" {
			reflectEdge = &got.Edges[i]
		}
	}
	if reflectEdge == nil {
		t.Fatal("reflect-dispatched edge missing after round trip")
	}
	if !reflectEdge.ReflectDispatch || reflectEdge.Confidence != domain2.ConfidenceUnknown {
		t.Errorf("reflect edge round trip = {reflect:%t conf:%q}, want {true Unknown}",
			reflectEdge.ReflectDispatch, reflectEdge.Confidence)
	}
}

func TestPutStoresCompressedBlob(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	// Read the raw bytes directly from SQLite to confirm they are zstd-compressed.
	row := s.InternalDB().DB().QueryRowContext(ctx,
		"SELECT serialised FROM callgraph_records WHERE module_path = ? AND module_version = ?",
		testCoord.Path, testCoord.Version,
	)
	var blob []byte
	if err := row.Scan(&blob); err != nil {
		t.Fatalf("reading raw blob: %v", err)
	}

	// zstd magic: 0x28 0xB5 0x2F 0xFD
	if len(blob) < 4 || blob[0] != 0x28 || blob[1] != 0xb5 || blob[2] != 0x2f || blob[3] != 0xfd {
		t.Errorf("stored blob does not start with zstd magic; first 4 bytes: %02x %02x %02x %02x",
			blob[0], blob[1], blob[2], blob[3])
	}
}

func TestGet_NotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_, found, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if err != nil {
		t.Fatalf("GetCallGraphRecord: %v", err)
	}
	if found {
		t.Error("expected not found for missing record")
	}
}

func TestPut_Idempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("second put (idempotent): %v", err)
	}
}

func TestListCallGraphRecords(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	coord2, _ := fetchdomain.NewModuleCoordinate("example.com/other", "v2.0.0")
	r1 := makeRecord(testCoord, "0.1.0")
	r2 := makeRecord(coord2, "0.1.0")

	if err := s.PutCallGraphRecord(ctx, r1); err != nil {
		t.Fatalf("put r1: %v", err)
	}
	if err := s.PutCallGraphRecord(ctx, r2); err != nil {
		t.Fatalf("put r2: %v", err)
	}

	summaries, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{})
	if err != nil {
		t.Fatalf("ListCallGraphRecords: %v", err)
	}
	if len(summaries) != 2 {
		t.Errorf("expected 2 summaries, got %d", len(summaries))
	}

	// Filter by module path.
	filtered, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{ModulePath: "example.com/mod"})
	if err != nil {
		t.Fatalf("ListCallGraphRecords (filtered): %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered summary, got %d", len(filtered))
	}
}

func TestFindCallers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	// The edge is Foo→Bar. FindCallers of Bar should return Foo.
	callers, err := s.FindCallers(ctx, "example.com/mod.Bar", "0.1.0")
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(callers) != 1 {
		t.Errorf("expected 1 caller, got %d: %v", len(callers), callers)
	}
	if len(callers) > 0 && callers[0].FromID != "example.com/mod.Foo" {
		t.Errorf("caller FromID = %q, want example.com/mod.Foo", callers[0].FromID)
	}
}

func TestFindCallees(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Foo calls Bar (Direct) and Baz (reflect-dispatched Unknown); FindCallees
	// of Foo should return both, ordered by ToID.
	callees, err := s.FindCallees(ctx, "example.com/mod.Foo", "0.1.0")
	if err != nil {
		t.Fatalf("FindCallees: %v", err)
	}
	if len(callees) != 2 {
		t.Fatalf("expected 2 callees, got %d: %v", len(callees), callees)
	}
	if callees[0].ToID != "example.com/mod.Bar" || callees[1].ToID != "example.com/mod.Baz" {
		t.Errorf("callee ToIDs = [%q %q], want [example.com/mod.Bar example.com/mod.Baz]",
			callees[0].ToID, callees[1].ToID)
	}
}

func TestFindCallers_EmptyResult(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	callers, err := s.FindCallers(ctx, "example.com/mod.Unknown", "0.1.0")
	if err != nil {
		t.Fatalf("FindCallers: %v", err)
	}
	if len(callers) != 0 {
		t.Errorf("expected no callers, got %d", len(callers))
	}
}

func TestListCallGraphRecords_LimitOffset(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	coords := []fetchdomain.ModuleCoordinate{}
	for _, path := range []string{"example.com/a", "example.com/b", "example.com/c"} {
		c, _ := fetchdomain.NewModuleCoordinate(path, "v1.0.0")
		coords = append(coords, c)
	}
	for _, c := range coords {
		if err := s.PutCallGraphRecord(ctx, makeRecord(c, "0.1.0")); err != nil {
			t.Fatalf("put %s: %v", c.Path, err)
		}
	}

	// Test Limit.
	limited, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{Limit: 2})
	if err != nil {
		t.Fatalf("list with limit: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("expected 2 results with Limit=2, got %d", len(limited))
	}

	// Test Offset.
	offset, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{Offset: 1})
	if err != nil {
		t.Fatalf("list with offset: %v", err)
	}
	if len(offset) != 2 {
		t.Errorf("expected 2 results with Offset=1 from 3 total, got %d", len(offset))
	}

	// Test Limit + Offset together.
	paged, err := s.ListCallGraphRecords(ctx, ports.CallGraphFilter{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("list with limit+offset: %v", err)
	}
	if len(paged) != 1 {
		t.Errorf("expected 1 result with Limit=1 Offset=1, got %d", len(paged))
	}
}

func TestPutCallGraphRecord_VerifiesHashOnPut(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Attempt to put a record without a valid ContentHash.
	r := makeRecord(testCoord, "0.1.0")
	r.ContentHash = "sha256:tampered"
	if err := s.PutCallGraphRecord(ctx, r); err == nil {
		t.Error("PutCallGraphRecord should fail for tampered record")
	}
}

func TestGetCallGraphRecord_IntegrityError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := makeRecord(testCoord, "0.1.0")
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}

	db := s.InternalDB().DB()
	rec.ContentHash = "sha256:invalid"
	var h domain2.CallGraphRecordHasher
	blob, _ := h.Marshal(rec)
	if _, err := db.Exec("UPDATE callgraph_records SET serialised = ?", blob); err != nil {
		t.Fatalf("failed to tamper with db: %v", err)
	}

	_, _, err := s.GetCallGraphRecord(ctx, testCoord, "0.1.0")
	if !errors.Is(err, ports.ErrCallGraphIntegrity) {
		t.Errorf("expected ErrCallGraphIntegrity, got %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	// Opening the same file-based DB twice exercises the v <= current skip
	// branch in the migration loop.
	dbPath := t.TempDir() + "/test.db"

	s1, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Errorf("close s1: %v", err)
	}

	s2, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("second Open (should be no-op migration): %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Errorf("close s2: %v", err)
	}
}
