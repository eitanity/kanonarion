package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walksqlite "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	"github.com/eitanity/kanonarion/internal/walk/domain"
)

// boundedWalkRecord is a walk that resolved four nodes and fetched two of them,
// the shape a depth-bounded or shallow walk produces: the requirements it did
// not follow are nodes with no outcome of their own.
func boundedWalkRecord(t testing.TB, id string) domain.WalkRecord {
	t.Helper()
	target := mustCoord("github.com/example/target", "v1.0.0")
	started := time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)

	followed := mustCoord("example.com/dep", "v1.0.0")
	bounded := []coordinate.ModuleCoordinate{
		mustCoord("example.com/beyond1", "v1.0.0"),
		mustCoord("example.com/beyond2", "v1.0.0"),
	}
	nodes := []domain.GraphNode{
		{Coordinate: target, ResolutionSource: domain.ResolutionTarget},
		{Coordinate: followed, ResolutionSource: domain.ResolutionMVS},
	}
	for _, c := range bounded {
		nodes = append(nodes, domain.GraphNode{Coordinate: c, ResolutionSource: domain.ResolutionDepthBounded})
	}
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target: target, ResolvedAt: started, PipelineVersion: "0.3.0", Nodes: nodes,
			Partial: true, PartialReason: domain.DepthBoundedReason(1),
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target:   {Coordinate: target, Status: domain.NodeSucceeded},
			followed: {Coordinate: followed, Status: domain.NodeSucceeded},
		},
		StartedAt:     started,
		CompletedAt:   started.Add(time.Second),
		OverallStatus: domain.WalkPartial,
	}
	rec := domain.NewWalkRecord(id, "test-operator", "0.3.0",
		domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return rec
}

// The listing's node count is the graph's, which is what "nodes" means on every
// other surface that prints it for a walk. It counted the per-node results, so a
// walk that leaves a node unfetched on purpose was listed as smaller than the
// walk line printed for it seconds earlier.
func TestPutWalk_StoresTheGraphsNodeCountNotTheOutcomeCount(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := boundedWalkRecord(t, "01NODECOUNT00000000BOUND1")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	sum := summaryOf(t, s, rec.ID)
	if sum.NodeCount != len(rec.Graph.Nodes) {
		t.Errorf("NodeCount = %d, want %d: the walk resolved that many nodes, whatever it fetched for them",
			sum.NodeCount, len(rec.Graph.Nodes))
	}
	if sum.FailureCount != 0 {
		t.Errorf("FailureCount = %d, want 0: a node the bound stopped at did not fail", sum.FailureCount)
	}
}

// The column is a projection of the graph already in the blob, so a row written
// under the old rule is corrected in place rather than left to keep answering
// walk-list with a node count its own record does not support.
func TestMigration11_RecomputesTheNodeCountFromTheSealedRecord(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 11)

	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	handle, err := sqlitestore.Open(dsn, pre, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the pre-migration schema: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	}()

	rec := boundedWalkRecord(t, "01NODECOUNT0000BACKFILL01")
	var h domain.WalkRecordHasher
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Written the way the previous build did: two nodes, because two were
	// fetched — over a graph of four.
	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, go_version, serialised)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 2, 0, 'code', '', '', '', '', '', '', ?)`,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339), rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus), rec.PipelineVersion, rec.Operator, rec.ContentHash,
		blobcodec.Encode(raw),
	); err != nil {
		t.Fatalf("inserting a pre-migration row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("applying migration 11: %v", err)
	}

	var nodes int
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT node_count FROM walks WHERE id = ?`, rec.ID).Scan(&nodes); err != nil {
		t.Fatalf("reading the re-derived count: %v", err)
	}
	if nodes != len(rec.Graph.Nodes) {
		t.Errorf("node_count after migration = %d, want %d", nodes, len(rec.Graph.Nodes))
	}

	// The projection must not have disturbed the seal.
	store := walksqlite.New(handle)
	back, err := store.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk after migration: %v", err)
	}
	if back.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash after migration = %q, want %q", back.ContentHash, rec.ContentHash)
	}
}

// A row this build cannot decode keeps the count it was written with: nothing
// can re-derive it, and inventing one would be the defect in reverse.
func TestMigration11_UndecodableRowKeepsItsCount(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 11)
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	handle, err := sqlitestore.Open(dsn, pre, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening at the pre-migration schema: %v", err)
	}
	defer func() {
		if cerr := handle.Close(); cerr != nil {
			t.Errorf("closing: %v", cerr)
		}
	}()

	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, go_version, serialised)
VALUES ('01NODECOUNT000000GARBAGE', 'example.com/m', 'v1.0.0',
    '2026-09-18T00:00:00Z', '2026-09-18T00:00:01Z', 0, '0.3.0', 'op', 'deadbeef',
    9, 0, 'code', '', '', '', '', '', '', ?)`, []byte("not a walk record")); err != nil {
		t.Fatalf("inserting an undecodable row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("a row this build cannot decode stopped the migration: %v", err)
	}
	var nodes int
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT node_count FROM walks WHERE id = '01NODECOUNT000000GARBAGE'`).Scan(&nodes); err != nil {
		t.Fatalf("reading the untouched count: %v", err)
	}
	if nodes != 9 {
		t.Errorf("node_count = %d, want the 9 it was written with: nothing could re-derive it", nodes)
	}
}
