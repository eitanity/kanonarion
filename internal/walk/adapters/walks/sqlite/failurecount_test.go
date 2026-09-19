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
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// walkRecordWithNodeStatuses builds a walk whose per-node results carry exactly
// the statuses given, one module each.
func walkRecordWithNodeStatuses(t testing.TB, id string, statuses ...domain.NodeStatus) domain.WalkRecord {
	t.Helper()
	target := mustCoord("github.com/example/target", "v1.0.0")
	started := time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)
	results := map[coordinate.ModuleCoordinate]domain.NodeResult{}
	// Each status also gets its graph node. The two counts the stored summary
	// carries project different parts of one record — the graph's size and the
	// failures among its outcomes — so a fixture that supplies only one of them
	// cannot say what either column should hold.
	nodes := make([]domain.GraphNode, 0, len(statuses))
	for i, s := range statuses {
		c, err := coordinate.NewModuleCoordinate("example.com/dep"+string(rune('a'+i)), "v1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		results[c] = domain.NodeResult{Coordinate: c, Status: s}
		source := domain.ResolutionMVS
		if s == domain.NodeLocalReplace {
			source = domain.ResolutionLocalReplace
		}
		nodes = append(nodes, domain.GraphNode{Coordinate: c, ResolutionSource: source})
	}
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target: target, ResolvedAt: started, PipelineVersion: "0.3.0", Nodes: nodes,
		},
		PerNodeResults: results,
		StartedAt:      started,
		CompletedAt:    started.Add(time.Second),
		OverallStatus:  domain.WalkSucceeded,
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

// summaryOf reads one walk's stored summary — the row walk-list prints from,
// as opposed to the record the CLI can recount for itself.
func summaryOf(t *testing.T, s *walksqlite.Store, id string) walkports.WalkSummary {
	t.Helper()
	summaries, err := s.ListWalks(context.Background(), walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	for _, sum := range summaries {
		if sum.ID == id {
			return sum
		}
	}
	t.Fatalf("no stored summary for walk %s", id)
	return walkports.WalkSummary{}
}

// TestPutWalk_StoresOnlyTheFailureStatusesAsFailures. The stored summary is what
// walk-list prints, and it counted every node that was not "succeeded". A
// require redirected to a local path is not a failed fetch — the domain says the
// walk is not partial because of one — so a project with a local replace was
// told one of its own dependencies had failed.
func TestPutWalk_StoresOnlyTheFailureStatusesAsFailures(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := walkRecordWithNodeStatuses(t, "01FAILCOUNT0000000000MIX1",
		domain.NodeSucceeded, domain.NodeLocalReplace, domain.NodeFetchFailed, domain.NodeInternalPanic)
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	sum := summaryOf(t, s, rec.ID)
	if sum.NodeCount != 4 {
		t.Errorf("NodeCount = %d, want 4", sum.NodeCount)
	}
	if sum.FailureCount != 2 {
		t.Errorf("FailureCount = %d, want 2 (the fetch failure and the panic, not the local replace)", sum.FailureCount)
	}

	// The control: a walk whose only non-succeeded node is a local replace has
	// nothing to report, which is the loki case.
	replaced := walkRecordWithNodeStatuses(t, "01FAILCOUNT000000000LOCAL",
		domain.NodeSucceeded, domain.NodeLocalReplace)
	if err := s.PutWalk(ctx, replaced); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}
	sum = summaryOf(t, s, replaced.ID)
	if sum.FailureCount != 0 {
		t.Errorf("FailureCount = %d, want 0: a local replace is not a fetch that failed", sum.FailureCount)
	}
}

// TestMigration10_RecomputesTheFailureCountFromTheSealedRecord. The column is a
// projection of the per-node results already in the blob, so a row written under
// the old rule is corrected in place rather than left to keep answering
// walk-list with a count its own record does not support.
func TestMigration10_RecomputesTheFailureCountFromTheSealedRecord(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 10)

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

	rec := walkRecordWithNodeStatuses(t, "01FAILCOUNT00000BACKFILL1",
		domain.NodeSucceeded, domain.NodeLocalReplace, domain.NodeFetchFailed)
	var h domain.WalkRecordHasher
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Written the way the previous build did: two nodes counted as failures,
	// because one of them merely did not succeed.
	if _, err := handle.DB().ExecContext(ctx, `
INSERT INTO walks (id, target_path, target_version, started_at, completed_at,
    overall_status, pipeline_version, operator, content_hash,
    node_count, failure_count, scope, depth, project_dir, identity_hash,
    goos, goarch, go_version, serialised)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 3, 2, 'code', '', '', '', '', '', '', ?)`,
		rec.ID, rec.Target.Path(), rec.Target.Version(),
		rec.StartedAt.UTC().Format(time.RFC3339), rec.CompletedAt.UTC().Format(time.RFC3339),
		int(rec.OverallStatus), rec.PipelineVersion, rec.Operator, rec.ContentHash,
		blobcodec.Encode(raw),
	); err != nil {
		t.Fatalf("inserting a pre-migration row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("applying migration 10: %v", err)
	}

	var failures int
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT failure_count FROM walks WHERE id = ?`, rec.ID).Scan(&failures); err != nil {
		t.Fatalf("reading the re-derived count: %v", err)
	}
	if failures != 1 {
		t.Errorf("failure_count after migration = %d, want 1", failures)
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

// TestMigration10_UndecodableRowDoesNotStopTheStoreOpening. One historical row
// this build cannot read must not make the store refuse to open; its count stays
// as written, which is the only honest answer for a row nothing can re-derive.
func TestMigration10_UndecodableRowDoesNotStopTheStoreOpening(t *testing.T) {
	ctx := context.Background()

	all := walksqlite.Migrations()
	pre := walkMigrationsBefore(t, 10)
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
VALUES ('01FAILCOUNT0000000GARBAGE', 'example.com/m', 'v1.0.0',
    '2026-09-18T00:00:00Z', '2026-09-18T00:00:01Z', 0, '0.3.0', 'op', 'deadbeef',
    1, 7, 'code', '', '', '', '', '', '', ?)`, []byte("not a walk record")); err != nil {
		t.Fatalf("inserting an undecodable row: %v", err)
	}

	if err := sqlitestore.Apply(handle, all); err != nil {
		t.Fatalf("a row this build cannot decode stopped the migration: %v", err)
	}
	var failures int
	if err := handle.DB().QueryRowContext(ctx,
		`SELECT failure_count FROM walks WHERE id = '01FAILCOUNT0000000GARBAGE'`).Scan(&failures); err != nil {
		t.Fatalf("reading the untouched count: %v", err)
	}
	if failures != 7 {
		t.Errorf("failure_count = %d, want the 7 it was written with: nothing could re-derive it", failures)
	}
}
