package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func openMemStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	})
	return s
}

func mustCoord(path, version string) coordinate.ModuleCoordinate {
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		panic(err)
	}
	return c
}

func buildWalkRecord(id string) domain.WalkRecord {
	target := mustCoord("github.com/example/target", "v1.0.0")
	dep := mustCoord("github.com/example/dep", "v2.3.0")
	fixedTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	graph := domain.Graph{
		Target: target,
		Nodes: []domain.GraphNode{
			{Coordinate: target, DirectDependency: false, ResolutionSource: domain.ResolutionTarget},
			{Coordinate: dep, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
		},
		Edges: []domain.GraphEdge{
			{From: target, To: dep, ConstraintVersion: "v2.3.0"},
		},
		ResolvedAt:      fixedTime,
		PipelineVersion: "0.3.0",
	}
	outcome := domain.WalkOutcome{
		Target: target,
		Graph:  graph,
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {
				Coordinate: target,
				Status:     domain.NodeSucceeded,
				FromCache:  false,
				DurationMs: 100,
			},
			dep: {
				Coordinate: dep,
				Status:     domain.NodeSucceeded,
				FromCache:  true,
				DurationMs: 10,
			},
		},
		StartedAt:     fixedTime,
		CompletedAt:   fixedTime.Add(200 * time.Millisecond),
		OverallStatus: domain.WalkSucceeded,
	}

	rec := domain.NewWalkRecord(id, "test-operator", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func TestPutGetWalkRecord(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000000000001")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	got, err := s.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("ID: got %q, want %q", got.ID, rec.ID)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, rec.ContentHash)
	}
	if got.OverallStatus != rec.OverallStatus {
		t.Errorf("OverallStatus: got %v, want %v", got.OverallStatus, rec.OverallStatus)
	}
	if got.Target.Path != rec.Target.Path || got.Target.Version != rec.Target.Version {
		t.Errorf("Target: got %v, want %v", got.Target, rec.Target)
	}
	if len(got.PerNodeResults) != len(rec.PerNodeResults) {
		t.Errorf("PerNodeResults len: got %d, want %d", len(got.PerNodeResults), len(rec.PerNodeResults))
	}
}

func TestGetWalkRecord_NotFound(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	_, err := s.GetWalk(ctx, "nonexistent-id")
	if !errors.Is(err, walkports.ErrWalkNotFound) {
		t.Errorf("expected ErrWalkNotFound, got %v", err)
	}
}

func TestPutWalk_IdempotentOnID(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000000000002")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("first PutWalk: %v", err)
	}
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("second PutWalk (idempotent): %v", err)
	}

	_, err := s.GetWalk(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GetWalk after double put: %v", err)
	}
}

func TestPutWalk_RejectsInvalidHash(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000000000003")
	rec.ContentHash = "sha256:badhash"

	if err := s.PutWalk(ctx, rec); err == nil {
		t.Error("expected error for invalid content hash, got nil")
	}
}

func TestListWalks_Empty(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	summaries, err := s.ListWalks(ctx, walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries, got %d", len(summaries))
	}
}

func TestListWalks_FilterByTarget(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	recA := buildWalkRecord("01HZTEST00000000000000004")
	if err := s.PutWalk(ctx, recA); err != nil {
		t.Fatalf("PutWalk A: %v", err)
	}

	target := mustCoord("github.com/example/target", "v1.0.0")
	other := mustCoord("github.com/other/mod", "v1.0.0")

	summaries, err := s.ListWalks(ctx, walkports.WalkFilter{Target: &target})
	if err != nil {
		t.Fatalf("ListWalks by target: %v", err)
	}
	if len(summaries) != 1 {
		t.Errorf("expected 1 summary, got %d", len(summaries))
	}

	summaries, err = s.ListWalks(ctx, walkports.WalkFilter{Target: &other})
	if err != nil {
		t.Fatalf("ListWalks by other target: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries for unrelated target, got %d", len(summaries))
	}
}

func TestListWalks_SummaryFields(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000000000005")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	summaries, err := s.ListWalks(ctx, walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	sum := summaries[0]
	if sum.ID != rec.ID {
		t.Errorf("ID: got %q, want %q", sum.ID, rec.ID)
	}
	if sum.NodeCount != 2 {
		t.Errorf("NodeCount: got %d, want 2", sum.NodeCount)
	}
	if sum.FailureCount != 0 {
		t.Errorf("FailureCount: got %d, want 0", sum.FailureCount)
	}
	if sum.OverallStatus != domain.WalkSucceeded {
		t.Errorf("OverallStatus: got %v, want WalkSucceeded", sum.OverallStatus)
	}
}

func TestListWalks_Limit(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for i, id := range []string{
		"01HZTEST00000000000000006",
		"01HZTEST00000000000000007",
		"01HZTEST00000000000000008",
	} {
		rec := buildWalkRecord(id)
		rec.StartedAt = time.Date(2025, 1, 15+i, 12, 0, 0, 0, time.UTC)
		rec.CompletedAt = rec.StartedAt.Add(200 * time.Millisecond)
		var h domain.WalkRecordHasher
		rec, _ = h.SetContentHash(rec)
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatalf("PutWalk %s: %v", id, err)
		}
	}

	summaries, err := s.ListWalks(ctx, walkports.WalkFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListWalks with limit: %v", err)
	}
	if len(summaries) != 2 {
		t.Errorf("expected 2 summaries, got %d", len(summaries))
	}
}

func TestListWalks_Offset(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for i, id := range []string{
		"01HZTEST00000000000000011",
		"01HZTEST00000000000000012",
	} {
		rec := buildWalkRecord(id)
		rec.StartedAt = time.Date(2025, 1, 15+i, 12, 0, 0, 0, time.UTC)
		var h domain.WalkRecordHasher
		rec, _ = h.SetContentHash(rec)
		if err := s.PutWalk(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	summaries, err := s.ListWalks(ctx, walkports.WalkFilter{Offset: 1})
	if err != nil {
		t.Fatalf("ListWalks with offset: %v", err)
	}
	if len(summaries) != 1 {
		t.Errorf("expected 1 summary with Offset=1, got %d", len(summaries))
	}
}

func TestGetWalk_IntegrityError(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000000000009")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	db := s.InternalDB().DB()
	rec.ContentHash = "sha256:invalid"
	var h domain.WalkRecordHasher
	blob, _ := h.Marshal(rec)
	if _, err := db.Exec("UPDATE walks SET serialised = ?", blob); err != nil {
		t.Fatalf("failed to tamper with db: %v", err)
	}

	_, err := s.GetWalk(ctx, rec.ID)
	if !errors.Is(err, walkports.ErrWalkIntegrity) {
		t.Errorf("expected ErrWalkIntegrity, got %v", err)
	}
}

func TestListWalks_FullFilter(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	rec := buildWalkRecord("01HZTEST00000000000000010")
	if err := s.PutWalk(ctx, rec); err != nil {
		t.Fatal(err)
	}

	since := rec.StartedAt.Add(-time.Hour)
	until := rec.StartedAt.Add(time.Hour)
	status := rec.OverallStatus

	summaries, err := s.ListWalks(ctx, walkports.WalkFilter{
		Since:         &since,
		Until:         &until,
		OverallStatus: &status,
	})
	if err != nil {
		t.Fatalf("ListWalks full filter: %v", err)
	}
	if len(summaries) != 1 {
		t.Errorf("expected 1 summary, got %d", len(summaries))
	}
}

func buildWalkRecordWithScope(id string, scope domain.WalkScope) domain.WalkRecord {
	target := mustCoord("github.com/example/target", "v1.0.0")
	fixedTime := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	outcome := domain.WalkOutcome{
		Target:         target,
		Graph:          domain.Graph{Target: target, ResolvedAt: fixedTime, PipelineVersion: "0.3.0"},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{},
		StartedAt:      fixedTime,
		CompletedAt:    fixedTime.Add(100 * time.Millisecond),
		OverallStatus:  domain.WalkSucceeded,
	}
	rec := domain.NewWalkRecord(id, "test-operator", "0.3.0", scope, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func TestWalkScope_StoredAndRetrieved(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	prod := buildWalkRecordWithScope("01SCOPE000000000PRODUCTION", domain.WalkScopeCode)
	tool := buildWalkRecordWithScope("01SCOPE000000000000000TOOL", domain.WalkScopeTool)

	if err := s.PutWalk(ctx, prod); err != nil {
		t.Fatalf("PutWalk production: %v", err)
	}
	if err := s.PutWalk(ctx, tool); err != nil {
		t.Fatalf("PutWalk tool: %v", err)
	}

	gotProd, err := s.GetWalk(ctx, prod.ID)
	if err != nil {
		t.Fatalf("GetWalk production: %v", err)
	}
	if gotProd.Scope != domain.WalkScopeCode {
		t.Errorf("production scope: got %q, want %q", gotProd.Scope, domain.WalkScopeCode)
	}

	gotTool, err := s.GetWalk(ctx, tool.ID)
	if err != nil {
		t.Fatalf("GetWalk tool: %v", err)
	}
	if gotTool.Scope != domain.WalkScopeTool {
		t.Errorf("tool scope: got %q, want %q", gotTool.Scope, domain.WalkScopeTool)
	}
}

func TestListWalks_FilterByScope(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	prod := buildWalkRecordWithScope("01SCOPE000000000PRODUCTION", domain.WalkScopeCode)
	tool := buildWalkRecordWithScope("01SCOPE000000000000000TOOL", domain.WalkScopeTool)

	for _, r := range []domain.WalkRecord{prod, tool} {
		if err := s.PutWalk(ctx, r); err != nil {
			t.Fatalf("PutWalk: %v", err)
		}
	}

	scopeTool := domain.WalkScopeTool
	sums, err := s.ListWalks(ctx, walkports.WalkFilter{Scope: &scopeTool})
	if err != nil {
		t.Fatalf("ListWalks scope=tool: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 tool walk, got %d", len(sums))
	}
	if sums[0].ID != tool.ID {
		t.Errorf("tool walk ID: got %q, want %q", sums[0].ID, tool.ID)
	}
	if sums[0].Scope != domain.WalkScopeTool {
		t.Errorf("summary scope: got %q, want %q", sums[0].Scope, domain.WalkScopeTool)
	}

	scopeProd := domain.WalkScopeCode
	sums, err = s.ListWalks(ctx, walkports.WalkFilter{Scope: &scopeProd})
	if err != nil {
		t.Fatalf("ListWalks scope=production: %v", err)
	}
	if len(sums) != 1 {
		t.Fatalf("expected 1 production walk, got %d", len(sums))
	}
	if sums[0].Scope != domain.WalkScopeCode {
		t.Errorf("summary scope: got %q, want %q", sums[0].Scope, domain.WalkScopeCode)
	}
}
