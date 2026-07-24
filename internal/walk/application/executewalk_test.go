package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/audit"

	application2 "github.com/eitanity/kanonarion/internal/walk/application"
	"github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---- fake walk store ----

type fakeWalkStore struct {
	walks  map[string]domain.WalkRecord
	putErr error
	getErr error
}

func newFakeWalkStore() *fakeWalkStore {
	return &fakeWalkStore{walks: make(map[string]domain.WalkRecord)}
}

func (f *fakeWalkStore) PutWalk(_ context.Context, rec domain.WalkRecord) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.walks[rec.ID] = rec
	return nil
}

func (f *fakeWalkStore) GetWalk(_ context.Context, id string) (domain.WalkRecord, error) {
	if f.getErr != nil {
		return domain.WalkRecord{}, f.getErr
	}
	rec, ok := f.walks[id]
	if !ok {
		return domain.WalkRecord{}, walkports.ErrWalkNotFound
	}
	return rec, nil
}

func (f *fakeWalkStore) ListWalks(_ context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	var summaries []walkports.WalkSummary
	for _, rec := range f.walks {
		if filter.Target != nil && (rec.Target.Path != filter.Target.Path || rec.Target.Version != filter.Target.Version) {
			continue
		}
		summaries = append(summaries, walkports.WalkSummary{
			ID:            rec.ID,
			Target:        rec.Target,
			StartedAt:     rec.StartedAt,
			CompletedAt:   rec.CompletedAt,
			OverallStatus: rec.OverallStatus,
			NodeCount:     len(rec.PerNodeResults),
			Depth:         rec.Depth,
		})
	}
	// Mimic SQLite ordering: started_at DESC.
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].StartedAt.After(summaries[j].StartedAt)
	})
	if filter.Limit > 0 && len(summaries) > filter.Limit {
		summaries = summaries[:filter.Limit]
	}
	return summaries, nil
}

var _ walkports.WalkStore = (*fakeWalkStore)(nil)

// buildMinimalWalker constructs a walker backed by a single target module with no
// dependencies. Uses the same fakeModuleFetcher + fakeBlobStore + walkerFakeFetcher
// wiring as the walker tests.
func buildMinimalWalker(path, version string) *application2.Walker {
	const goMod = "module " // minimal go.mod
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	rf.add(path, version, goMod+path+"\ngo 1.21\n", blobs)

	wf := newWalkerFetcher()
	wf.addRecord(path, version)

	return buildWalker(rf, wf, blobs, 1)
}

// ---- ExecuteWalkUseCase tests ----

func TestExecuteWalkUseCase_Success(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())

	target := coord("github.com/example/m", "v1.0.0")
	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ID == "" {
		t.Error("expected non-empty walk ID")
	}
	if result.Record.ContentHash == "" {
		t.Error("expected non-empty content hash")
	}
	if result.Record.Operator != "test-op" {
		t.Errorf("Operator = %q, want test-op", result.Record.Operator)
	}
	if _, ok := store.walks[result.Record.ID]; !ok {
		t.Error("expected walk record to be persisted in store")
	}
}

func TestExecuteWalkUseCase_StoreError(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	store.putErr = errors.New("disk full")
	uc := application2.NewExecuteWalkUseCase(walker, store, "op", "0.3.0", discardLogger())

	target := coord("github.com/example/m", "v1.0.0")
	_, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err == nil {
		t.Fatal("expected error from store, got nil")
	}
}

func TestExecuteWalkUseCase_ContextCancelled(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	uc := application2.NewExecuteWalkUseCase(walker, store, "op", "0.3.0", discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := coord("github.com/example/m", "v1.0.0")
	_, err := uc.Execute(ctx, application2.WalkRequest{Target: target})
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

// ---- audit emission ----

type fakeAuditSink struct {
	events  []audit.Event
	recErr  error
	nEvents int
}

func (s *fakeAuditSink) RecordEvent(e audit.Event) error {
	if s.recErr != nil {
		return s.recErr
	}
	s.events = append(s.events, e)
	s.nEvents++
	return nil
}

var _ walkports.AuditSink = (*fakeAuditSink)(nil)

func TestExecuteWalkUseCase_EmitsWalkCompletedEvent(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	sink := &fakeAuditSink{}
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger()).WithAudit(sink)

	target := coord("github.com/example/m", "v1.0.0")
	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("expected exactly one audit event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Type != audit.EventWalkCompleted {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventWalkCompleted)
	}
	if got := ev.Payload["walk_id"]; got != result.Record.ID {
		t.Errorf("payload walk_id = %v, want %q", got, result.Record.ID)
	}
	if got := ev.Payload["module"]; got != "github.com/example/m" {
		t.Errorf("payload module = %v, want github.com/example/m", got)
	}
	if got := ev.Payload["version"]; got != "v1.0.0" {
		t.Errorf("payload version = %v, want v1.0.0", got)
	}
	if got := ev.Payload["scope"]; got != string(domain.WalkScopeCode) {
		t.Errorf("payload scope = %v, want %q", got, domain.WalkScopeCode)
	}
	if got := ev.Payload["node_count"]; got != len(result.Record.Graph.Nodes) {
		t.Errorf("payload node_count = %v, want %d", got, len(result.Record.Graph.Nodes))
	}
	if got := ev.Payload["content_hash"]; got != result.Record.ContentHash {
		t.Errorf("payload content_hash = %v, want %q", got, result.Record.ContentHash)
	}
}

func TestExecuteWalkUseCase_NoAuditSink_NoEmission(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	// No WithAudit call: a nil sink must be a no-op, not a panic.
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())

	target := coord("github.com/example/m", "v1.0.0")
	if _, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestExecuteWalkUseCase_FailedWalk_EmitsNothing(t *testing.T) {
	// A walk whose target fetch fails resolves to a non-succeeded status; no
	// complete population exists to anchor, so no walk_completed event is emitted.
	blobs := newFakeBlobStore()
	rf := newFakeFetcher()
	wf := newWalkerFetcher()
	wf.addFetchError("example.com/target", "v1.0.0", errors.New("proxy unavailable"))
	walker := buildWalker(rf, wf, blobs, 1)

	store := newFakeWalkStore()
	sink := &fakeAuditSink{}
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger()).WithAudit(sink)

	target := coord("example.com/target", "v1.0.0")
	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus == domain.WalkSucceeded {
		t.Fatalf("test setup: expected a non-succeeded walk, got %s", result.Record.OverallStatus)
	}
	if sink.nEvents != 0 {
		t.Errorf("expected no audit events for a non-succeeded walk, got %d", sink.nEvents)
	}
}

func TestExecuteWalkUseCase_AuditSinkError_Propagates(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	sink := &fakeAuditSink{recErr: errors.New("audit log write failed")}
	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger()).WithAudit(sink)

	target := coord("github.com/example/m", "v1.0.0")
	if _, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target}); err == nil {
		t.Fatal("expected error when audit sink fails, got nil")
	}
}

// ---- resume tests ----

func TestExecuteWalkUseCase_Resume_PartialWalk(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildPartialRecord(priorID, target)

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ID != priorID {
		t.Errorf("resume: expected walk ID %q to be reused, got %q", priorID, result.Record.ID)
	}
}

func TestExecuteWalkUseCase_Resume_CancelledWalk(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildCancelledRecord(priorID, target)

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ID != priorID {
		t.Errorf("resume: expected cancelled walk ID %q to be reused, got %q", priorID, result.Record.ID)
	}
}

func TestExecuteWalkUseCase_NoResume_SucceededWalk(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildMinimalRecord(priorID, target) // WalkSucceeded

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())

	t.Run("Default (Skip)", func(t *testing.T) {
		result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if result.Record.ID != priorID {
			t.Errorf("expected prior succeeded ID %q to be reused (skipped), got %q", priorID, result.Record.ID)
		}
	})

	t.Run("Force (Re-run)", func(t *testing.T) {
		result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target, Force: true})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if result.Record.ID == priorID {
			t.Errorf("expected fresh walk ID when Force=true, got prior ID %q", priorID)
		}
	})
}

func TestExecuteWalkUseCase_NoResume_DifferentVersion(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v2.0.0")
	store := newFakeWalkStore()
	targetV1 := coord("github.com/example/m", "v1.0.0")
	targetV2 := coord("github.com/example/m", "v2.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildPartialRecord(priorID, targetV1)

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: targetV2})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ID == priorID {
		t.Errorf("no-resume: expected fresh walk ID for v2.0.0, got v1.0.0 partial ID %q", priorID)
	}
}

// ---- QueryWalksUseCase tests ----

func TestQueryWalksUseCase_GetWalk(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/q", "v1.0.0")
	rec := buildMinimalRecord("test-id-01", target)
	store.walks["test-id-01"] = rec

	uc := application2.NewQueryWalksUseCase(store)
	got, err := uc.GetWalk(context.Background(), "test-id-01")
	if err != nil {
		t.Fatalf("GetWalk: %v", err)
	}
	if got.ID != "test-id-01" {
		t.Errorf("ID = %q, want test-id-01", got.ID)
	}
}

func TestQueryWalksUseCase_GetWalk_NotFound(t *testing.T) {
	store := newFakeWalkStore()
	uc := application2.NewQueryWalksUseCase(store)
	_, err := uc.GetWalk(context.Background(), "missing")
	if !errors.Is(err, walkports.ErrWalkNotFound) {
		t.Errorf("expected ErrWalkNotFound, got %v", err)
	}
}

func TestQueryWalksUseCase_ListWalks(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/q", "v1.0.0")
	store.walks["id-a"] = buildMinimalRecord("id-a", target)
	store.walks["id-b"] = buildMinimalRecord("id-b", target)

	uc := application2.NewQueryWalksUseCase(store)
	summaries, err := uc.ListWalks(context.Background(), walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(summaries) != 2 {
		t.Errorf("expected 2 summaries, got %d", len(summaries))
	}
}

// ---- DiffWalksUseCase tests ----

func TestDiffWalksUseCase_NoChange(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/d", "v1.0.0")
	recA := buildMinimalRecord("diff-a", target)
	recB := buildMinimalRecord("diff-b", target)
	store.walks["diff-a"] = recA
	store.walks["diff-b"] = recB

	uc := application2.NewDiffWalksUseCase(store)
	diff, err := uc.Diff(context.Background(), "diff-a", "diff-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.VersionChanged) != 0 {
		t.Errorf("expected empty diff for identical walks, got %+v", diff)
	}
}

func TestDiffWalksUseCase_Added(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/d", "v1.0.0")
	dep := coord("github.com/example/dep", "v2.0.0")

	recA := buildMinimalRecord("diff-add-a", target)
	recB := buildRecordWithDep("diff-add-b", target, dep)
	store.walks["diff-add-a"] = recA
	store.walks["diff-add-b"] = recB

	uc := application2.NewDiffWalksUseCase(store)
	diff, err := uc.Diff(context.Background(), "diff-add-a", "diff-add-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.Added) != 1 || diff.Added[0].Path != dep.Path {
		t.Errorf("expected 1 added dep, got %+v", diff.Added)
	}
}

func TestDiffWalksUseCase_Removed(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/d", "v1.0.0")
	dep := coord("github.com/example/dep", "v2.0.0")

	recA := buildRecordWithDep("diff-rm-a", target, dep)
	recB := buildMinimalRecord("diff-rm-b", target)
	store.walks["diff-rm-a"] = recA
	store.walks["diff-rm-b"] = recB

	uc := application2.NewDiffWalksUseCase(store)
	diff, err := uc.Diff(context.Background(), "diff-rm-a", "diff-rm-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Path != dep.Path {
		t.Errorf("expected 1 removed dep, got %+v", diff.Removed)
	}
}

func TestDiffWalksUseCase_VersionChanged(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/d", "v1.0.0")
	depV1 := coord("github.com/example/dep", "v1.0.0")
	depV2 := coord("github.com/example/dep", "v2.0.0")

	recA := buildRecordWithDep("diff-ver-a", target, depV1)
	recB := buildRecordWithDep("diff-ver-b", target, depV2)
	store.walks["diff-ver-a"] = recA
	store.walks["diff-ver-b"] = recB

	uc := application2.NewDiffWalksUseCase(store)
	diff, err := uc.Diff(context.Background(), "diff-ver-a", "diff-ver-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.VersionChanged) != 1 {
		t.Errorf("expected 1 version change, got %+v", diff.VersionChanged)
	}
	if diff.VersionChanged[0].VersionA != "v1.0.0" || diff.VersionChanged[0].VersionB != "v2.0.0" {
		t.Errorf("unexpected version change: %+v", diff.VersionChanged[0])
	}
}

func TestDiffWalksUseCase_StatusChanged(t *testing.T) {
	store := newFakeWalkStore()
	target := coord("github.com/example/d", "v1.0.0")
	dep := coord("github.com/example/dep", "v1.0.0")

	recA := buildRecordWithDep("diff-st-a", target, dep)
	recB := buildRecordWithFailedDep("diff-st-b", target, dep)
	store.walks["diff-st-a"] = recA
	store.walks["diff-st-b"] = recB

	uc := application2.NewDiffWalksUseCase(store)
	diff, err := uc.Diff(context.Background(), "diff-st-a", "diff-st-b")
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.StatusChanged) != 1 {
		t.Errorf("expected 1 status change, got %+v", diff.StatusChanged)
	}
}

func TestDiffWalksUseCase_NotFound(t *testing.T) {
	store := newFakeWalkStore()
	uc := application2.NewDiffWalksUseCase(store)
	_, err := uc.Diff(context.Background(), "missing-a", "missing-b")
	if !errors.Is(err, walkports.ErrWalkNotFound) {
		t.Errorf("expected ErrWalkNotFound, got %v", err)
	}
}

// ---- depth-aware cache tests ----

func TestExecuteWalkUseCase_ShallowCacheHit_ForShallowRequest(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildShallowRecord(priorID, target)

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{
		Target: target,
		Depth:  domain.WalkDepthShallow,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Shallow request should reuse the shallow cache hit.
	if result.Record.ID != priorID {
		t.Errorf("expected shallow cache hit with ID %q, got %q", priorID, result.Record.ID)
	}
}

func TestExecuteWalkUseCase_ShallowCacheMiss_ForFullRequest(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildShallowRecord(priorID, target)

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{
		Target: target,
		Depth:  domain.WalkDepthFull,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Full request must NOT reuse shallow cache; expect a fresh walk.
	if result.Record.ID == priorID {
		t.Errorf("full request must not use shallow cache hit, but got prior ID %q", priorID)
	}
}

func TestExecuteWalkUseCase_FullCacheHit_ForShallowRequest(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildMinimalRecord(priorID, target) // full, succeeded

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{
		Target: target,
		Depth:  domain.WalkDepthShallow,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// A full walk satisfies a shallow request.
	if result.Record.ID != priorID {
		t.Errorf("shallow request should accept full cache hit with ID %q, got %q", priorID, result.Record.ID)
	}
}

func TestExecuteWalkUseCase_ShallowRecordHasShallowDepth(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "0.3.0", discardLogger())
	result, err := uc.Execute(context.Background(), application2.WalkRequest{
		Target: target,
		Depth:  domain.WalkDepthShallow,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.Depth != domain.WalkDepthShallow {
		t.Errorf("Depth = %q, want %q", result.Record.Depth, domain.WalkDepthShallow)
	}
}

// ---- helpers ----

func buildShallowRecord(id string, target coordinate.ModuleCoordinate) domain.WalkRecord {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target:          target,
			Nodes:           []domain.GraphNode{{Coordinate: target, ResolutionSource: domain.ResolutionTarget}},
			Partial:         true,
			PartialReason:   "shallow",
			ResolvedAt:      now,
			PipelineVersion: application2.PipelineVersion,
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {Coordinate: target, Status: domain.NodeSucceeded},
		},
		StartedAt:     now,
		CompletedAt:   now.Add(5 * time.Millisecond),
		OverallStatus: domain.WalkSucceeded,
	}
	rec := domain.NewWalkRecord(id, "test-op", "0.3.0", domain.WalkScopeCode, domain.WalkDepthShallow, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func buildMinimalRecord(id string, target coordinate.ModuleCoordinate) domain.WalkRecord {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target:          target,
			Nodes:           []domain.GraphNode{{Coordinate: target, ResolutionSource: domain.ResolutionTarget}},
			ResolvedAt:      now,
			PipelineVersion: application2.PipelineVersion,
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {Coordinate: target, Status: domain.NodeSucceeded},
		},
		StartedAt:     now,
		CompletedAt:   now.Add(10 * time.Millisecond),
		OverallStatus: domain.WalkSucceeded,
	}
	rec := domain.NewWalkRecord(id, "test-op", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func buildRecordWithDep(id string, target, dep coordinate.ModuleCoordinate) domain.WalkRecord {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target: target,
			Nodes: []domain.GraphNode{
				{Coordinate: target, ResolutionSource: domain.ResolutionTarget},
				{Coordinate: dep, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
			},
			Edges:           []domain.GraphEdge{{From: target, To: dep, ConstraintVersion: dep.Version}},
			ResolvedAt:      now,
			PipelineVersion: application2.PipelineVersion,
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {Coordinate: target, Status: domain.NodeSucceeded},
			dep:    {Coordinate: dep, Status: domain.NodeSucceeded},
		},
		StartedAt:     now,
		CompletedAt:   now.Add(10 * time.Millisecond),
		OverallStatus: domain.WalkSucceeded,
	}
	rec := domain.NewWalkRecord(id, "test-op", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func buildRecordWithFailedDep(id string, target, dep coordinate.ModuleCoordinate) domain.WalkRecord {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target: target,
			Nodes: []domain.GraphNode{
				{Coordinate: target, ResolutionSource: domain.ResolutionTarget},
				{Coordinate: dep, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
			},
			Edges:           []domain.GraphEdge{{From: target, To: dep, ConstraintVersion: dep.Version}},
			ResolvedAt:      now,
			PipelineVersion: application2.PipelineVersion,
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {Coordinate: target, Status: domain.NodeSucceeded},
			dep: {
				Coordinate: dep,
				Status:     domain.NodeFetchFailed,
				Error:      &domain.StoredError{Type: "fetch_failed", Message: "timeout"},
			},
		},
		StartedAt:     now,
		CompletedAt:   now.Add(10 * time.Millisecond),
		OverallStatus: domain.WalkPartial,
	}
	rec := domain.NewWalkRecord(id, "test-op", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func buildPartialRecord(id string, target coordinate.ModuleCoordinate) domain.WalkRecord {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	dep := coordinate.ModuleCoordinate{Path: "github.com/example/dep", Version: "v1.0.0"}
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target: target,
			Nodes: []domain.GraphNode{
				{Coordinate: target, ResolutionSource: domain.ResolutionTarget},
				{Coordinate: dep, DirectDependency: true, ResolutionSource: domain.ResolutionMVS},
			},
			ResolvedAt:      now,
			PipelineVersion: application2.PipelineVersion,
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {Coordinate: target, Status: domain.NodeSucceeded},
			dep:    {Coordinate: dep, Status: domain.NodeFetchFailed, Error: &domain.StoredError{Type: "fetch_failed", Message: "git rate limit"}},
		},
		StartedAt:     now,
		CompletedAt:   now.Add(time.Second),
		OverallStatus: domain.WalkPartial,
	}
	rec := domain.NewWalkRecord(id, "test-op", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

func buildCancelledRecord(id string, target coordinate.ModuleCoordinate) domain.WalkRecord {
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	outcome := domain.WalkOutcome{
		Target: target,
		Graph: domain.Graph{
			Target:          target,
			Nodes:           []domain.GraphNode{{Coordinate: target, ResolutionSource: domain.ResolutionTarget}},
			ResolvedAt:      now,
			PipelineVersion: application2.PipelineVersion,
		},
		PerNodeResults: map[coordinate.ModuleCoordinate]domain.NodeResult{
			target: {Coordinate: target, Status: domain.NodeSucceeded},
		},
		StartedAt:     now,
		CompletedAt:   now.Add(500 * time.Millisecond),
		OverallStatus: domain.WalkCancelled,
	}
	rec := domain.NewWalkRecord(id, "test-op", "0.3.0", domain.WalkScopeCode, domain.WalkDepthFull, outcome, domain.DefaultDepthPolicy(), "")
	var h domain.WalkRecordHasher
	rec, err := h.SetContentHash(rec)
	if err != nil {
		panic(err)
	}
	return rec
}

// A cached walk resolved by superseded graph logic must be re-resolved, not
// served. The pipeline version is what lets a corrected resolver take effect on
// its own; without this gate a graph known to be incomplete (for instance one
// that predates require-path node keying, which dropped a replaced module that
// shares its target path with an independent requirement) would keep being
// handed out as authoritative until someone happened to pass --force.
func TestExecuteWalkUseCase_StalePipelineVersionIsReresolved(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	stale := buildMinimalRecord(priorID, target) // WalkSucceeded
	stale.Graph.PipelineVersion = "0.0.1-superseded"
	store.walks[priorID] = stale

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "", discardLogger())

	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ID == priorID {
		t.Fatalf("stale-pipeline walk %q was served from cache; it must be re-resolved", priorID)
	}
	if got := result.Record.Graph.PipelineVersion; got != application2.PipelineVersion {
		t.Errorf("re-resolved graph pipeline version = %q, want %q", got, application2.PipelineVersion)
	}
}

// The gate must not re-resolve a walk that is already current — that would
// discard the cache entirely and make every run pay for a full re-walk.
func TestExecuteWalkUseCase_CurrentPipelineVersionStillCached(t *testing.T) {
	walker := buildMinimalWalker("github.com/example/m", "v1.0.0")
	store := newFakeWalkStore()
	target := coord("github.com/example/m", "v1.0.0")

	priorID := "01JZZZZZZZZZZZZZZZZZZZZZZA"
	store.walks[priorID] = buildMinimalRecord(priorID, target) // current PipelineVersion

	uc := application2.NewExecuteWalkUseCase(walker, store, "test-op", "", discardLogger())

	result, err := uc.Execute(context.Background(), application2.WalkRequest{Target: target})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ID != priorID {
		t.Errorf("current-pipeline walk should be served from cache; got %q want %q", result.Record.ID, priorID)
	}
}
