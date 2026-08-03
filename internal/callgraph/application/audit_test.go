package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// recordingSink captures the events an extraction appends.
type recordingSink struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (s *recordingSink) RecordEvent(e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, e)
	return nil
}

func (s *recordingSink) recorded() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestLocalExecute_AppendsCallGraphExtractedEvent is the headline guard for the
// gap this fixes: the working-tree route wrote a generation to the store and
// appended nothing to the assurance log, so a stable line count read as "nothing
// ran" while the ledger gained rows.
func TestLocalExecute_AppendsCallGraphExtractedEvent(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{
		OverallStatus:  domain.CallGraphStatusExtracted,
		Completeness:   domain.CompletenessBuiltWithBodies,
		AnalysisSource: domain.AnalysisSourceWorktree,
		WorktreeDigest: "sha256:tree",
	}}
	sink := &recordingSink{}
	uc := application.NewExtractLocalCallGraphUseCase(application.LocalConfig{
		Store:           store,
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          discardLogger(),
	}).WithAudit(sink)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Type != audit.EventCallGraphExtracted {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventCallGraphExtracted)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
	// The payload must identify the write without carrying the graph.
	want := map[string]any{
		"module":           testCoord.Path(),
		"version":          testCoord.Version(),
		"pipeline_version": testPipelineV,
		"completeness":     domain.CompletenessBuiltWithBodies.String(),
		"analysis_source":  domain.AnalysisSourceWorktree.String(),
		"content_hash":     res.Record.ContentHash,
		"worktree_digest":  "sha256:tree",
	}
	for k, v := range want {
		if got := ev.Payload[k]; got != v {
			t.Errorf("payload[%q] = %v, want %v", k, got, v)
		}
	}
	if _, ok := ev.Payload["overall_status"]; !ok {
		t.Errorf("payload names no overall_status")
	}
	if _, ok := ev.Payload["nodes"]; ok {
		t.Errorf("payload carries the graph body; it must only identify the write")
	}
	// A working-tree analysis names no artefact, so the field is absent rather
	// than empty — an empty identity would read as an artefact that hashed to
	// nothing.
	if _, ok := ev.Payload["artefact_identity"]; ok {
		t.Errorf("payload names an artefact identity for a working-tree analysis")
	}
}

// TestLocalExecute_AuditSinkFailureIsReported guards the posture the other
// stages already take: the record is written first and an append that fails is
// reported, never swallowed.
func TestLocalExecute_AuditSinkFailureIsReported(t *testing.T) {
	sinkErr := errors.New("disk full")
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted}}
	uc := application.NewExtractLocalCallGraphUseCase(application.LocalConfig{
		Store:           store,
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          discardLogger(),
	}).WithAudit(&recordingSink{err: sinkErr})

	_, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("Execute error = %v, want it to report the sink failure", err)
	}
	// The record is persisted before the event: the write happened, and the
	// failure is about recording it, not about performing it.
	if _, ok, _ := store.GetCallGraphRecord(context.Background(), testCoord, testPipelineV); !ok {
		t.Errorf("record not persisted; the append failure must not undo the write")
	}
}

// TestLocalExecute_NoSinkAppendsNothing guards the optional-dependency contract:
// a use case built without a sink still extracts.
func TestLocalExecute_NoSinkAppendsNothing(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted}}
	uc := buildLocalUseCase(store, analyser)
	if _, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

// TestExecute_AppendsCallGraphExtractedEvent covers the other write path: the
// fetched-artefact route. It names the artefact it read, which the working-tree
// route cannot.
func TestExecute_AppendsCallGraphExtractedEvent(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{
		OverallStatus:  domain.CallGraphStatusExtracted,
		Completeness:   domain.CompletenessBuiltWithBodies,
		AnalysisSource: domain.AnalysisSourceModuleZip,
	}}
	storeFetchRecord(t, facts, blobs, testCoord)

	sink := &recordingSink{}
	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:           facts,
		Blobs:           blobs,
		Store:           store,
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          discardLogger(),
	}).WithAudit(sink)

	res, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	if events[0].Type != audit.EventCallGraphExtracted {
		t.Errorf("event type = %q, want %q", events[0].Type, audit.EventCallGraphExtracted)
	}
	if got := events[0].Payload["artefact_identity"]; got != res.Record.ArtefactIdentity || got == "" {
		t.Errorf("payload artefact_identity = %v, want %q", got, res.Record.ArtefactIdentity)
	}

	// A second Execute is served from cache, which is not a write and must not
	// append: the event says a generation was persisted.
	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("Execute (cached): %v", err)
	}
	if got := len(sink.recorded()); got != 1 {
		t.Errorf("appended %d events after a cache hit, want the original 1", got)
	}
}
