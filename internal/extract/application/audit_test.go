package application

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// recordingSink captures the events a run appends.
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

var _ ports.AuditSink = (*recordingSink)(nil)

// auditFixture builds a use case over a two-node walk: one ordinary dependency
// whose stages run, and the local main module, which has no fetched artefact and
// is skipped-with-reason. The run therefore records both outcome kinds.
func auditFixture(t *testing.T, sink ports.AuditSink) (*ExtractUseCase, string) {
	t.Helper()
	dep, err := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	root, err := coordinate.NewLocalCoordinate("example.test/proj")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	walkID := "walk-audit"
	walk := walkdomain.WalkRecord{
		Target: root,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
			{Coordinate: dep},
			{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
		}},
	}
	uc := NewExtractUseCase(Config{
		Runs:      &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)},
		Walks:     &mockWalkStore{walks: map[string]walkdomain.WalkRecord{walkID: walk}},
		Extractor: &mockExtractor{},
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
		Workers:   1,
	})
	if sink != nil {
		uc = uc.WithAudit(sink)
	}
	return uc, walkID
}

// TestExecute_AppendsExtractionRunCompletedEvent is the headline guard for the
// gap this fixes: the orchestrator persisted a run record and appended nothing
// to the assurance log, so the campaign that drove a batch of stage writes left
// no trace of itself.
func TestExecute_AppendsExtractionRunCompletedEvent(t *testing.T) {
	sink := &recordingSink{}
	uc, walkID := auditFixture(t, sink)

	run, err := uc.Execute(context.Background(), ExtractRequest{
		WalkID: walkID,
		Stages: []string{"license", "interface"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Type != audit.EventExtractionRunCompleted {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventExtractionRunCompleted)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
	want := map[string]any{
		"run_id":           run.ID,
		"walk_id":          walkID,
		"module_count":     2,
		"stages_succeeded": 2, // the dependency's two stages
		"stages_failed":    0,
		"stages_skipped":   2, // the local main module's two stages
		"overall_status":   domain.ExtractionRunSucceeded.String(),
		"content_hash":     run.ContentHash,
	}
	for k, v := range want {
		if got := ev.Payload[k]; got != v {
			t.Errorf("payload[%q] = %v, want %v", k, got, v)
		}
	}
	stages, _ := ev.Payload["requested_stages"].([]string)
	if len(stages) != 2 || stages[0] != "license" || stages[1] != "interface" {
		t.Errorf("payload requested_stages = %v, want [license interface]", ev.Payload["requested_stages"])
	}
	if run.ContentHash == "" {
		t.Error("run carries no content hash; the payload assertion above is vacuous")
	}
	if _, ok := ev.Payload["per_module_results"]; ok {
		t.Error("payload carries the run body; it must only identify the write")
	}

	// The orchestrator has no cache branch: it persists a run record on every
	// invocation, so a second run is a second write and appends again. This is
	// the control for the per-stage cache-hit zeros — a stage that appended
	// nothing was served from cache, not silenced.
	if _, err := uc.Execute(context.Background(), ExtractRequest{WalkID: walkID, Stages: []string{"license"}}); err != nil {
		t.Fatalf("Execute (second run): %v", err)
	}
	if got := len(sink.recorded()); got != 2 {
		t.Errorf("appended %d events after a second run, want 2", got)
	}
}

// TestExecute_AuditSinkFailureIsReported guards the house posture: the run is
// written first and an append that fails is reported, never swallowed.
func TestExecute_AuditSinkFailureIsReported(t *testing.T) {
	sinkErr := errors.New("disk full")
	uc, walkID := auditFixture(t, &recordingSink{err: sinkErr})

	_, err := uc.Execute(context.Background(), ExtractRequest{WalkID: walkID, Stages: []string{"license"}})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("Execute error = %v, want it to report the sink failure", err)
	}
	// The run is persisted before the event: the write happened, and the failure
	// is about recording it, not about performing it.
	store, ok := uc.runs.(*mockExtractionStore)
	if !ok {
		t.Fatalf("fixture store is %T, want *mockExtractionStore", uc.runs)
	}
	if len(store.runs) != 1 {
		t.Errorf("store holds %d runs, want 1; the append failure must not undo the write", len(store.runs))
	}
}

// TestExecute_NoSinkAppendsNothing guards the optional-dependency contract: a
// use case built without a sink still runs and persists.
func TestExecute_NoSinkAppendsNothing(t *testing.T) {
	uc, walkID := auditFixture(t, nil)
	run, err := uc.Execute(context.Background(), ExtractRequest{WalkID: walkID, Stages: []string{"license"}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if run.ID == "" {
		t.Error("no run produced without an audit sink")
	}
}

// TestExecute_FailedStageCountsInTheEvent: a run whose stages failed still
// writes a run record, and the event states how many failed alongside the
// overall status.
func TestExecute_FailedStageCountsInTheEvent(t *testing.T) {
	sink := &recordingSink{}
	uc, walkID := auditFixture(t, sink)

	// The fixture extractor fails the licence stage when the run is forced.
	run, err := uc.Execute(context.Background(), ExtractRequest{
		WalkID: walkID,
		Stages: []string{"license"},
		Force:  true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if run.OverallStatus != domain.ExtractionRunPartial {
		t.Fatalf("OverallStatus = %v, want partial; the assertions below would not exercise a failure", run.OverallStatus)
	}
	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	if got := events[0].Payload["stages_failed"]; got != 1 {
		t.Errorf("payload stages_failed = %v, want 1", got)
	}
	if got := events[0].Payload["overall_status"]; got != domain.ExtractionRunPartial.String() {
		t.Errorf("payload overall_status = %v, want %q", got, domain.ExtractionRunPartial.String())
	}
}
