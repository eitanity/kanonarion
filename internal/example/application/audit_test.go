package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/example/ports"

	goast "github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
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

var _ ports.AuditSink = (*recordingSink)(nil)

// auditUseCase builds a harvesting use case over the given fakes with a sink
// wired. It mirrors buildUseCase, which cannot take one.
func auditUseCase(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	examples *fakeExampleStore,
	sink ports.AuditSink,
) *application.ExtractExampleUseCase {
	t.Helper()
	return application.NewExtractExampleUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Examples:  examples,
		Parser:    goast.New(),
		Clock:     fakeClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).WithAudit(sink)
}

// seedFetchedModule stores a fetch record and a zip carrying one example.
func seedFetchedModule(t *testing.T) (coordinate.ModuleCoordinate, *fakeFactStore, *fakeBlobStore) {
	t.Helper()
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go":      "package client\n\n// Client calls the service.\ntype Client struct{}\n",
		"client_test.go": "package client_test\n\nfunc ExampleClient() {\n}\n",
	})
	putFactWithBlob(t, facts, blobs, coord, zipData)
	return coord, facts, blobs
}

// TestExecute_AppendsExamplesExtractedEvent is the headline guard for the gap
// this fixes: the stage persisted an example generation and appended nothing to
// the assurance log, so a stable line count read as "nothing ran" while the
// ledger gained rows.
func TestExecute_AppendsExamplesExtractedEvent(t *testing.T) {
	coord, facts, blobs := seedFetchedModule(t)
	sink := &recordingSink{}
	uc := auditUseCase(t, facts, blobs, &fakeExampleStore{}, sink)

	res, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Type != audit.EventExamplesExtracted {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventExamplesExtracted)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
	// The payload must identify the write without carrying the examples.
	want := map[string]any{
		"module":              coord.Path(),
		"version":             coord.Version(),
		"pipeline_version":    application.PipelineVersion,
		"overall_status":      res.Record.OverallStatus.String(),
		"example_count":       len(res.Record.Examples),
		"parse_failure_count": len(res.Record.ParseFailures),
		"content_hash":        res.Record.ContentHash,
		"artefact_identity":   res.Record.ArtefactIdentity,
		"source_content_hash": res.Record.SourceContentHash,
	}
	for k, v := range want {
		if got := ev.Payload[k]; got != v {
			t.Errorf("payload[%q] = %v, want %v", k, got, v)
		}
	}
	if len(res.Record.Examples) == 0 {
		t.Error("record carries no examples; the count assertion above is vacuous")
	}
	if res.Record.ArtefactIdentity == "" {
		t.Error("record names no artefact; the payload assertion above is vacuous")
	}
	if _, ok := ev.Payload["examples"]; ok {
		t.Error("payload carries the example bodies; it must only identify the write")
	}
	if _, ok := ev.Payload["failure_detail"]; ok {
		t.Error("payload states a failure_detail for a clean extraction")
	}

	// CACHE HIT: a second Execute is served from cache, which is not a write and
	// must not append.
	res2, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute (cached): %v", err)
	}
	if !res2.FromCache {
		t.Fatal("second Execute was not served from cache; the zero below would prove nothing")
	}
	if got := len(sink.recorded()); got != 1 {
		t.Errorf("appended %d events after a cache hit, want the original 1", got)
	}

	// CONTROL for that zero: forcing a re-extraction is a write, and appends again.
	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord, Force: true}); err != nil {
		t.Fatalf("Execute (forced): %v", err)
	}
	if got := len(sink.recorded()); got != 2 {
		t.Errorf("appended %d events after a forced re-extraction, want 2", got)
	}
}

// TestExecute_AuditSinkFailureIsReported guards the posture the other stages
// take: the record is written first and an append that fails is reported, never
// swallowed.
func TestExecute_AuditSinkFailureIsReported(t *testing.T) {
	coord, facts, blobs := seedFetchedModule(t)
	sinkErr := errors.New("disk full")
	store := &fakeExampleStore{}
	uc := auditUseCase(t, facts, blobs, store, &recordingSink{err: sinkErr})

	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("Execute error = %v, want it to report the sink failure", err)
	}
	// The record is persisted before the event: the write happened, and the
	// failure is about recording it, not about performing it.
	if _, ok, _ := store.GetExampleRecord(context.Background(), coord, application.PipelineVersion); !ok {
		t.Error("record not persisted; the append failure must not undo the write")
	}
}

// TestExecute_NoSinkAppendsNothing guards the optional-dependency contract: a
// use case built without a sink still harvests and persists.
func TestExecute_NoSinkAppendsNothing(t *testing.T) {
	coord, facts, blobs := seedFetchedModule(t)
	store := &fakeExampleStore{}
	uc := buildUseCase(t, facts, blobs, store)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, ok, _ := store.GetExampleRecord(context.Background(), coord, application.PipelineVersion); !ok {
		t.Error("record not persisted without an audit sink")
	}
}

// TestExecute_FailedExtractionAppendsWithReason: a recorded failure is still a
// persisted generation, and the log carries the status and the reason with it.
func TestExecute_FailedExtractionAppendsWithReason(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	putFactWithBlob(t, facts, blobs, coord, []byte("not a zip at all"))
	sink := &recordingSink{}
	uc := auditUseCase(t, facts, blobs, &fakeExampleStore{}, sink)

	res, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	if got := events[0].Payload["overall_status"]; got != res.Record.OverallStatus.String() {
		t.Errorf("payload overall_status = %v, want %q", got, res.Record.OverallStatus.String())
	}
	if got, _ := events[0].Payload["failure_detail"].(string); got == "" {
		t.Error("payload states no failure_detail for a failed extraction")
	}
}
