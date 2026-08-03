package application_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
)

// recordingSink captures the events a generation or a serving appends.
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

func (s *recordingSink) ofType(t audit.EventType) []audit.Event {
	var out []audit.Event
	for _, e := range s.recorded() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

var _ ports.AuditSink = (*recordingSink)(nil)

// auditUC builds a generation use case with an audit sink wired, over the same
// fakes the rest of the package's tests use.
func auditUC(ws *fakeWalkStore, ss *fakeSBOMStore, gen *fakeSBOMGenerator, sink ports.AuditSink) *application.GenerateSBOMUseCase {
	return makeUC(ws, ss, gen).WithAudit(sink)
}

// generatedRecord is the document the fake generator produces: an identity, a
// walk, a format and a content hash, which is exactly what the event is
// expected to name.
func generatedRecord() domain.SBOMRecord {
	return domain.SBOMRecord{
		ID:              "sbom-1",
		WalkID:          "walk-1",
		Format:          domain.CycloneDX16,
		PipelineVersion: "0.3.0",
		ContentHash:     "sha256:abc",
		Content:         []byte(`{}`),
		Operator:        "release-bot",
	}
}

// TestGenerate_AppendsSBOMGeneratedEvent is the headline guard for the gap this
// closes: an SBOM — the artefact that leaves the building — was produced and
// its record persisted with nothing appended to the assurance log, so nothing
// said when the document was made or from which walk.
func TestGenerate_AppendsSBOMGeneratedEvent(t *testing.T) {
	ss := &fakeSBOMStore{}
	sink := &recordingSink{}
	uc := auditUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, &fakeSBOMGenerator{record: generatedRecord()}, sink)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	events := sink.ofType(audit.EventSBOMGenerated)
	if len(events) != 1 {
		t.Fatalf("sbom_generated events = %d, want 1", len(events))
	}
	p := events[0].Payload
	assertField(t, p, "sbom_id", "sbom-1")
	assertField(t, p, "walk_id", "walk-1")
	assertField(t, p, "format", string(domain.CycloneDX16))
	assertField(t, p, "pipeline_version", "0.3.0")
	assertField(t, p, "content_hash", "sha256:abc")
	assertField(t, p, "caller_supplied_timestamp", false)
	if n := len(sink.ofType(audit.EventSBOMServed)); n != 0 {
		t.Errorf("sbom_served events = %d, want 0: a freshly produced document was not served from the cache", n)
	}
}

// TestGenerate_EventWitnessesTheWriteNotTheDocument pins the payload's edges.
// The event says a document was made and names the bytes; the document's own
// claims — its components, their licences, its completeness statements — belong
// to the document, which the content hash reaches. Restating them here would
// make the log an unsealed second copy of the artefact.
func TestGenerate_EventWitnessesTheWriteNotTheDocument(t *testing.T) {
	rec := generatedRecord()
	rec.LicensesIncomplete = true
	sink := &recordingSink{}
	uc := auditUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeSBOMStore{}, &fakeSBOMGenerator{record: rec}, sink)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	events := sink.ofType(audit.EventSBOMGenerated)
	if len(events) != 1 {
		t.Fatalf("sbom_generated events = %d, want 1", len(events))
	}
	want := map[string]struct{}{
		"sbom_id": {}, "walk_id": {}, "format": {}, "pipeline_version": {},
		"content_hash": {}, "caller_supplied_timestamp": {},
	}
	for k := range events[0].Payload {
		if _, ok := want[k]; !ok {
			t.Errorf("payload carries %q; the event witnesses the write, and the document carries its own claims", k)
		}
	}
	if len(events[0].Payload) != len(want) {
		t.Errorf("payload has %d fields, want %d", len(events[0].Payload), len(want))
	}
}

// TestGenerate_CallerSuppliedTimestampIsStated covers the one input that makes
// two otherwise identical requests produce different documents: a
// caller-supplied creation time bypasses the cache, so a reader must be able to
// tell a document dated by its caller from one dated from its inputs.
func TestGenerate_CallerSuppliedTimestampIsStated(t *testing.T) {
	sink := &recordingSink{}
	uc := auditUC(&fakeWalkStore{walk: makeWalk("walk-1")}, &fakeSBOMStore{}, &fakeSBOMGenerator{record: generatedRecord()}, sink)

	_, err := uc.Generate(t.Context(), application.SBOMRequest{
		WalkID:      "walk-1",
		GeneratedAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	events := sink.ofType(audit.EventSBOMGenerated)
	if len(events) != 1 {
		t.Fatalf("sbom_generated events = %d, want 1", len(events))
	}
	assertField(t, events[0].Payload, "caller_supplied_timestamp", true)
}

// TestGenerate_CacheHitAppendsServedEvent covers the served half of the
// decision: a stored document handed back is still a document that went out,
// and "when did we last produce this artefact, and how often has it gone out"
// is unanswerable if only the first generation is visible.
func TestGenerate_CacheHitAppendsServedEvent(t *testing.T) {
	cached := generatedRecord()
	ss := &fakeSBOMStore{cached: cached, cachedOK: true}
	sink := &recordingSink{}
	uc := auditUC(&fakeWalkStore{}, ss, &fakeSBOMGenerator{}, sink)

	got, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1", Operator: "auditor"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got.ID != "sbom-1" {
		t.Fatalf("expected the cached record, got %q", got.ID)
	}

	events := sink.ofType(audit.EventSBOMServed)
	if len(events) != 1 {
		t.Fatalf("sbom_served events = %d, want 1", len(events))
	}
	p := events[0].Payload
	assertField(t, p, "sbom_id", "sbom-1")
	assertField(t, p, "walk_id", "walk-1")
	assertField(t, p, "format", string(domain.CycloneDX16))
	assertField(t, p, "pipeline_version", "0.3.0")
	assertField(t, p, "content_hash", "sha256:abc")
	// The requester is this serving's, not the record's operator: the stored
	// record names whoever asked for the original generation, and reporting that
	// name here would answer "who received this document" with the wrong one.
	assertField(t, p, "requested_by", "auditor")
	if n := len(sink.ofType(audit.EventSBOMGenerated)); n != 0 {
		t.Errorf("sbom_generated events = %d, want 0: a served document was not produced by this run", n)
	}
}

// TestGenerate_ServedEventOmitsAnAbsentRequester keeps an unsupplied identity
// out of the payload rather than recording it as an empty string, which would
// read as an anonymous principal that the request never named.
func TestGenerate_ServedEventOmitsAnAbsentRequester(t *testing.T) {
	ss := &fakeSBOMStore{cached: generatedRecord(), cachedOK: true}
	sink := &recordingSink{}
	uc := auditUC(&fakeWalkStore{}, ss, &fakeSBOMGenerator{}, sink)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	events := sink.ofType(audit.EventSBOMServed)
	if len(events) != 1 {
		t.Fatalf("sbom_served events = %d, want 1", len(events))
	}
	if _, ok := events[0].Payload["requested_by"]; ok {
		t.Error("payload carries requested_by when the request named no identity")
	}
}

// TestGenerate_ScopedRequestAppendsNothing is the zero, paired with the control
// in the same test: a package-scoped (--package) document is ephemeral — no
// cache lookup, no record persisted — so it appends nothing, because the event
// states that a record exists and this run leaves none. The unscoped run below
// it proves the same use case and sink DO append.
func TestGenerate_ScopedRequestAppendsNothing(t *testing.T) {
	ctx := t.Context()
	allowed, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	ss := &fakeSBOMStore{}
	sink := &recordingSink{}
	uc := auditUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, &fakeSBOMGenerator{record: generatedRecord()}, sink)

	if _, err := uc.Generate(ctx, application.SBOMRequest{
		WalkID:    "walk-1",
		AllowList: []coordinate.ModuleCoordinate{allowed},
	}); err != nil {
		t.Fatalf("Generate (scoped): %v", err)
	}
	if ss.stored != nil {
		t.Fatal("a package-scoped request must persist nothing")
	}
	if n := len(sink.recorded()); n != 0 {
		t.Errorf("events = %d, want 0 for an ephemeral document", n)
	}

	// Control: the same use case, the same sink, an unscoped request.
	if _, err := uc.Generate(ctx, application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate (unscoped): %v", err)
	}
	if n := len(sink.ofType(audit.EventSBOMGenerated)); n != 1 {
		t.Errorf("sbom_generated events = %d, want 1: the zero above must be a decision about scoped requests, not a silent sink", n)
	}
}

// TestGenerate_AppendFailureIsReported holds the record-written-first contract:
// the record is persisted before the event is appended, and a failed append is
// reported rather than swallowed.
func TestGenerate_AppendFailureIsReported(t *testing.T) {
	ss := &fakeSBOMStore{}
	sink := &recordingSink{err: errors.New("assurance log unavailable")}
	uc := auditUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, &fakeSBOMGenerator{record: generatedRecord()}, sink)

	_, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"})
	if err == nil {
		t.Fatal("Generate: expected the failed audit append to be reported")
	}
	if ss.stored == nil {
		t.Error("the record must be persisted before the event is appended; a failed append reports an unlogged write, it does not undo one")
	}
}

// TestGenerate_ServedAppendFailureIsReported: a serving whose event cannot be
// appended fails rather than handing the document over silently. That is the
// gap itself, not a smaller version of it.
func TestGenerate_ServedAppendFailureIsReported(t *testing.T) {
	ss := &fakeSBOMStore{cached: generatedRecord(), cachedOK: true}
	sink := &recordingSink{err: errors.New("assurance log unavailable")}
	uc := auditUC(&fakeWalkStore{}, ss, &fakeSBOMGenerator{}, sink)

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err == nil {
		t.Fatal("Generate: expected the failed audit append to be reported")
	}
}

// TestGenerate_NilSinkAppendsNothing keeps the sink optional: a use case built
// without one persists exactly as before and never reaches for a log it has
// not got.
func TestGenerate_NilSinkAppendsNothing(t *testing.T) {
	ss := &fakeSBOMStore{}
	uc := makeUC(&fakeWalkStore{walk: makeWalk("walk-1")}, ss, &fakeSBOMGenerator{record: generatedRecord()})

	if _, err := uc.Generate(t.Context(), application.SBOMRequest{WalkID: "walk-1"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if ss.stored == nil {
		t.Error("a use case without an audit sink must still persist the record")
	}
}

// assertField checks one payload field, naming it so a failure says which claim
// moved rather than dumping the whole map.
func assertField(t *testing.T, payload map[string]any, key string, want any) {
	t.Helper()
	got, ok := payload[key]
	if !ok {
		t.Errorf("payload has no %q", key)
		return
	}
	if got != want {
		t.Errorf("payload[%q] = %v, want %v", key, got, want)
	}
}
