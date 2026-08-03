package application_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/stdlib/application"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// recordingSink captures the events an acquisition appends.
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

// verifiedGoDevAcquirer builds an online acquirer whose tarball matches the
// published checksum, with a sink wired.
func verifiedGoDevAcquirer(t *testing.T, sink ports.AuditSink, store *memStore) *application.Acquirer {
	t.Helper()
	tb := buildTarball(t, map[string]string{"go/LICENSE": "BSD-3-Clause text"})
	m := fakeManifest{releases: []domain.Release{{
		Version: "go1.26.4",
		Files:   []domain.ReleaseFile{{Filename: "go1.26.4.src.tar.gz", Kind: "source", SHA256: sha256hex(tb)}},
	}}}
	return newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{commit: "abc123"},
		fakeLicense{spdx: "BSD-3-Clause"}, store, nil).WithAudit(sink)
}

// anchorsOf reads the verification_anchors list off a payload. The field is
// always present, so a missing one is a failure rather than an empty list.
func anchorsOf(t *testing.T, ev audit.Event) []string {
	t.Helper()
	raw, ok := ev.Payload["verification_anchors"]
	if !ok {
		t.Fatal("payload names no verification_anchors")
	}
	anchors, ok := raw.([]string)
	if !ok {
		t.Fatalf("verification_anchors = %T, want []string", raw)
	}
	return anchors
}

func containsAnchor(anchors []string, want string) bool {
	for _, a := range anchors {
		if a == want {
			return true
		}
	}
	return false
}

// TestAcquire_AppendsCustodyRecordedEvent is the headline guard for the gap this
// fixes: the go.dev/dl route persisted a chain-of-custody measurement and
// appended nothing, so the one record whose whole value is provable observation
// was itself unobserved — an operator could read that the standard library was
// verified but not when, or by which run, that was established.
func TestAcquire_AppendsCustodyRecordedEvent(t *testing.T) {
	sink := &recordingSink{}
	store := newMemStore()
	acq := verifiedGoDevAcquirer(t, sink, store)

	facts, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Type != audit.EventStdlibCustodyRecorded {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventStdlibCustodyRecorded)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
	want := map[string]any{
		"go_version":        "go1.26.4",
		"acquisition_route": domain.RouteGoDev.String(),
		"content_hash":      facts.ContentHash,
		"artefact_identity": domain.ArtefactIdentity(facts),
	}
	for k, v := range want {
		if got := ev.Payload[k]; got != v {
			t.Errorf("payload[%q] = %v, want %v", k, got, v)
		}
	}
	if facts.ContentHash == "" || domain.ArtefactIdentity(facts) == "" {
		t.Error("record carries no seal or no artefact identity; the assertions above are vacuous")
	}

	// Both anchors this acquisition established are named: the published checksum
	// it matched and the googlesource commit it resolved.
	anchors := anchorsOf(t, ev)
	for _, want := range []string{"godev_checksum", "googlesource_commit"} {
		if !containsAnchor(anchors, want) {
			t.Errorf("verification_anchors = %v, want it to name %q", anchors, want)
		}
	}

	// WITNESS, NOT RESTATEMENT: the log says a record was written and by which
	// route. The record's own claims about the toolchain — its verification
	// verdict, the checksum it was matched against, the licence it carries, the
	// prose detail — stay on the record, which the content hash reaches.
	for _, forbidden := range []string{
		"verification_status", "verification_detail", "published_sha256",
		"license_spdx", "source_url", "content_location",
	} {
		if _, ok := ev.Payload[forbidden]; ok {
			t.Errorf("payload restates the record's claim %q; it must only witness the write", forbidden)
		}
	}

	// CONTROL/CACHE HIT: a second Acquire is served from cache, which is not a
	// write and must not append — the event says a measurement was persisted.
	if _, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{}); err != nil {
		t.Fatalf("Acquire (cached): %v", err)
	}
	if store.puts != 1 {
		t.Fatalf("store.puts = %d after a cache hit, want 1; the zero below would prove nothing", store.puts)
	}
	if got := len(sink.recorded()); got != 1 {
		t.Errorf("appended %d events after a cache hit, want the original 1", got)
	}

	// CONTROL for that zero: a forced re-acquisition IS a write, and appends again.
	if _, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{Force: true}); err != nil {
		t.Fatalf("Acquire (forced): %v", err)
	}
	if got := len(sink.recorded()); got != 2 {
		t.Errorf("appended %d events after a forced re-acquisition, want 2", got)
	}
}

// TestAcquire_UnanchoredAcquisitionNamesNoAnchor: a tarball that could not be
// matched against a published checksum is still a persisted measurement, so it
// is still witnessed — with an empty anchor list, which states that the
// acquisition corroborated nothing rather than passing a verdict on the
// toolchain.
func TestAcquire_UnanchoredAcquisitionNamesNoAnchor(t *testing.T) {
	tb := buildTarball(t, map[string]string{"go/LICENSE": "x"})
	m := fakeManifest{err: errors.New("offline")}
	sink := &recordingSink{}
	acq := newAcquirer(t, m, &fakeTarball{data: tb}, &fakeCommits{}, fakeLicense{}, newMemStore(), nil).
		WithAudit(sink)

	facts, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{SkipVCS: true})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if facts.VerificationStatus != domain.UnverifiedGoDevUnavailable {
		t.Fatalf("status = %s, want UnverifiedGoDevUnavailable", facts.VerificationStatus)
	}
	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	if anchors := anchorsOf(t, events[0]); len(anchors) != 0 {
		t.Errorf("verification_anchors = %v, want none named", anchors)
	}
}

// TestLocalAcquire_AppendsCustodyRecordedEvent: the offline route writes the
// same kind of record, so it must leave the same kind of trace — named by its
// own route and its own anchor, never as a go.dev/dl acquisition.
func TestLocalAcquire_AppendsCustodyRecordedEvent(t *testing.T) {
	tc := &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"}
	src := fakeSource{fsys: stdlibSrcFS(), license: []byte("BSD-3-Clause text")}
	store := newMemStore()
	sink := &recordingSink{}
	acq := newLocalAcquirer(t, tc, src, fakeLicense{spdx: "BSD-3-Clause"}, store).WithAudit(sink)

	facts, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("appended %d audit events, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.Type != audit.EventStdlibCustodyRecorded {
		t.Errorf("event type = %q, want %q", ev.Type, audit.EventStdlibCustodyRecorded)
	}
	if got := ev.Payload["acquisition_route"]; got != domain.RouteLocalToolchain.String() {
		t.Errorf("payload acquisition_route = %v, want %q", got, domain.RouteLocalToolchain.String())
	}
	if got := ev.Payload["content_hash"]; got != facts.ContentHash {
		t.Errorf("payload content_hash = %v, want %q", got, facts.ContentHash)
	}
	anchors := anchorsOf(t, ev)
	if !containsAnchor(anchors, "local_toolchain_source") {
		t.Errorf("verification_anchors = %v, want it to name %q", anchors, "local_toolchain_source")
	}
	// The offline route consults no published checksum and resolves no commit, so
	// it must never name either anchor.
	for _, forbidden := range []string{"godev_checksum", "googlesource_commit"} {
		if containsAnchor(anchors, forbidden) {
			t.Errorf("offline acquisition names anchor %q, which it never consulted", forbidden)
		}
	}

	// CONTROL/CACHE HIT: re-serving the stored measurement is not a write.
	if _, err := acq.Acquire(context.Background(), "v1.26.4", application.Options{}); err != nil {
		t.Fatalf("Acquire (cached): %v", err)
	}
	if store.puts != 1 {
		t.Fatalf("store.puts = %d after a cache hit, want 1; the zero below would prove nothing", store.puts)
	}
	if got := len(sink.recorded()); got != 1 {
		t.Errorf("appended %d events after a cache hit, want the original 1", got)
	}
}

// TestAcquire_CustodyUnavailableAppendsNothing: a run that could not establish
// custody at all wrote no record, so it must witness nothing — an absence is not
// an observation. Paired with a control on the same fakes that does append.
func TestAcquire_CustodyUnavailableAppendsNothing(t *testing.T) {
	sink := &recordingSink{}
	store := newMemStore()
	failing := newAcquirer(t, fakeManifest{}, &fakeTarball{err: errors.New("no network")},
		&fakeCommits{}, fakeLicense{}, store, nil).WithAudit(sink)

	if _, err := failing.Acquire(context.Background(), "go1.26.4", application.Options{}); err == nil {
		t.Fatal("Acquire succeeded without a tarball; the zero below would prove nothing")
	}
	if store.puts != 0 {
		t.Errorf("store.puts = %d, want 0 — nothing was persisted", store.puts)
	}
	if got := len(sink.recorded()); got != 0 {
		t.Errorf("appended %d events for an acquisition that recorded nothing, want 0", got)
	}

	// CONTROL: the same sink, an acquisition that does establish custody.
	if _, err := verifiedGoDevAcquirer(t, sink, newMemStore()).
		Acquire(context.Background(), "go1.26.4", application.Options{}); err != nil {
		t.Fatalf("control Acquire: %v", err)
	}
	if got := len(sink.recorded()); got != 1 {
		t.Errorf("control appended %d events, want 1; the zero above is not evidence without it", got)
	}
}

// TestLocalAcquire_ToolchainUnavailableAppendsNothing: the offline counterpart —
// an unprobeable toolchain establishes no custody, so it witnesses none.
func TestLocalAcquire_ToolchainUnavailableAppendsNothing(t *testing.T) {
	sink := &recordingSink{}
	store := newMemStore()
	acq := newLocalAcquirer(t, &fakeToolchain{err: errors.New("no go binary")},
		fakeSource{fsys: stdlibSrcFS()}, fakeLicense{}, store).WithAudit(sink)

	if _, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{}); err == nil {
		t.Fatal("Acquire succeeded with no toolchain; the zero below would prove nothing")
	}
	if got := len(sink.recorded()); got != 0 {
		t.Errorf("appended %d events for an acquisition that recorded nothing, want 0", got)
	}

	// CONTROL: a probeable toolchain on the same sink does append.
	working := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"},
		fakeSource{fsys: stdlibSrcFS(), license: []byte("BSD-3-Clause text")},
		fakeLicense{spdx: "BSD-3-Clause"}, newMemStore()).WithAudit(sink)
	if _, err := working.Acquire(context.Background(), "go1.26.4", application.Options{}); err != nil {
		t.Fatalf("control Acquire: %v", err)
	}
	if got := len(sink.recorded()); got != 1 {
		t.Errorf("control appended %d events, want 1; the zero above is not evidence without it", got)
	}
}

// TestAcquire_AuditSinkFailureIsReported guards the posture the other contexts
// take: the measurement is written first and an append that fails is reported,
// never swallowed.
func TestAcquire_AuditSinkFailureIsReported(t *testing.T) {
	sinkErr := errors.New("disk full")
	store := newMemStore()
	acq := verifiedGoDevAcquirer(t, &recordingSink{err: sinkErr}, store)

	_, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("Acquire error = %v, want it to report the sink failure", err)
	}
	// The measurement is persisted before the event: the write happened, and the
	// failure is about recording it, not about performing it.
	if store.puts != 1 {
		t.Errorf("store.puts = %d, want 1; the append failure must not undo the write", store.puts)
	}
}

// TestLocalAcquire_AuditSinkFailureIsReported: the offline route reports it too.
func TestLocalAcquire_AuditSinkFailureIsReported(t *testing.T) {
	sinkErr := errors.New("disk full")
	store := newMemStore()
	acq := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"},
		fakeSource{fsys: stdlibSrcFS(), license: []byte("BSD-3-Clause text")},
		fakeLicense{spdx: "BSD-3-Clause"}, store).WithAudit(&recordingSink{err: sinkErr})

	_, err := acq.Acquire(context.Background(), "go1.26.4", application.Options{})
	if !errors.Is(err, sinkErr) {
		t.Fatalf("Acquire error = %v, want it to report the sink failure", err)
	}
	if store.puts != 1 {
		t.Errorf("store.puts = %d, want 1; the append failure must not undo the write", store.puts)
	}
}

// TestAcquire_NoSinkStillPersists guards the optional-dependency contract on
// both routes: an acquirer built without a sink still acquires and persists.
func TestAcquire_NoSinkStillPersists(t *testing.T) {
	store := newMemStore()
	if _, err := verifiedGoDevAcquirer(t, nil, store).
		Acquire(context.Background(), "go1.26.4", application.Options{}); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if store.puts != 1 {
		t.Errorf("store.puts = %d without an audit sink, want 1", store.puts)
	}

	localStore := newMemStore()
	local := newLocalAcquirer(t, &fakeToolchain{goRoot: "/opt/go", version: "go1.26.4"},
		fakeSource{fsys: stdlibSrcFS(), license: []byte("BSD-3-Clause text")},
		fakeLicense{spdx: "BSD-3-Clause"}, localStore)
	if _, err := local.Acquire(context.Background(), "go1.26.4", application.Options{}); err != nil {
		t.Fatalf("LocalAcquire: %v", err)
	}
	if localStore.puts != 1 {
		t.Errorf("local store.puts = %d without an audit sink, want 1", localStore.puts)
	}
}
