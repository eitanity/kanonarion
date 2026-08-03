package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// snapshotAuditNow is the instant every test in this file pins its clock and
// its snapshot retrieval to, so the payload's retrieval instant is checked
// against a value the test states rather than one it reads back.
var snapshotAuditNow = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

// seedSnapshotAuditModule gives a coordinate the fetch record and blob a scan
// needs to reach the scanner, and returns it. It is a thin wrapper over
// seedScannableModule so these tests state the module path once.
func seedSnapshotAuditModule(t *testing.T, facts *fakeFacts, blobs *fakeBlob, coordPath string) coordinate.ModuleCoordinate {
	t.Helper()
	coord := coordinatetest.MustNew(coordPath, "v1.0.0")
	seedScannableModule(t, facts, blobs, coord)
	return coord
}

// TestScanModule_AppendsAdvisorySnapshotRecorded is the headline guard for the
// gap this closes: the scan downloaded an advisory database and persisted it
// with no ledger event at all, so "what did we know, and when did we come to
// know it" had no dated observation behind it.
func TestScanModule_AppendsAdvisorySnapshotRecorded(t *testing.T) {
	ctx := t.Context()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	coord := seedSnapshotAuditModule(t, facts, blobs, "github.com/foo/bar")

	snap := vulntest.MustSealOver("vuln.go.dev", "2026-02-03T00:00:00Z", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	sink := &recordingAuditSink{}
	uc := application.NewScanModuleUseCase(
		facts, blobs, newFakeVulnStore(), nil, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	events := sink.ofType(audit.EventAdvisorySnapshotRecorded)
	if len(events) != 1 {
		t.Fatalf("advisory_snapshot_recorded events = %d, want 1", len(events))
	}
	p := events[0].Payload
	assertPayload(t, p, "snapshot_source", "vuln.go.dev")
	assertPayload(t, p, "snapshot_version", "2026-02-03T00:00:00Z")
	assertPayload(t, p, "retrieved_at", "2026-02-03T04:05:06Z")
	assertPayload(t, p, "acquisition_route", "module_scan")
	assertPayload(t, p, "content_hash", snap.ContentHash())
}

// TestScanModule_SnapshotEventWitnessesOnlyThePersist pins what the event must
// NOT say. It witnesses the arrival of an advisory set and its route; the
// advisories themselves, how many there are and any module's standing against
// them are the snapshot's and the scan record's claims. A payload that grew
// them would make the log an unsealed copy of an advisory set upstream can
// still withdraw from under the same version string.
func TestScanModule_SnapshotEventWitnessesOnlyThePersist(t *testing.T) {
	ctx := t.Context()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	coord := seedSnapshotAuditModule(t, facts, blobs, "github.com/foo/bar")

	snap := vulntest.MustSealOver("vuln.go.dev", "gen-1", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{
		snapshot:    snap,
		content:     "vulndb content",
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-TEST-0001"}},
	}
	sink := &recordingAuditSink{}
	uc := application.NewScanModuleUseCase(
		facts, blobs, newFakeVulnStore(), nil, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	events := sink.ofType(audit.EventAdvisorySnapshotRecorded)
	if len(events) != 1 {
		t.Fatalf("advisory_snapshot_recorded events = %d, want 1", len(events))
	}
	want := map[string]struct{}{
		"snapshot_source": {}, "snapshot_version": {}, "retrieved_at": {},
		"acquisition_route": {}, "content_hash": {},
	}
	for k := range events[0].Payload {
		if _, ok := want[k]; !ok {
			t.Errorf("payload carries %q; the event witnesses the persist and its route, not the advisory set's contents", k)
		}
	}
	if len(events[0].Payload) != len(want) {
		t.Errorf("payload has %d fields, want %d", len(events[0].Payload), len(want))
	}
}

// TestScanModule_ReusedSnapshotAppendsNothing is the zero half of the pair:
// reuse is not an acquisition, so a scan handed a snapshot it did not fetch
// appends nothing. The control above proves the same use case DOES append when
// it acquires, so this zero is a decision rather than a sink that never fires.
func TestScanModule_ReusedSnapshotAppendsNothing(t *testing.T) {
	ctx := t.Context()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	coord := seedSnapshotAuditModule(t, facts, blobs, "github.com/foo/bar")

	snap := vulntest.MustSealOver("vuln.go.dev", "gen-1", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	sink := &recordingAuditSink{}
	uc := application.NewScanModuleUseCase(
		facts, blobs, newFakeVulnStore(), nil, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Snapshot: &snap,
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if n := len(sink.ofType(audit.EventAdvisorySnapshotRecorded)); n != 0 {
		t.Errorf("advisory_snapshot_recorded events = %d, want 0: a reused snapshot was acquired on some earlier run, and dating it to this one would report an arrival that never happened", n)
	}
	if db.snapshotCalls.Load() != 0 {
		t.Errorf("database snapshot fetches = %d, want 0", db.snapshotCalls.Load())
	}
}

// TestScanModule_SnapshotAppendFailureIsReported holds the record-written-first
// contract: the snapshot is persisted before the event is appended, and a
// failed append is surfaced rather than swallowed — the store keeps the bytes,
// and the caller learns the log does not know about them.
func TestScanModule_SnapshotAppendFailureIsReported(t *testing.T) {
	ctx := t.Context()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	coord := seedSnapshotAuditModule(t, facts, blobs, "github.com/foo/bar")

	snap := vulntest.MustSealOver("vuln.go.dev", "gen-1", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	store := newFakeVulnStore()
	sink := &failingAuditSink{}
	uc := application.NewScanModuleUseCase(
		facts, blobs, store, nil, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)

	_, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"})
	if err == nil {
		t.Fatal("Scan: expected the failed audit append to be reported")
	}
	if !strings.Contains(err.Error(), "advisory snapshot audit event") {
		t.Errorf("error %q does not name the failed append", err)
	}
	if _, ok, serr := store.GetLatestDatabaseSnapshot(ctx); serr != nil || !ok {
		t.Error("the snapshot must be persisted before the event is appended; a failed append reports an unlogged write, it does not undo one")
	}
}

// TestScanModule_NilSinkAppendsNothing keeps the sink optional, on the same
// terms as every other stage: a use case built without one persists exactly as
// before and never panics reaching for a log it has not got.
func TestScanModule_NilSinkAppendsNothing(t *testing.T) {
	ctx := t.Context()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	coord := seedSnapshotAuditModule(t, facts, blobs, "github.com/foo/bar")

	snap := vulntest.MustSealOver("vuln.go.dev", "gen-1", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	store := newFakeVulnStore()
	uc := application.NewScanModuleUseCase(
		facts, blobs, store, nil, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	)

	if _, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok, serr := store.GetLatestDatabaseSnapshot(ctx); serr != nil || !ok {
		t.Error("a use case without an audit sink must still persist the snapshot")
	}
}

// TestScanWalk_SnapshotDownloadAppendsByItsOwnRoute proves the walk scan's own
// acquisition is witnessed and names the route that took it — the same snapshot
// arriving through a walk scan and through a module scan are two different
// entries in an operator's account of when the advisory set changed.
func TestScanWalk_SnapshotDownloadAppendsByItsOwnRoute(t *testing.T) {
	ctx := t.Context()
	walkID := "walk-snapshot-route"
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	}); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	rec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	snap := vulntest.MustSealOver("vuln.go.dev", "gen-1", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	store := newFakeVulnStore()
	sink := &recordingAuditSink{}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, store, walkStore, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)
	walkUC := application.NewScanWalkUseCase(
		walkStore, store, moduleUC, nil, fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	events := sink.ofType(audit.EventAdvisorySnapshotRecorded)
	if len(events) != 1 {
		t.Fatalf("advisory_snapshot_recorded events = %d, want 1", len(events))
	}
	assertPayload(t, events[0].Payload, "acquisition_route", "walk_scan")
	// The events the walk scan already emitted must be untouched by this change.
	if n := len(sink.ofType(audit.EventVulnScanCompleted)); n != 1 {
		t.Errorf("vuln_scan_completed events = %d, want 1", n)
	}
}

// TestScanWalk_StoredSnapshotAppendsNothing is the walk-side zero, paired with
// the control above: a run that found a snapshot already in the store acquired
// nothing, transferred nothing, and appends nothing.
func TestScanWalk_StoredSnapshotAppendsNothing(t *testing.T) {
	ctx := t.Context()
	walkID := "walk-snapshot-reuse"
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	}); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	rec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	snap := vulntest.MustSealOver("vuln.go.dev", "gen-1", snapshotAuditNow, []byte("vulndb content"))
	store := newFakeVulnStore()
	if err := store.PutDatabaseSnapshot(ctx, snap, strings.NewReader("vulndb content")); err != nil {
		t.Fatalf("PutDatabaseSnapshot: %v", err)
	}
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	sink := &recordingAuditSink{}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, store, walkStore, &fakeScanner{}, db, nil,
		fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)
	walkUC := application.NewScanWalkUseCase(
		walkStore, store, moduleUC, nil, fixedClock{t: snapshotAuditNow}, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if n := len(sink.ofType(audit.EventAdvisorySnapshotRecorded)); n != 0 {
		t.Errorf("advisory_snapshot_recorded events = %d, want 0 for a snapshot the store already held", n)
	}
	if n := len(sink.ofType(audit.EventVulnScanCompleted)); n != 1 {
		t.Errorf("vuln_scan_completed events = %d, want 1: the zero above must be a decision about snapshots, not a silent sink", n)
	}
}

// assertPayload checks one payload field, reporting the field name so a failure
// says which claim moved rather than dumping the whole map.
func assertPayload(t *testing.T, payload map[string]any, key string, want any) {
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

// failingAuditSink refuses every append, so a test can prove a failed append is
// reported rather than swallowed.
type failingAuditSink struct{}

func (failingAuditSink) RecordEvent(audit.Event) error { return errAuditAppend }

var errAuditAppend = errSnapshotAudit{}

type errSnapshotAudit struct{}

func (errSnapshotAudit) Error() string { return "assurance log unavailable" }

// TestRescan_SnapshotDownloadAppendsByItsOwnRoute covers the third acquisition
// site. A re-scan's whole purpose is to judge against a newer advisory set, so
// the moment that set arrived is the fact the re-scan rests on, and it must not
// be filed under the walk scan it delegates to.
func TestRescan_SnapshotDownloadAppendsByItsOwnRoute(t *testing.T) {
	ctx := t.Context()
	target := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	walk, ws, facts, blobs := makeWalkWithModules(t, target)

	snap := vulntest.MustSealOver("vuln.go.dev", "fresh-1", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: snap, content: "vulndb content"}
	store := newFakeVulnStore()
	sink := &recordingAuditSink{}
	clock := fixedClock{t: snapshotAuditNow}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, store, ws, &fakeScanner{}, db, nil, clock, "v1", slog.Default(),
	).WithAudit(sink)
	rescanner := application.NewRescanWalkUseCase(
		ws, store, moduleUC, nil, clock, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := rescanner.Rescan(ctx, application.RescanRequest{WalkID: walk.ID}); err != nil {
		t.Fatalf("Rescan: %v", err)
	}

	events := sink.ofType(audit.EventAdvisorySnapshotRecorded)
	if len(events) != 1 {
		t.Fatalf("advisory_snapshot_recorded events = %d, want 1", len(events))
	}
	assertPayload(t, events[0].Payload, "acquisition_route", "walk_rescan")
	assertPayload(t, events[0].Payload, "snapshot_version", "fresh-1")
}

// TestRescan_PinnedSnapshotAppendsNothing is the zero paired with it: a re-scan
// handed a snapshot acquired it from nowhere, and the control above proves the
// same use case and sink do append when a download happens.
func TestRescan_PinnedSnapshotAppendsNothing(t *testing.T) {
	ctx := t.Context()
	target := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	walk, ws, facts, blobs := makeWalkWithModules(t, target)

	pinned := vulntest.MustSealOver("vuln.go.dev", "pinned-42", snapshotAuditNow, []byte("vulndb content"))
	db := &fakeDatabase{snapshot: vulntest.MustNew("vuln.go.dev", "network"), content: "vulndb content"}
	store := newFakeVulnStore()
	sink := &recordingAuditSink{}
	clock := fixedClock{t: snapshotAuditNow}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, store, ws, &fakeScanner{}, db, nil, clock, "v1", slog.Default(),
	).WithAudit(sink)
	rescanner := application.NewRescanWalkUseCase(
		ws, store, moduleUC, nil, clock, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := rescanner.Rescan(ctx, application.RescanRequest{WalkID: walk.ID, Snapshot: &pinned}); err != nil {
		t.Fatalf("Rescan: %v", err)
	}

	if n := len(sink.ofType(audit.EventAdvisorySnapshotRecorded)); n != 0 {
		t.Errorf("advisory_snapshot_recorded events = %d, want 0 for a snapshot this run did not acquire", n)
	}
	if n := len(sink.ofType(audit.EventVulnScanCompleted)); n != 1 {
		t.Errorf("vuln_scan_completed events = %d, want 1: the zero above must be a decision about snapshots, not a silent sink", n)
	}
}
