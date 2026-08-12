package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// TestServeReusableRun_AppendsOneServedEvent is the headline: a stored run that
// is handed back instead of measured leaves a trace. Before this existed, reuse
// appended nothing at all — record and ledger timestamps tracked when evidence
// was DERIVED, so "when did we last check" was unrecoverable from the store.
//
// The control is the run's own derivation: reuse measures nothing, so the ONLY
// event a serving may append is this one, and the assertion is on the whole
// event list rather than on a filtered view of it.
func TestServeReusableRun_AppendsOneServedEvent(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	sink := &recordingAuditSink{}
	uc.WithAudit(sink)

	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	run := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)

	// Control: asking whether a run is reusable is not serving it, and must
	// append nothing. An event emitted from the question would date a serving
	// that may never happen, and would date two for the surfaces that ask twice.
	if _, ok, err := uc.ReusableRun(context.Background(), reuseWalkID, ""); err != nil || !ok {
		t.Fatalf("control: ReusableRun = (%v, %v), want a reusable run", ok, err)
	}
	if len(sink.events) != 0 {
		t.Fatalf("asking the reuse question appended %d event(s); it must append none", len(sink.events))
	}

	if err := uc.ServeReusableRun(run, application.ServeSurfaceVulnScan); err != nil {
		t.Fatalf("ServeReusableRun: %v", err)
	}

	if len(sink.events) != 1 {
		t.Fatalf("serving a reused run appended %d event(s), want exactly 1: %+v", len(sink.events), sink.events)
	}
	ev := sink.events[0]
	if ev.Type != audit.EventVulnScanServed {
		t.Fatalf("served event type = %q, want %q", ev.Type, audit.EventVulnScanServed)
	}
	for key, want := range map[string]string{
		"scan_id":          "vscan-1",
		"walk_id":          reuseWalkID,
		"pipeline_version": "v1",
		"snapshot_source":  snap.Source(),
		"snapshot_version": snap.Version(),
		"surface":          application.ServeSurfaceVulnScan,
	} {
		got, ok := ev.Payload[key].(string)
		if !ok || got != want {
			t.Errorf("served event payload %q = %v, want %q", key, ev.Payload[key], want)
		}
	}
}

// TestServeReusableRun_RestatesNoneOfTheRunsConclusions pins the witness-not-
// restate rule. The findings, the per-module statuses, the coverage and the
// counts are the RUN's; the scan id reaches them. Copying them into the log
// would put a second, unsealed summary of a sealed run in an append-only file
// that no later correction to the run could ever reach.
func TestServeReusableRun_RestatesNoneOfTheRunsConclusions(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	sink := &recordingAuditSink{}
	uc.WithAudit(sink)

	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	run := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)

	if err := uc.ServeReusableRun(run, application.ServeSurfaceAudit); err != nil {
		t.Fatalf("ServeReusableRun: %v", err)
	}
	payload := sink.events[0].Payload
	for _, banned := range []string{
		"overall_status", "findings_status", "coverage_status",
		"affected", "clean", "withdrawn", "unscannable", "failed", "findings",
	} {
		if _, present := payload[banned]; present {
			t.Errorf("served event restates the run's own conclusion %q; the scan id is what reaches it", banned)
		}
	}
	// Control: the keys that identify the run ARE present, so the check above is
	// measuring restraint rather than an empty payload.
	if _, present := payload["scan_id"]; !present {
		t.Error("served event does not name the run it served")
	}
}

// TestServeReusableRun_WithoutASinkIsANoOp pins the optional-dependency shape
// every emitter in this context has: a nil sink disables emission and never
// fails the serving.
func TestServeReusableRun_WithoutASinkIsANoOp(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	run := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)

	if err := uc.ServeReusableRun(run, application.ServeSurfaceInspect); err != nil {
		t.Fatalf("ServeReusableRun with no audit sink: %v", err)
	}
}

// TestServeReusableRun_ReportsAFailedAppend pins that a serving which could not
// be witnessed says so. The caller fails the serving on it: an answer that left
// the tool with no trace is the gap this closes, not a smaller version of it.
func TestServeReusableRun_ReportsAFailedAppend(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	boom := errors.New("disk full")
	uc.WithAudit(refusingSink{err: boom})

	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	run := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)

	err := uc.ServeReusableRun(run, application.ServeSurfaceVulnScan)
	if err == nil {
		t.Fatal("a failed append reported success; the serving would be untraced")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
}

// TestServeReusableRun_OmitsAnUnstatedSurface pins that no surface is recorded
// as absent rather than as an empty principal.
func TestServeReusableRun_OmitsAnUnstatedSurface(t *testing.T) {
	uc, store := reuseFixture(t, "v1")
	sink := &recordingAuditSink{}
	uc.WithAudit(sink)

	snap := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	seedSnapshot(t, store, snap)
	run := seedRun(t, store, "vscan-1", reuseWalkID, snap, "v1", domain.CoverageComplete)

	if err := uc.ServeReusableRun(run, ""); err != nil {
		t.Fatalf("ServeReusableRun: %v", err)
	}
	if _, present := sink.events[0].Payload["surface"]; present {
		t.Error("an unstated surface was recorded as an empty string; it must be omitted")
	}
}

// refusingSink refuses every append with a caller-supplied error, so a test can
// prove the failure is reported rather than swallowed and that the reported
// error still names its cause.
type refusingSink struct{ err error }

func (s refusingSink) RecordEvent(audit.Event) error { return s.err }
