package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/audit"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// recordingAuditSink captures every event appended during a scan so a test can
// assert exactly which assurance-log facts a run emitted.
type recordingAuditSink struct {
	events []audit.Event
}

func (s *recordingAuditSink) RecordEvent(e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

func (s *recordingAuditSink) ofType(t audit.EventType) []audit.Event {
	var out []audit.Event
	for _, e := range s.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

// TestScanWalk_EmitsAuditEvents is the regression test for wiring the walk scan
// to the assurance log: a scan that produces a finding must append one
// vuln_finding_observed event per finding plus one vuln_scan_completed summary.
func TestScanWalk_EmitsAuditEvents(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-audit"

	affected := fetchdomain.ModuleCoordinate{Path: "github.com/lib/baz", Version: "v2.0.0"}
	clean := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID: walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{
			{Coordinate: clean},
			{Coordinate: affected},
		}},
	}); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	for _, c := range []fetchdomain.ModuleCoordinate{clean, affected} {
		h, _ := blobs.Put(ctx, strings.NewReader("zip-"+c.Path))
		if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
			ModulePath: c.Path, ModuleVersion: c.Version, PipelineVersion: "v1", ContentLocation: string(h),
		}); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}
	}

	scanner := &fakeScanner{
		results: map[string]domain.VulnerabilityRecord{
			affected.String(): {
				Coordinate:    affected,
				OverallStatus: domain.StatusAffected,
				Findings: []domain.VulnerabilityFinding{
					{ID: "GO-2024-0001", Summary: "one"},
					{ID: "GO-2024-0002", Summary: "two"},
				},
			},
		},
	}
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Source: "test", Version: "v1"},
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{affected: {"GO-VULN-ID"}},
	}
	clock := fixedClock{t: now}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	sink := &recordingAuditSink{}
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	).WithAudit(sink)

	run, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Every emitted event must be a recognised vocabulary type.
	for _, e := range sink.events {
		if err := e.Validate(); err != nil {
			t.Errorf("emitted event failed validation: %v", err)
		}
	}

	// One vuln_finding_observed per finding, in deterministic (module, id) order.
	findings := sink.ofType(audit.EventVulnFindingObserved)
	if len(findings) != 2 {
		t.Fatalf("expected 2 vuln_finding_observed events, got %d", len(findings))
	}
	wantIDs := []string{"GO-2024-0001", "GO-2024-0002"}
	for i, e := range findings {
		if got := e.Payload["module"]; got != affected.Path {
			t.Errorf("finding[%d] module = %v, want %v", i, got, affected.Path)
		}
		if got := e.Payload["version"]; got != affected.Version {
			t.Errorf("finding[%d] version = %v, want %v", i, got, affected.Version)
		}
		if got := e.Payload["vuln_id"]; got != wantIDs[i] {
			t.Errorf("finding[%d] vuln_id = %v, want %v", i, got, wantIDs[i])
		}
		if got := e.Payload["overall_status"]; got != string(domain.StatusAffected) {
			t.Errorf("finding[%d] overall_status = %v, want %v", i, got, domain.StatusAffected)
		}
	}

	// Exactly one vuln_scan_completed with the run identity and count breakdown.
	completed := sink.ofType(audit.EventVulnScanCompleted)
	if len(completed) != 1 {
		t.Fatalf("expected 1 vuln_scan_completed event, got %d", len(completed))
	}
	p := completed[0].Payload
	if got := p["scan_id"]; got != run.ID {
		t.Errorf("scan_id = %v, want %v", got, run.ID)
	}
	if got := p["walk_id"]; got != walkID {
		t.Errorf("walk_id = %v, want %v", got, walkID)
	}
	if got := p["affected"]; got != 1 {
		t.Errorf("affected = %v, want 1", got)
	}
	if got := p["clean"]; got != 1 {
		t.Errorf("clean = %v, want 1", got)
	}
	if got := p["snapshot_version"]; got != "v1" {
		t.Errorf("snapshot_version = %v, want v1", got)
	}

	// The completed summary must be the final event (findings precede it).
	if last := sink.events[len(sink.events)-1]; last.Type != audit.EventVulnScanCompleted {
		t.Errorf("last event = %q, want vuln_scan_completed", last.Type)
	}
}

// TestRescan_EmitsAuditEvents verifies the audit sink wired on the rescan use
// case propagates into the delegated walk scan so a re-scan also reaches the
// assurance log. Rescan forces a fresh scan, so the finding is re-observed.
func TestRescan_EmitsAuditEvents(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)

	affected := fetchdomain.ModuleCoordinate{Path: "github.com/lib/baz", Version: "v2.0.0"}
	walk, ws, facts, blobs := makeWalkWithModules(t, affected)

	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{
		results: map[string]domain.VulnerabilityRecord{
			affected.String(): {
				Coordinate:    affected,
				OverallStatus: domain.StatusAffected,
				Findings:      []domain.VulnerabilityFinding{{ID: "GO-2024-0001", Summary: "one"}},
			},
		},
	}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	clock := fixedClock{t: now}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	sink := &recordingAuditSink{}
	rescanner := application.NewRescanWalkUseCase(
		ws, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	).WithAudit(sink)

	if _, err := rescanner.Rescan(ctx, application.RescanRequest{
		WalkID:   walk.ID,
		Snapshot: &db.snapshot,
	}); err != nil {
		t.Fatalf("Rescan: %v", err)
	}

	if got := len(sink.ofType(audit.EventVulnFindingObserved)); got != 1 {
		t.Errorf("expected 1 vuln_finding_observed from rescan, got %d", got)
	}
	if got := len(sink.ofType(audit.EventVulnScanCompleted)); got != 1 {
		t.Errorf("expected 1 vuln_scan_completed from rescan, got %d", got)
	}
}

// TestScanWalk_NilAuditSink verifies emission is optional: a scan with no audit
// sink wired completes normally and simply appends nothing.
func TestScanWalk_NilAuditSink(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-noaudit"

	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	}); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	h, _ := blobs.Put(ctx, strings.NewReader("zip"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	vulnStore := newFakeVulnStore()
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, &fakeScanner{}, &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}, nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, fixedClock{t: now}, "v1", slog.Default(),
	)

	if _, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan with nil audit sink: %v", err)
	}
}
