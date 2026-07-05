package application_test

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// TestScanWalk_PreflightFailsFast verifies that when the scanner's pre-flight
// check fails, the walk scan aborts before any work: the scanner's Scan is
// never invoked, no run is persisted, and the error surfaces the actionable
// pre-flight message. The "present -> proceeds" path is covered by every
// other test in this file (default fakeScanner.Preflight returns nil).
func TestScanWalk_PreflightFailsFast(t *testing.T) {
	ctx := t.Context()
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}

	preflightErr := errors.New("govulncheck not found in PATH (install with: go install golang.org/x/vuln/cmd/govulncheck@latest)")

	// No walk is stored: if pre-flight did NOT run first, Scan would fail
	// later with a "retrieving walk" error instead of the pre-flight error.
	walkStore := newFakeWalkStore()
	vulnStore := newFakeVulnStore()
	scanned := false
	scanner := &callCountingScanner{
		inner:  &fakeScanner{preflightErr: preflightErr},
		called: &scanned,
	}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}

	moduleUC := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	_, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "walk-absent"})
	if err == nil {
		t.Fatal("Scan: expected pre-flight error, got nil")
	}
	if !errors.Is(err, preflightErr) {
		t.Errorf("Scan error = %v, want it to wrap the pre-flight error", err)
	}
	if !strings.Contains(err.Error(), "go install golang.org/x/vuln/cmd/govulncheck@latest") {
		t.Errorf("Scan error %q is missing the actionable install command", err)
	}
	if scanned {
		t.Error("scanner.Scan was invoked despite pre-flight failure")
	}
	if runs, _ := vulnStore.ListAllWalkScanRuns(ctx); len(runs) != 0 {
		t.Errorf("expected no persisted scan runs, got %d", len(runs))
	}
}

func TestScanWalk(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-1"

	// 1. Setup Walk
	target := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	dep := fetchdomain.ModuleCoordinate{Path: "github.com/lib/baz", Version: "v2.0.0"}

	walk := walkdomain.WalkRecord{
		ID: walkID,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target},
				{Coordinate: dep},
			},
		},
	}

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	// 2. Setup Module Scan dependencies
	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{
		results: map[string]domain.VulnerabilityRecord{
			dep.String(): {
				Coordinate:    dep,
				OverallStatus: domain.StatusAffected,
				Findings: []domain.VulnerabilityFinding{
					{ID: "VULN-1", Summary: "Bad bug"},
				},
			},
		},
	}
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Source: "test", Version: "v1"},
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{dep: {"GO-VULN-ID"}},
	}
	clock := fixedClock{t: now}

	// Prepare facts for scanner
	h1, _ := blobs.Put(ctx, strings.NewReader("zip1"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: target.Path, ModuleVersion: target.Version, PipelineVersion: "v1", ContentLocation: string(h1),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	h2, _ := blobs.Put(ctx, strings.NewReader("zip2"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: dep.Path, ModuleVersion: dep.Version, PipelineVersion: "v1", ContentLocation: string(h2),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)

	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	// 3. Execute
	run, err := walkUC.Scan(ctx, application.ScanWalkParams{
		WalkID:   walkID,
		Operator: "test-user",
	})

	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// 4. Verify
	if run.OverallStatus != domain.WalkStatusAffected {
		t.Errorf("expected WalkStatusAffected, got %s", run.OverallStatus)
	}

	if len(run.PerModuleResults) != 2 {
		t.Errorf("expected 2 module results, got %d", len(run.PerModuleResults))
	}

	// Verify persistence
	persisted, ok, err := vulnStore.GetWalkScanRun(ctx, run.ID)
	if err != nil || !ok {
		t.Fatal("walk scan run not persisted")
	}
	if persisted.OverallStatus != domain.WalkStatusAffected {
		t.Error("persisted status mismatch")
	}
}

// TestScanWalk_SnapshotPersisted is a regression test for the bug where
// ScanWalkUseCase.Scan discarded the body returned by database.Snapshot,
// causing the scanner to fall back to live network access and hang indefinitely.
// It asserts that after Scan returns, the snapshot content is stored in the
// VulnerabilityStore so that the scanner can retrieve it locally.
func TestScanWalk_SnapshotPersisted(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-snap"

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
	h, _ := blobs.Put(ctx, strings.NewReader("zip1"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	const snapshotContent = "snapshot-body-data"
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v42"},
		content:  snapshotContent,
	}
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	clock := fixedClock{t: now}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	_, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// The snapshot body must have been persisted so the scanner can use it locally.
	rc, err := vulnStore.GetDatabaseSnapshot(ctx, db.snapshot)
	if err != nil {
		t.Fatalf("snapshot not persisted in vuln store: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != snapshotContent {
		t.Errorf("persisted snapshot content = %q, want %q", got, snapshotContent)
	}
}

func TestScanWalk_OverallStatus(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := fixedClock{t: now}

	coord1 := fetchdomain.ModuleCoordinate{Path: "m1", Version: "v1"}
	coord2 := fetchdomain.ModuleCoordinate{Path: "m2", Version: "v1"}

	tests := []struct {
		name     string
		results  map[string]domain.VulnerabilityRecord
		expected domain.WalkScanStatus
	}{
		{
			name: "All Clean",
			results: map[string]domain.VulnerabilityRecord{
				"m1@v1": {Coordinate: coord1, OverallStatus: domain.StatusClean},
				"m2@v1": {Coordinate: coord2, OverallStatus: domain.StatusClean},
			},
			expected: domain.WalkStatusAllClean,
		},
		{
			name: "One Affected",
			results: map[string]domain.VulnerabilityRecord{
				"m1@v1": {Coordinate: coord1, OverallStatus: domain.StatusAffected},
				"m2@v1": {Coordinate: coord2, OverallStatus: domain.StatusClean},
			},
			expected: domain.WalkStatusAffected,
		},
		{
			name: "One Failed",
			results: map[string]domain.VulnerabilityRecord{
				"m1@v1": {Coordinate: coord1, OverallStatus: domain.StatusScanFailed},
				"m2@v1": {Coordinate: coord2, OverallStatus: domain.StatusClean},
			},
			expected: domain.WalkStatusPartial,
		},
		{
			name: "All Failed",
			results: map[string]domain.VulnerabilityRecord{
				"m1@v1": {Coordinate: coord1, OverallStatus: domain.StatusScanFailed},
				"m2@v1": {Coordinate: coord2, OverallStatus: domain.StatusScanFailed},
			},
			expected: domain.WalkStatusFailed,
		},
		{
			name: "One Unscannable",
			results: map[string]domain.VulnerabilityRecord{
				"m1@v1": {Coordinate: coord1, OverallStatus: domain.StatusUnscannable},
				"m2@v1": {Coordinate: coord2, OverallStatus: domain.StatusClean},
			},
			expected: domain.WalkStatusPartial,
		},
		{
			name: "Affected wins over Unscannable",
			results: map[string]domain.VulnerabilityRecord{
				"m1@v1": {Coordinate: coord1, OverallStatus: domain.StatusUnscannable},
				"m2@v1": {Coordinate: coord2, OverallStatus: domain.StatusAffected},
			},
			expected: domain.WalkStatusAffected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			walkStore := newFakeWalkStore()
			if err := walkStore.PutWalk(ctx, walkdomain.WalkRecord{
				ID: "w1",
				Graph: walkdomain.Graph{
					Nodes: []walkdomain.GraphNode{{Coordinate: coord1}, {Coordinate: coord2}},
				},
			}); err != nil {
				t.Fatalf("PutWalk: %v", err)
			}

			facts := newFakeFacts()
			blobs := newFakeBlob()
			for _, c := range []fetchdomain.ModuleCoordinate{coord1, coord2} {
				h, _ := blobs.Put(ctx, strings.NewReader("zip"))
				if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
					ModulePath: c.Path, ModuleVersion: c.Version, PipelineVersion: "v1", ContentLocation: string(h),
				}); err != nil {
					t.Fatalf("PutFetchRecord: %v", err)
				}
			}

			scanner := &fakeScanner{results: tt.results}
			var vulnerables map[fetchdomain.ModuleCoordinate][]string
			if tt.expected != domain.WalkStatusAllClean {
				// If we expect anything other than Clean, we must trigger the heavy scanner
				vulnerables = map[fetchdomain.ModuleCoordinate][]string{
					coord1: {"GO-VULN-ID"},
					coord2: {"GO-VULN-ID"},
				}
			}
			db := &fakeDatabase{
				snapshot:    domain.DatabaseSnapshot{Version: "v1"},
				vulnerables: vulnerables,
				// The metadata pre-filter (CheckVulnerable) uses vulnerables to force
				// the heavy scan, but a scanner-reported Unscannable result now routes
				// through the OSV metadata fallback (LookupFindings). Pin that fallback
				// to no matching advisory so an Unscannable module stays Unscannable in
				// the aggregation here, exercising the status rollup rather than the
				// advisory-attribution path covered by the scan_module tests.
				findings: map[fetchdomain.ModuleCoordinate][]domain.VulnerabilityFinding{
					coord1: {},
					coord2: {},
				},
			}
			vulnStore := newFakeVulnStore()

			moduleUC := application.NewScanModuleUseCase(
				facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
			)
			walkUC := application.NewScanWalkUseCase(
				walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
			)

			run, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1"})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if run.OverallStatus != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, run.OverallStatus)
			}
		})
	}
}

func TestScanWalk_FreshFetch(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := fixedClock{t: now}

	coord := fetchdomain.ModuleCoordinate{Path: "m1", Version: "v1"}
	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    "w1",
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()
	h, _ := blobs.Put(ctx, strings.NewReader("zip"))
	_ = facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(h),
	})

	scanner := &fakeScanner{}
	vulnStore := newFakeVulnStore()

	// 1. Put a cached snapshot.
	cachedSnap := domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now.Add(-time.Hour)}
	_ = vulnStore.PutDatabaseSnapshot(ctx, cachedSnap, strings.NewReader("cached"))

	// 2. Mock database returns a newer snapshot.
	freshSnap := domain.DatabaseSnapshot{Source: "test", Version: "v2", RetrievedAt: now}
	db := &fakeDatabase{snapshot: freshSnap, content: "fresh"}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	// 3. Scan WITHOUT fresh=true -> should use cached.
	run, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if run.Snapshot.Version != "v1" {
		t.Errorf("expected cached version v1, got %s", run.Snapshot.Version)
	}

	// 4. Scan WITH fresh=true -> should fetch fresh.
	run, err = walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1", Fresh: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if run.Snapshot.Version != "v2" {
		t.Errorf("expected fresh version v2, got %s", run.Snapshot.Version)
	}

	// 5. Verify v2 was persisted.
	persisted, ok, _ := vulnStore.GetLatestDatabaseSnapshot(ctx)
	if !ok || persisted.Version != "v2" {
		t.Errorf("fresh snapshot v2 not persisted")
	}
}

// a ResolutionLocalReplace node has no remote artefact for
// govulncheck to open. ScanWalk must skip it before dispatch and emit a
// deterministic StatusUnscannable VulnerabilityRecord carrying the local path
// under the structured unscan_reason taxonomy, so the scan-run counts the
// module as unscannable rather than silently dropping it.
func TestScanWalk_LocalReplaceUnscannable(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-localreplace"

	target := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	localDep := fetchdomain.ModuleCoordinate{Path: "example.com/dep", Version: "v1.0.0"}

	walk := walkdomain.WalkRecord{
		ID: walkID,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target},
				{
					Coordinate:       localDep,
					ResolutionSource: walkdomain.ResolutionLocalReplace,
					LocalPath:        "../local/dep",
				},
			},
		},
	}

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()

	// Track scanner invocations so we can assert the local-replace node never
	// reaches the scanner — it has no blob, no fact record, and would crash
	// govulncheck if dispatched.
	scanned := false
	scanner := &callCountingScanner{
		inner:  &fakeScanner{results: map[string]domain.VulnerabilityRecord{}},
		called: &scanned,
	}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	clock := fixedClock{t: now}

	// Fact for the target only — the local-replace dep deliberately has no
	// fact record, mirroring the live wiring where the walker never fetched it.
	h, _ := blobs.Put(ctx, strings.NewReader("zip-target"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: target.Path, ModuleVersion: target.Version,
		PipelineVersion: "v1", ContentLocation: string(h),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	run, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// The local-replace dep must be recorded as unscannable with a reason.
	rec, found, err := vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, localDep, "v1", walkID)
	if err != nil || !found {
		t.Fatalf("no VulnerabilityRecord persisted for local-replace dep %s (found=%t err=%v)", localDep, found, err)
	}
	if rec.OverallStatus != domain.StatusUnscannable {
		t.Errorf("OverallStatus = %s, want Unscannable", rec.OverallStatus)
	}
	// The reason must live in the structured taxonomy, consistent with every
	// other Unscannable path — not in the retired bespoke ErrorDetail string.
	if rec.UnscanReason != domain.UnscanReasonLocalReplace {
		t.Errorf("UnscanReason = %q, want %q", rec.UnscanReason, domain.UnscanReasonLocalReplace)
	}
	if rec.UnscannableReason == "" {
		t.Error("UnscannableReason is empty; a local-replace node must carry human prose")
	}
	if !strings.Contains(rec.UnscannableReason, "../local/dep") {
		t.Errorf("UnscannableReason = %q, want it to name the local path", rec.UnscannableReason)
	}
	if rec.ErrorDetail != "" {
		t.Errorf("ErrorDetail = %q, want empty; the error_detail-only representation is retired", rec.ErrorDetail)
	}

	// The PerModuleResults map of the run must include the local-replace
	// coordinate so consumers (sbom, audit) iterate every walked node.
	if _, ok := run.PerModuleResults[localDep]; !ok {
		t.Errorf("PerModuleResults missing %s; the local-replace node was silently dropped", localDep)
	}
}
