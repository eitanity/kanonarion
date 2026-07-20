package application_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestScanModule_NewScan(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:  "vulndb content",
	}
	clock := fixedClock{t: now}

	// Setup: module must be fetched first
	contentHash := "hash1"
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "v1",
		ContentHash:     contentHash,
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	if _, err := blobs.Put(ctx, strings.NewReader("zip content")); err != nil { // Handle will be fake:zip content
		t.Fatalf("blobs.Put: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)

	// In the fakeBlob, handle is "fake:" + data
	// So we need to match the ContentLocation in FactRecord with what Put returns
	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-1",
	})

	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if res.OverallStatus != domain.StatusClean {
		t.Errorf("expected StatusClean, got %s", res.OverallStatus)
	}

	if res.DatabaseSnapshot.Version != "v1" {
		t.Errorf("expected snapshot v1, got %s", res.DatabaseSnapshot.Version)
	}

	// Verify persistence
	persisted, ok, err := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", db.snapshot)
	if err != nil || !ok {
		t.Fatal("record not persisted")
	}
	if persisted.ContentHash == "" {
		t.Error("expected ContentHash to be set")
	}
}

// TestScanModule_ReuseReattributesToCurrentRun covers re-scanning a module that
// was already scanned under the same snapshot by an earlier, unrelated walk. The
// cached verdict is reused, but its provenance must follow the run the user
// actually invoked: the returned and persisted record carry the current walk id
// and scan time, and the result is flagged as reuse rather than a fresh scan.
func TestScanModule_ReuseReattributesToCurrentRun(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snapshot := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	earlier := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2024, 6, 17, 0, 0, 0, 0, time.UTC)

	vulnStore := newFakeVulnStore()
	existing := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		PipelineVersion:  "v1",
		DatabaseSnapshot: snapshot,
		WalkID:           "walk-earlier",
		OverallStatus:    domain.StatusClean,
		ScannedAt:        earlier,
		FirstScannedAt:   earlier,
	}
	if err := vulnStore.PutVulnerabilityRecord(ctx, existing); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		nil, nil, vulnStore, nil, nil, nil, nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-current",
		Snapshot:   &snapshot,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if res.OverallStatus != domain.StatusClean {
		t.Errorf("expected StatusClean from cache, got %s", res.OverallStatus)
	}
	if !res.Reused {
		t.Error("expected Reused=true for a cache reuse")
	}
	if res.WalkID != "walk-current" {
		t.Errorf("expected returned record re-attributed to walk-current, got %q", res.WalkID)
	}
	if !res.ScannedAt.Equal(now) {
		t.Errorf("expected returned ScannedAt %s, got %s", now, res.ScannedAt)
	}
	// last-validated (ScannedAt) advances to the invoked run, but the first-seen
	// anchor must stay pinned to the earlier scan that established the verdict.
	if !res.FirstScannedAt.Equal(earlier) {
		t.Errorf("expected FirstScannedAt to stay %s, got %s", earlier, res.FirstScannedAt)
	}

	// The persisted record must be re-attributed too, so a later vuln-show /
	// context query reflects the run the user invoked, not the earlier walk.
	persisted, ok, err := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", snapshot)
	if err != nil || !ok {
		t.Fatalf("persisted record missing: ok=%v err=%v", ok, err)
	}
	if persisted.WalkID != "walk-current" {
		t.Errorf("expected persisted walk-current, got %q", persisted.WalkID)
	}
	if !persisted.ScannedAt.Equal(now) {
		t.Errorf("expected persisted ScannedAt %s, got %s", now, persisted.ScannedAt)
	}
	if !persisted.FirstScannedAt.Equal(earlier) {
		t.Errorf("expected persisted FirstScannedAt to stay %s, got %s", earlier, persisted.FirstScannedAt)
	}
	if persisted.Reused {
		t.Error("Reused is call-scoped and must never be persisted")
	}
}

func TestScanModule_ContentHashExcludesFirstScannedAt(t *testing.T) {
	uc := application.NewScanModuleUseCase(
		nil, nil, nil, nil, nil, nil, nil, fixedClock{}, "v1", "v1", slog.Default(),
	)
	base := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"},
		WalkID:           "walk-1",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"},
		ScannedAt:        time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
	}
	withAnchor := base
	withAnchor.FirstScannedAt = time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	movedAnchor := base
	movedAnchor.FirstScannedAt = time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	// The first-seen anchor is provenance, not verdict: records that differ only
	// in FirstScannedAt must hash identically so reuse re-attribution keeps a
	// stable identity.
	h1, err := uc.ComputeContentHash(withAnchor)
	if err != nil {
		t.Fatalf("ComputeContentHash(withAnchor): %v", err)
	}
	h2, err := uc.ComputeContentHash(movedAnchor)
	if err != nil {
		t.Fatalf("ComputeContentHash(movedAnchor): %v", err)
	}
	if h1 != h2 {
		t.Errorf("content hash changed with FirstScannedAt: %s vs %s", h1, h2)
	}
}

// TestComputeContentHash_MarshalFailure exercises the marshal-failure guard
// with a genuinely unmarshalable value — encoding/json rejects NaN/Inf floats
// — rather than an injected fake, so it proves the guard is actually
// reachable in production (a finding's CVSS Severity.Score is a plain
// float64), not just that the wrapping code is well-formed.
func TestComputeContentHash_MarshalFailure(t *testing.T) {
	uc := application.NewScanModuleUseCase(
		nil, nil, nil, nil, nil, nil, nil, fixedClock{}, "v1", "v1", slog.Default(),
	)
	rec := domain.VulnerabilityRecord{
		Findings: []domain.VulnerabilityFinding{
			{ID: "GO-2024-0001", Severity: &domain.Severity{Score: math.NaN()}},
		},
	}
	if _, err := uc.ComputeContentHash(rec); err == nil {
		t.Fatal("ComputeContentHash() error = nil, want a marshal error for a NaN severity score")
	}
}

// TestScanModule_MetadataFilter_UsesGraphEdges verifies that checkVulnerabilities
// restricts the vulnerability candidate set to the module's actual transitive
// dependencies (via graph edges) rather than all nodes in the walk. Module A
// depends only on B; module C is in the walk but is NOT reachable from A. Only
// C is marked vulnerable. Scanning A must take the fast clean path without
// invoking the heavy scanner.
func TestScanModule_MetadataFilter_UsesGraphEdges(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	coordA := coordinate.ModuleCoordinate{Path: "github.com/example/a", Version: "v1.0.0"}
	coordB := coordinate.ModuleCoordinate{Path: "github.com/example/b", Version: "v1.0.0"}
	coordC := coordinate.ModuleCoordinate{Path: "github.com/example/c", Version: "v1.0.0"}

	// Walk: A→B, C is a separate root (no edge from A).
	walk := walkdomain.WalkRecord{
		ID: "walk-edge-test",
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: coordA},
				{Coordinate: coordB},
				{Coordinate: coordC},
			},
			Edges: []walkdomain.GraphEdge{
				{From: coordA, To: coordB},
			},
		},
	}

	ws := newFakeWalkStore()
	if err := ws.PutWalk(ctx, walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	blobs := newFakeBlob()
	facts := newFakeFacts()
	handle, _ := blobs.Put(ctx, strings.NewReader("zip"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coordA.Path,
		ModuleVersion:   coordA.Version,
		PipelineVersion: "v1",
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	// Only C is vulnerable — A and B are clean.
	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[coordinate.ModuleCoordinate][]string{coordC: {"GO-TEST-0001"}},
	}

	var scannerCalled bool
	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, ws,
		&callCountingScanner{inner: &fakeScanner{}, called: &scannerCalled},
		db, nil, fixedClock{t: now}, "v1", "v1", slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coordA,
		WalkID:     "walk-edge-test",
		Snapshot:   &snap,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusClean {
		t.Errorf("expected StatusClean (fast path), got %s", res.OverallStatus)
	}
	if scannerCalled {
		t.Error("govulncheck scanner must NOT be called: A's transitive deps (A, B) are clean")
	}
}

// The heavy-scan path persists the record built by the scanner adapter, which
// does not own record identity: without the use case stamping Ecosystem, the
// persisted JSON fails VulnerabilityRecord.UnmarshalJSON's fail-closed gate on
// every subsequent read (vuln-show, context), surfacing as "unsupported
// ecosystem" errors for freshly scanned modules.
func TestScanModule_HeavyScanRecordSurvivesReadGate(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	// The fake scanner mirrors the real adapter: it returns records without
	// Ecosystem set. Marking the module vulnerable forces the heavy-scan path
	// past the metadata fast path that stamps Ecosystem itself.
	scanner := &fakeScanner{}
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-VULN-ID"}},
	}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-1",
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Ecosystem != fetchdomain.EcosystemGo {
		t.Errorf("expected Ecosystem %q on scanner-built record, got %q", fetchdomain.EcosystemGo, res.Ecosystem)
	}

	persisted, ok, err := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", db.snapshot)
	if err != nil || !ok {
		t.Fatal("record not persisted")
	}
	raw, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshalling persisted record: %v", err)
	}
	var roundTripped domain.VulnerabilityRecord
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("persisted heavy-scan record rejected by read gate: %v", err)
	}
}

func TestScanModule_ScanFailure(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("scan failed")}
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Version: "v1"},
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-VULN-ID"}},
	}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-1",
	})

	if err != nil {
		t.Fatalf("Scan should not return error on scanner failure, but got: %v", err)
	}

	if res.OverallStatus != domain.StatusScanFailed {
		t.Errorf("expected StatusScanFailed, got %s", res.OverallStatus)
	}
}

// TestScanModule_BuildIncompatibility_FallsBackToMetadata: a module that does
// not build under the host toolchain must not be left as a bare ScanFailed —
// the scan falls back to metadata matching so known advisories are still
// attributed (metadata-only, no reachability).
func TestScanModule_BuildIncompatibility_FallsBackToMetadata(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "golang.org/x/text", Version: "v0.19.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("govulncheck: loading packages: invalid array length -delta * delta")}
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Version: "v1"},
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-2024-0001"}},
	}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusAffected {
		t.Errorf("expected StatusAffected from metadata fallback, got %s", res.OverallStatus)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "GO-2024-0001" {
		t.Errorf("expected the metadata advisory to be attributed, got %+v", res.Findings)
	}
	if !strings.Contains(res.UnscannableReason, "does not build under the host Go toolchain") {
		t.Errorf("expected reason to explain the build incompatibility, got %q", res.UnscannableReason)
	}
	if res.UnscanReason != domain.UnscanReasonBuildIncompatible {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonBuildIncompatible)
	}
}

// TestScanModule_MetadataPath_PersistsEnrichedFindings is the round-trip guard:
// when a module falls back to the metadata path, the advisory's summary,
// affected range, fixed version and at-risk symbols flow through the scan into
// the persisted record, so vuln-show can answer remediation without the user
// leaving the tool.
func TestScanModule_MetadataPath_PersistsEnrichedFindings(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/gorilla/csrf", Version: "v1.7.3"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("govulncheck: loading packages: invalid array length -delta * delta")}
	enriched := domain.VulnerabilityFinding{
		ID:              "GO-2025-3884",
		Summary:         "CSRF bypass",
		AffectedRange:   ">= v1.7.3",
		AffectedSymbols: []string{"TrustedOrigins"},
		PublishedAt:     now,
	}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Version: "v1"},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{coord: {enriched}},
	}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	got := res.Findings[0]
	if got.Summary != "CSRF bypass" || got.AffectedRange != ">= v1.7.3" {
		t.Errorf("finding not enriched: %+v", got)
	}
	if got.FixedIn != "" || got.FixDisplay() != "no fix available" {
		t.Errorf("expected explicit no-fix state, got FixedIn=%q", got.FixedIn)
	}
	if len(got.AffectedSymbols) != 1 || got.AffectedSymbols[0] != "TrustedOrigins" {
		t.Errorf("AffectedSymbols = %v", got.AffectedSymbols)
	}

	persisted, ok, err := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", db.snapshot)
	if err != nil || !ok {
		t.Fatal("record not persisted")
	}
	if len(persisted.Findings) != 1 || persisted.Findings[0].AffectedRange != ">= v1.7.3" {
		t.Errorf("persisted finding lost enrichment: %+v", persisted.Findings)
	}
}

// TestScanModule_ScanFailed_NotServedFromCache verifies that a cached
// StatusScanFailed record is never returned from cache. ScanFailed is a
// transient infrastructure failure; caching it permanently blocks retry
// without --force. A second Scan call must bypass the cached failure and
// produce a fresh result (StatusClean in this case).
func TestScanModule_ScanFailed_NotServedFromCache(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	snapshot := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Pre-seed a cached ScanFailed record — simulates a previous failed run.
	vulnStore := newFakeVulnStore()
	cachedFailure := domain.VulnerabilityRecord{
		Coordinate:       coord,
		PipelineVersion:  "v1",
		DatabaseSnapshot: snapshot,
		OverallStatus:    domain.StatusScanFailed,
		ErrorDetail:      "govulncheck: temp dir /tmp/govulncheck-12345 does not exist",
	}
	if err := vulnStore.PutVulnerabilityRecord(ctx, cachedFailure); err != nil {
		t.Fatalf("PutVulnerabilityRecord: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	db := &fakeDatabase{
		snapshot: snapshot,
		vulnerables: map[coordinate.ModuleCoordinate][]string{
			coord: {"CVE-2024-12345"},
		},
	}
	var scannerCalled bool
	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil,
		&callCountingScanner{inner: &fakeScanner{}, called: &scannerCalled},
		db, nil, fixedClock{t: now}, "v1", "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord,
		WalkID:     "walk-1",
		Snapshot:   &snapshot,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus == domain.StatusScanFailed {
		t.Error("cached ScanFailed must not be served from cache; expected a fresh scan result")
	}
	if !scannerCalled {
		t.Error("scanner must be called to retry the failed scan")
	}
}

// TestScanModule_GeneratedAssetsMissing_UnscanReason: when govulncheck fails
// with undefined symbols pointing to generated asset packages, the record must
// carry UnscanReasonGeneratedAssets so consumers can distinguish it from other
// build incompatibilities.
func TestScanModule_GeneratedAssetsMissing_UnscanReason(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "www.velocidex.com/golang/velociraptor", Version: "v0.76.6"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	// Simulate govulncheck failing with undefined generated-asset symbols.
	scanner := &fakeScanner{err: fmt.Errorf("govulncheck: loading packages:\n" +
		"/tmp/scan/velociraptor/utils/reflect.go:11:22: undefined: assets.ReadFile\n" +
		"/tmp/scan/velociraptor/vql/unimplemented.go:176:44: undefined: assets.FileDocsReferencesVqlYaml")}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusUnscannable {
		t.Errorf("OverallStatus = %s, want Unscannable", res.OverallStatus)
	}
	if res.UnscanReason != domain.UnscanReasonGeneratedAssets {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonGeneratedAssets)
	}
	if !strings.Contains(res.UnscannableReason, "generated or embedded assets") {
		t.Errorf("UnscannableReason = %q, want it to mention generated assets", res.UnscannableReason)
	}
}

// TestScanModule_BuildIncompatibility_NoAdvisory_IsUnscannable: when the module
// does not build and metadata finds no advisory, the result is an Unscannable
// coverage gap — never a confident clean.
func TestScanModule_BuildIncompatibility_NoAdvisory_IsUnscannable(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "golang.org/x/tools", Version: "v0.26.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("govulncheck: loading packages: invalid array length")}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}} // no advisories
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusUnscannable {
		t.Errorf("expected StatusUnscannable coverage gap, got %s", res.OverallStatus)
	}
	if res.OverallStatus == domain.StatusClean {
		t.Error("a module that could not be analysed must never be reported clean")
	}
	if !strings.Contains(res.UnscannableReason, "does not build under the host Go toolchain") {
		t.Errorf("expected reason to explain the build incompatibility, got %q", res.UnscannableReason)
	}
	if res.UnscanReason != domain.UnscanReasonBuildIncompatible {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonBuildIncompatible)
	}
}

// scannerUnscannableReason returns a fakeScanner whose Scan reports a module the
// scanner itself could not analyse, mirroring the real govulncheck adapter:
// StatusUnscannable with the given reason, no findings, nil error.
func scannerUnscannableReason(coord coordinate.ModuleCoordinate, reason domain.UnscanReason, detail string) *fakeScanner {
	return &fakeScanner{results: map[string]domain.VulnerabilityRecord{
		coord.String(): {
			Coordinate:        coord,
			Findings:          nil,
			OverallStatus:     domain.StatusUnscannable,
			UnscanReason:      reason,
			UnscannableReason: detail,
		},
	}}
}

// scannerUnscannable is the no-go.mod variant used by the bulk of the routing
// tests.
func scannerUnscannable(coord coordinate.ModuleCoordinate) *fakeScanner {
	return scannerUnscannableReason(coord, domain.UnscanReasonNoGoMod, "no go.mod found in module zip")
}

// TestScanModule_ScannerUnscannable_MetadataAttributesAdvisories: a no-go.mod
// module the scanner reports Unscannable must still route through the OSV
// metadata path so known advisories are attributed — never silently dropped as
// a confident "no findings". This is the unresolved-metadata half of the
// absence-as-answer regression pair.
func TestScanModule_ScannerUnscannable_MetadataAttributesAdvisories(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "golang.org/x/text", Version: "v0.3.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := scannerUnscannable(coord)
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Version: "v1"},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			coord: {
				{ID: "GO-2020-0015", Summary: "unicode issue", FixedIn: "v0.3.3", AffectedSymbols: []string{"Transform"}},
				{ID: "GO-2021-0113", Summary: "index oob", FixedIn: "v0.3.7"},
				{ID: "GO-2022-1059", Summary: "denial of service", FixedIn: "v0.3.8"},
			},
		},
	}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusAffected {
		t.Errorf("OverallStatus = %s, want Affected (advisories attributed)", res.OverallStatus)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("Findings = %d, want 3 advisories from metadata", len(res.Findings))
	}
	if res.UnscanReason != domain.UnscanReasonNoGoMod {
		t.Errorf("UnscanReason = %q, want %q (no-go-mod caveat preserved)", res.UnscanReason, domain.UnscanReasonNoGoMod)
	}
	// Metadata-only findings carry advisory detail but no reachability verdict.
	for _, f := range res.Findings {
		if f.Reachable != nil {
			t.Errorf("finding %s: Reachable = %v, want nil for metadata-only scan", f.ID, *f.Reachable)
		}
	}
}

// TestScanModule_ScannerUnscannable_NoAdvisory_IsUnscannable: a no-go.mod module
// with no matching advisory must record an explicit Unscannable coverage gap —
// never a silent clean. This is the genuine-zero half of the regression pair.
func TestScanModule_ScannerUnscannable_NoAdvisory_IsUnscannable(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "example.com/nogomod", Version: "v1.0.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := scannerUnscannable(coord)
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}} // no advisories
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusUnscannable {
		t.Errorf("OverallStatus = %s, want Unscannable coverage gap", res.OverallStatus)
	}
	if res.OverallStatus == domain.StatusClean {
		t.Error("a module the scanner could not analyse must never be reported clean")
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(res.Findings))
	}
	if res.UnscanReason != domain.UnscanReasonNoGoMod {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonNoGoMod)
	}
}

// TestScanModule_ScannerUnscannable_OOMKilled_RoutesToMetadata: the routing is
// reason-agnostic — any scanner-reported Unscannable, not just no-go.mod, must
// attribute known advisories from OSV metadata. An OOM-killed scan with a
// matching advisory surfaces it while preserving the oom-killed caveat.
func TestScanModule_ScannerUnscannable_OOMKilled_RoutesToMetadata(t *testing.T) {
	ctx := t.Context()
	coord := coordinate.ModuleCoordinate{Path: "github.com/big/module", Version: "v2.0.0"}
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := scannerUnscannableReason(coord, domain.UnscanReasonOOMKilled, "govulncheck was killed (likely OOM)")
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Version: "v1"},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			coord: {{ID: "GO-2024-0001", Summary: "boom", FixedIn: "v2.0.1"}},
		},
	}
	clock := fixedClock{t: now}

	handle, _ := blobs.Put(ctx, strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version, PipelineVersion: "v1", ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusAffected {
		t.Errorf("OverallStatus = %s, want Affected (advisory attributed)", res.OverallStatus)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if res.UnscanReason != domain.UnscanReasonOOMKilled {
		t.Errorf("UnscanReason = %q, want %q (oom-killed caveat preserved)", res.UnscanReason, domain.UnscanReasonOOMKilled)
	}
}
