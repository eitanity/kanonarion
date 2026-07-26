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
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

func TestScanModule_NewScan(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
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
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
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
		Coordinate:       coordinatetest.MustNew("github.com/foo/bar", "v1.0.0"),
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

	coordA := coordinatetest.MustNew("github.com/example/a", "v1.0.0")
	coordB := coordinatetest.MustNew("github.com/example/b", "v1.0.0")
	coordC := coordinatetest.MustNew("github.com/example/c", "v1.0.0")

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
	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coordA), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coordA), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"))); err != nil {
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
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("golang.org/x/text", "v0.19.0")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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

// TestScanModule_OfflineResolution_SourcePositionShapeIsVerified is the guard
// against an unverified out-of-toolchain verdict: an offline resolution failure
// attributed to a source position names no coordinate in its own text, so the
// incomplete-scan-cache check used
// to silently never run and every such module kept version-not-in-toolchain by
// default. The recovery now resolves the unimportable package to its module and
// reads the version the scanned module's own go.mod selects, then verifies it
// against the walk's known set.
func TestScanModule_OfflineResolution_SourcePositionShapeIsVerified(t *testing.T) {
	const goMod = "module github.com/shopify/goreferrer\n\ngo 1.12\n\n" +
		"require golang.org/x/net v0.0.0-20180218175443-cbe0f9307d01\n"
	// The dominant shape: a GOPROXY=off line and a could-not-import line sharing
	// one source position, naming a package but no coordinate.
	scannerErr := "govulncheck: loading packages: \n" +
		"rich_url.go:7:2: module lookup disabled by GOPROXY=off\n" +
		"/tmp/x/github.com/shopify/goreferrer@v0.0.0/rich_url.go:7:2: could not import golang.org/x/net/publicsuffix (invalid package name: \"\")"
	coord := coordinatetest.MustNew("github.com/shopify/goreferrer", "v0.0.0")
	recovered := coordinatetest.MustNew("golang.org/x/net", "v0.0.0-20180218175443-cbe0f9307d01")

	cases := []struct {
		name       string
		known      map[coordinate.ModuleCoordinate]struct{}
		wantReason domain.UnscanReason
		wantInNote string
	}{
		{
			// The recovered version is not the one the project builds, so the
			// out-of-toolchain verdict is confirmed — and the prose names it.
			name:       "recovered version outside the walk is verified out-of-toolchain",
			known:      map[coordinate.ModuleCoordinate]struct{}{coordinatetest.MustNew("golang.org/x/net", "v0.55.0"): {}},
			wantReason: domain.UnscanReasonVersionNotInToolchain,
			wantInNote: recovered.String(),
		},
		{
			// The recovered version is one the walk records: a scan-cache hole,
			// not a module reaching outside the project.
			name:       "recovered version inside the walk is an incomplete scan cache",
			known:      map[coordinate.ModuleCoordinate]struct{}{recovered: {}},
			wantReason: domain.UnscanReasonIncompleteScanCache,
			wantInNote: recovered.String(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			facts := newFakeFacts()
			blobs := newFakeBlob()
			vulnStore := newFakeVulnStore()
			scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
			db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
			clock := fixedClock{t: now}

			seedRec := fetchtest.Record(t,
				fetchtest.Coordinate(coord),
				fetchtest.PipelineVersion("v1"),
				fetchtest.Content("zip content"),
				fetchtest.GoMod("gomod"),
			)
			_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
			_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
			if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
				t,
				fetchtest.Coordinate(coord),
				fetchtest.PipelineVersion("v1"),
				fetchtest.Content("zip content"),
				fetchtest.GoMod("gomod"),
			)); err != nil {
				t.Fatalf("PutFetchRecord: %v", err)
			}

			uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
			res, err := uc.Scan(ctx, application.ScanModuleParams{
				Coordinate: coord, WalkID: "walk-1", Force: true, KnownVersions: tc.known,
			})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if res.UnscanReason != tc.wantReason {
				t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, tc.wantReason)
			}
			if !strings.Contains(res.UnscannableReason, tc.wantInNote) {
				t.Errorf("UnscannableReason = %q, want it to name %q", res.UnscannableReason, tc.wantInNote)
			}
		})
	}
}

// TestScanModule_OfflineResolution_UnrecoverableIsMarkedUnverified guards the
// second half of the fix: when no version can be recovered from the error, the
// reason must state the cause is unverified rather than assert an out-of-toolchain
// re-selection nothing established. Here the module's go.mod names no requirement
// for the unimportable package's module, so recovery fails.
func TestScanModule_OfflineResolution_UnrecoverableIsMarkedUnverified(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("github.com/shopify/goreferrer", "v0.0.0")
	// go.mod requires no golang.org/x/net, so the recovered module path resolves
	// to no version and the coordinate cannot be established.
	const goMod = "module github.com/shopify/goreferrer\n\ngo 1.12\n"
	scannerErr := "govulncheck: loading packages: \n" +
		"rich_url.go:7:2: module lookup disabled by GOPROXY=off\n" +
		"/tmp/x/rich_url.go:7:2: could not import golang.org/x/net/publicsuffix (invalid package name: \"\")"

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Force: true,
		KnownVersions: map[coordinate.ModuleCoordinate]struct{}{coordinatetest.MustNew("golang.org/x/net", "v0.55.0"): {}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscanReason != domain.UnscanReasonVersionNotInToolchainUnverified {
		t.Errorf("UnscanReason = %q, want %q", res.UnscanReason, domain.UnscanReasonVersionNotInToolchainUnverified)
	}
	if res.UnscanReason.ExpectedOutOfToolchain() {
		t.Error("an unverified reason must not be marked expected out-of-toolchain")
	}
}

// TestScanModule_OfflineResolution_DirectShapeGatedOnRequireClosure guards
// against a coordinate the toolchain names but the scanned module does not
// require sustaining a verified out-of-toolchain verdict. A synthesised go.mod
// requiring the whole build list makes MVS name a version an unrelated entry
// demanded; that says nothing about the module being scanned, so a coordinate
// absent from the module's own require closure must fall back to unverified.
func TestScanModule_OfflineResolution_DirectShapeGatedOnRequireClosure(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("example.com/scanned", "v1.0.0")
	// The module requires only x/text; it never requires fsnotify. The direct
	// shape names fsnotify@v1.7.0 (an unrelated build-list upgrade).
	const goMod = "module example.com/scanned\n\ngo 1.19\n\nrequire golang.org/x/text v0.3.8\n"
	scannerErr := "govulncheck: loading packages: \n" +
		"go: example.com/scanned imports\n\tgithub.com/fsnotify/fsnotify@v1.7.0: module lookup disabled by GOPROXY=off"

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Force: true,
		// fsnotify@v1.7.0 is outside the walk's known set, so the un-gated code
		// would report a confident verified out-of-toolchain naming it.
		KnownVersions: map[coordinate.ModuleCoordinate]struct{}{coordinatetest.MustNew("github.com/fsnotify/fsnotify", "v1.4.9"): {}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscanReason != domain.UnscanReasonVersionNotInToolchainUnverified {
		t.Errorf("UnscanReason = %q, want %q (a coordinate the module does not require must not be verified)",
			res.UnscanReason, domain.UnscanReasonVersionNotInToolchainUnverified)
	}
	if strings.Contains(res.UnscannableReason, "fsnotify") {
		t.Errorf("prose must not name fsnotify as an established out-of-toolchain coordinate: %q", res.UnscannableReason)
	}
}

// TestScanModule_OfflineResolution_ColumnMismatchRecovers guards the
// column-pairing fix end to end. Real govulncheck emits the GOPROXY=off line and
// the could-not-import line on the same source line but at different columns
// (:7:8 vs :7:13). The scanned module's own go.mod requires testify at a version
// the walk never built (v1.7.0 vs the walk's v1.9.0), so once the pair links and
// the import resolves against the module's own go.mod, the verdict is a verified
// out-of-toolchain naming that coordinate rather than the ambiguous unverified
// bucket.
func TestScanModule_OfflineResolution_ColumnMismatchRecovers(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("github.com/cortezaproject/goqu/v9", "v9.18.4")
	const goMod = "module github.com/cortezaproject/goqu/v9\n\ngo 1.16\n\n" +
		"require github.com/stretchr/testify v1.7.0\n"
	scannerErr := "govulncheck: loading packages: \n" +
		"mocks/SQLDialect.go:7:8: module lookup disabled by GOPROXY=off\n" +
		"/tmp/x/github.com/cortezaproject/goqu/v9@v9.18.4/mocks/SQLDialect.go:7:13: " +
		"could not import github.com/stretchr/testify/mock (invalid package name: \"\")"

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Force: true,
		KnownVersions: map[coordinate.ModuleCoordinate]struct{}{coordinatetest.MustNew("github.com/stretchr/testify", "v1.9.0"): {}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscanReason != domain.UnscanReasonVersionNotInToolchain {
		t.Errorf("UnscanReason = %q, want verified version-not-in-toolchain", res.UnscanReason)
	}
	if !strings.Contains(res.UnscannableReason, "github.com/stretchr/testify@v1.7.0") {
		t.Errorf("UnscannableReason = %q, want it to name the recovered coordinate testify@v1.7.0", res.UnscannableReason)
	}
}

// TestScanModule_OfflineResolution_OwnGoModWhenPackageOutsideWalk guards the
// item-3 fix: the unimportable package's module is absent from the walk's node
// set entirely (the walk never built stretchr/objx), so a longest-prefix match
// against the walk paths alone recovers nothing and the module drops into the
// unverified bucket. The scanned module's own go.mod does require it, so folding
// the module's own requires into the search universe recovers the coordinate and
// verifies the out-of-toolchain verdict.
func TestScanModule_OfflineResolution_OwnGoModWhenPackageOutsideWalk(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("github.com/stretchr/testify", "v1.9.0")
	const goMod = "module github.com/stretchr/testify\n\ngo 1.17\n\n" +
		"require github.com/stretchr/objx v0.5.2\n"
	scannerErr := "govulncheck: loading packages: \n" +
		"mock/mock.go:16:2: module lookup disabled by GOPROXY=off\n" +
		"/tmp/x/github.com/stretchr/testify@v1.9.0/mock/mock.go:16:2: " +
		"could not import github.com/stretchr/objx (invalid package name: \"\")"

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Force: true,
		// The walk built testify itself but never objx; objx is off-graph.
		KnownVersions: map[coordinate.ModuleCoordinate]struct{}{coordinatetest.MustNew("github.com/stretchr/testify", "v1.9.0"): {}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscanReason != domain.UnscanReasonVersionNotInToolchain {
		t.Errorf("UnscanReason = %q, want verified version-not-in-toolchain", res.UnscanReason)
	}
	if !strings.Contains(res.UnscannableReason, "github.com/stretchr/objx@v0.5.2") {
		t.Errorf("UnscannableReason = %q, want it to name objx@v0.5.2 recovered from the module's own go.mod", res.UnscannableReason)
	}
}

// TestScanModule_OfflineResolution_ImportSiteDependencyGoMod guards the
// parent-module recovery: the unimportable package is imported from a
// *dependency's* source, not the scanned module's own code. matttproud's pbutil
// imports google.golang.org/protobuf via golang/protobuf's proto package, and
// matttproud's own go.mod names no protobuf requirement — so the coordinate is
// recoverable only from the import-site module (golang/protobuf@v1.5.3, named by
// the failing file path), whose go.mod selects protobuf@v1.26.0. That version is
// not the one the walk built (v1.32.0), so the verdict is verified out-of-toolchain.
func TestScanModule_OfflineResolution_ImportSiteDependencyGoMod(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("github.com/matttproud/golang_protobuf_extensions", "v1.0.1")
	// The scanned module's own go.mod requires no protobuf module at all.
	const goMod = "module github.com/matttproud/golang_protobuf_extensions\n\ngo 1.9\n"
	// The import site is golang/protobuf@v1.5.3, a dependency whose go.mod selects
	// the missing protobuf version.
	site := coordinatetest.MustNew("github.com/golang/protobuf", "v1.5.3")
	const siteGoMod = "module github.com/golang/protobuf\n\ngo 1.9\n\n" +
		"require google.golang.org/protobuf v1.26.0\n"
	scannerErr := "govulncheck: loading packages: \n" +
		"/tmp/kanonarion-modcache-1/github.com/golang/protobuf@v1.5.3/proto/buffer.go:11:2: module lookup disabled by GOPROXY=off\n" +
		"/tmp/kanonarion-modcache-1/github.com/golang/protobuf@v1.5.3/proto/buffer.go:11:2: " +
		"could not import google.golang.org/protobuf/proto (invalid package name: \"\")"

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	// Seed the import-site dependency's go.mod so its protobuf selection is readable.
	siteRec := fetchtest.Record(t,
		fetchtest.Coordinate(site),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("site-gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, siteRec), strings.NewReader(siteGoMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, siteRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(site),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("site-gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord(site): %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Force: true,
		KnownVersions: map[coordinate.ModuleCoordinate]struct{}{
			coordinatetest.MustNew("google.golang.org/protobuf", "v1.32.0"): {},
			coordinatetest.MustNew("github.com/golang/protobuf", "v1.5.3"):  {},
		},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscanReason != domain.UnscanReasonVersionNotInToolchain {
		t.Errorf("UnscanReason = %q, want verified version-not-in-toolchain", res.UnscanReason)
	}
	if !strings.Contains(res.UnscannableReason, "google.golang.org/protobuf@v1.26.0") {
		t.Errorf("UnscannableReason = %q, want it to name protobuf@v1.26.0 recovered from the import-site go.mod", res.UnscannableReason)
	}
}

// TestScanModule_OfflineResolution_VersionedReplaceScoping guards that a
// versioned replace only redirects the version it names. The module requires
// x/text v0.3.8 and carries a replace scoped to a *different* version; the
// recovered coordinate must therefore be the required version, not the replace
// target.
func TestScanModule_OfflineResolution_VersionedReplaceScoping(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	coord := coordinatetest.MustNew("example.com/scanned", "v1.0.0")
	// The replace targets x/text v0.9.9, but the require selects v0.3.8, so the
	// replace does not apply and must not be read as if it did.
	const goMod = "module example.com/scanned\n\ngo 1.19\n\n" +
		"require golang.org/x/text v0.3.8\n\n" +
		"replace golang.org/x/text v0.9.9 => golang.org/x/text v0.9.9\n"
	scannerErr := "govulncheck: loading packages: \n" +
		"main.go:3:2: module lookup disabled by GOPROXY=off\n" +
		"/tmp/x/main.go:3:2: could not import golang.org/x/text/language (invalid package name: \"\")"

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("%s", scannerErr)}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}}
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, seedRec), strings.NewReader(goMod))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content"))
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip content"),
		fetchtest.GoMod("gomod"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(facts, blobs, vulnStore, nil, scanner, db, nil, clock, "v1", "v1", slog.Default())
	res, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Force: true,
		KnownVersions: map[coordinate.ModuleCoordinate]struct{}{coordinatetest.MustNew("golang.org/x/text", "v0.21.0"): {}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.UnscanReason != domain.UnscanReasonVersionNotInToolchain {
		t.Fatalf("UnscanReason = %q, want verified version-not-in-toolchain", res.UnscanReason)
	}
	if !strings.Contains(res.UnscannableReason, "golang.org/x/text@v0.3.8") {
		t.Errorf("recovered coordinate = %q, want the required v0.3.8, not the out-of-scope replace target v0.9.9", res.UnscannableReason)
	}
}

// TestScanModule_MetadataPath_PersistsEnrichedFindings is the round-trip guard:
// when a module falls back to the metadata path, the advisory's summary,
// affected range, fixed version and at-risk symbols flow through the scan into
// the persisted record, so vuln-show can answer remediation without the user
// leaving the tool.
func TestScanModule_MetadataPath_PersistsEnrichedFindings(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("github.com/gorilla/csrf", "v1.7.3")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
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
	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("www.velocidex.com/golang/velociraptor", "v0.76.6")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("golang.org/x/tools", "v0.26.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := &fakeScanner{err: fmt.Errorf("govulncheck: loading packages: invalid array length")}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}} // no advisories
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("golang.org/x/text", "v0.3.0")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("example.com/nogomod", "v1.0.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	scanner := scannerUnscannable(coord)
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Version: "v1"}} // no advisories
	clock := fixedClock{t: now}

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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
	coord := coordinatetest.MustNew("github.com/big/module", "v2.0.0")
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

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
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

// scanModuleFixture wires a fetched module and the use case, so a test can vary
// only the scanner verdict and the advisory database.
func scanModuleFixture(t *testing.T, coord coordinate.ModuleCoordinate, scanner *fakeScanner, db *fakeDatabase) (*application.ScanModuleUseCase, *fakeVulnStore) {
	t.Helper()
	ctx := t.Context()
	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil,
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}, "v1", "v1", slog.Default(),
	)
	return uc, vulnStore
}

// A module scanned in isolation is govulncheck's main module, and a main module
// has no version, so version-range advisory matching can never report an
// advisory about the module itself. A successful source scan therefore returns
// no findings for it, and before this guard that was recorded as Clean — a false
// negative that got MORE likely as scanning improved, because the advisory set
// was consulted only when the scan failed.
func TestScanModule_SuccessfulSourceScanStillMatchesOwnAdvisories(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("github.com/gomarkdown/markdown", "v1.0.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// The source scan succeeds and reports nothing, exactly as it does for a
	// module in the main-module position.
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{
		coord.String(): {Coordinate: coord, OverallStatus: domain.StatusClean},
	}}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:  "vulndb content",
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			coord: {{ID: "GO-2024-3205", Summary: "Infinite loop", AffectedRange: "< v1.1.0", FixedIn: "v1.1.0"}},
		},
	}
	uc, vulnStore := scanModuleFixture(t, coord, scanner, db)

	// Force skips the CheckVulnerable pre-filter at step 3.5 and runs the heavy
	// scan — the path every --force walk takes, and the one that produced Clean
	// records never checked against the advisory database.
	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusAffected {
		t.Fatalf("OverallStatus = %s, want %s: a clean source scan must not suppress a coordinate-matched advisory",
			res.OverallStatus, domain.StatusAffected)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "GO-2024-3205" {
		t.Fatalf("Findings = %+v, want the coordinate-matched advisory", res.Findings)
	}
	// Reachability was not determined by the source scan, and that must be
	// visible rather than defaulted to "not reachable".
	if res.Findings[0].Reachable != nil {
		t.Errorf("Reachable = %+v, want nil when the source scan could not report the advisory", res.Findings[0].Reachable)
	}
	persisted, ok, err := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", db.snapshot)
	if err != nil || !ok {
		t.Fatal("record not persisted")
	}
	if persisted.OverallStatus != domain.StatusAffected {
		t.Errorf("persisted OverallStatus = %s, want %s", persisted.OverallStatus, domain.StatusAffected)
	}
}

// A Clean verdict must mean "advisories were matched and none applied".
func TestScanModule_CleanVerdictMeansAdvisoriesWereMatched(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{
		coord.String(): {Coordinate: coord, OverallStatus: domain.StatusClean},
	}}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:  "vulndb content",
	}
	uc, _ := scanModuleFixture(t, coord, scanner, db)
	res, err := uc.Scan(t.Context(), application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusClean {
		t.Errorf("OverallStatus = %s, want %s", res.OverallStatus, domain.StatusClean)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %+v, want none", res.Findings)
	}
}

// The source analysis knows reachability the coordinate match cannot, so where
// both report the same advisory the source finding must survive intact.
func TestScanModule_SourceFindingWinsOverCoordinateMatch(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	reachable := &domain.ReachabilityResult{IsReachable: true}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{
		coord.String(): {
			Coordinate:    coord,
			OverallStatus: domain.StatusAffected,
			Findings: []domain.VulnerabilityFinding{
				{ID: "GO-2024-0001", Summary: "from source", Reachable: reachable},
			},
		},
	}}
	db := &fakeDatabase{
		snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:  "vulndb content",
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			coord: {{ID: "GO-2024-0001", Summary: "from coordinate"}},
		},
	}
	uc, _ := scanModuleFixture(t, coord, scanner, db)
	res, err := uc.Scan(t.Context(), application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1", Force: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 (the advisory must not be duplicated)", len(res.Findings))
	}
	if res.Findings[0].Reachable == nil || !res.Findings[0].Reachable.IsReachable {
		t.Errorf("source reachability was lost: %+v", res.Findings[0])
	}
	if res.Findings[0].Summary != "from source" {
		t.Errorf("Summary = %q, want the source analysis finding to win", res.Findings[0].Summary)
	}
}

// The sharpest form of the defect: the CheckVulnerable pre-filter at step 3.5
// establishes that this module has a known advisory, which is why the heavy scan
// runs at all — and then the source analysis, which cannot match an advisory
// about its own main module, overrides that with Clean. The scan discards a
// verdict the pipeline had already established.
func TestScanModule_PrefilterVulnerableIsNotOverriddenByCleanSourceScan(t *testing.T) {
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{
		coord.String(): {Coordinate: coord, OverallStatus: domain.StatusClean},
	}}
	db := &fakeDatabase{
		snapshot:    domain.DatabaseSnapshot{Source: "test", Version: "v1", RetrievedAt: now},
		content:     "vulndb content",
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-2024-0002"}},
	}
	uc, _ := scanModuleFixture(t, coord, scanner, db)

	res, err := uc.Scan(t.Context(), application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.OverallStatus != domain.StatusAffected {
		t.Fatalf("OverallStatus = %s, want %s: the pre-filter established this module is affected and the source scan must not erase it",
			res.OverallStatus, domain.StatusAffected)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "GO-2024-0002" {
		t.Errorf("Findings = %+v, want the advisory the pre-filter matched", res.Findings)
	}
}
