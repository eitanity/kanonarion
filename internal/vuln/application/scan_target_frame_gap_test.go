package application_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// loadError is the shape of the failure this file is about: govulncheck exits
// non-zero without loading a single package, because the module ships no go.mod
// and the offline toolchain cannot resolve the package that would supply one.
// It is the error text the live reproduction logged, shortened.
const loadError = "govulncheck exited with error: exit status 1; cannot find module providing package " +
	"github.com/Masterminds/goutils; module lookup disabled by GOPROXY=off"

// soleTargetFixture wires a coordinate-keyed walk with exactly ONE node: the
// target. It is the shape of the live reproduction — a walk of a single
// published module — and it is the shape in which the defect is undeniable,
// because there is no dependency whose verdict could stand in for the walk's
// coverage.
type soleTargetFixture struct {
	walkUC    *application.ScanWalkUseCase
	scanner   *fakeScanner
	vulnStore *fakeVulnStore
	snapshot  domain.DatabaseSnapshot
	target    coordinate.ModuleCoordinate
	walkID    string
}

func newSoleTargetFixture(t *testing.T, scanner *fakeScanner) soleTargetFixture {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	walkID := "walk-sole-target"
	target := coordinatetest.MustNew("github.com/Masterminds/sprig", "v2.22.0+incompatible")

	walk := walkdomain.WalkRecord{
		ID:     walkID,
		Target: target,
		Graph: walkdomain.Graph{
			Target: target,
			Nodes:  []walkdomain.GraphNode{{Coordinate: target, ResolutionSource: walkdomain.ResolutionMVS}},
		},
	}

	walkStore := newFakeWalkStore()
	if err := walkStore.PutWalk(ctx, walk); err != nil {
		t.Fatalf("PutWalk: %v", err)
	}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()
	snapshot := vulntest.MustNew("test", "v1")
	db := &fakeDatabase{snapshot: snapshot}
	clock := fixedClock{t: now}

	// The target's source IS in the store. That is what separates this from
	// source-not-in-store: the bytes are held and were handed to the scanner,
	// which then could not load them.
	seedRec := fetchtest.Record(t, fetchtest.Coordinate(target), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip-sprig"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip-sprig")); err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(target), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip-sprig"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	return soleTargetFixture{
		walkUC: walkUC, scanner: scanner, vulnStore: vulnStore,
		snapshot: snapshot, target: target, walkID: walkID,
	}
}

// TestScanWalk_TargetThatFailsToLoad_ReportsPartialCoverage is the regression
// test for the false clean.
//
// A walk of one module whose target-rooted analysis fails to load reported
// Complete coverage and a Clean findings axis, and exited 0. Nothing about that
// run was a measurement of the target in the frame the walk asked for: the
// analysis never started, and the isolated fallback answered a different
// question. The run must state the gap it has rather than the completeness it
// has not established.
func TestScanWalk_TargetThatFailsToLoad_ReportsPartialCoverage(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{
		targetRooted: true,
		targetStatus: domain.StatusScanFailed,
		targetReason: loadError,
	}
	f := newSoleTargetFixture(t, scanner)

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.targetCalls != 1 {
		t.Fatalf("target-rooted scan ran %d times, want 1: the test is not on the path it describes", scanner.targetCalls)
	}
	// The premise of the whole test: the fallback path DID produce an
	// analysed-and-clean answer for the target. Without it, Partial below would
	// prove nothing — it is also what a walk that simply found no records
	// reports.
	fallback, ok, err := f.vulnStore.GetVulnerabilityRecordAt(ctx, f.target, "v1", f.snapshot, domain.RootingIsolated)
	if err != nil || !ok {
		t.Fatalf("the isolated fallback left no record, so there is no cleaner answer for the run to have preferred: ok=%v err=%v", ok, err)
	}
	if coverage, findings := domain.RecordAxes(fallback); coverage != domain.CoverageAnalysed || findings != domain.FindingsRecordClean {
		t.Fatalf("the isolated fallback recorded %v/%v, want Analysed/Clean: the false-clean input is not present", coverage, findings)
	}

	if run.CoverageStatus != domain.CoveragePartial {
		t.Errorf("CoverageStatus = %v, want Partial: the target was never analysed in this run's frame", run.CoverageStatus)
	}
	if run.Counts.Analysed != 0 {
		t.Errorf("Counts.Analysed = %d, want 0: no module was analysed in the run's frame", run.Counts.Analysed)
	}
	if run.Counts.Unscannable != 1 {
		t.Errorf("Counts.Unscannable = %d, want 1", run.Counts.Unscannable)
	}
	if run.OverallStatus != domain.WalkStatusPartial {
		t.Errorf("OverallStatus = %v, want Partial", run.OverallStatus)
	}

	// The reason travels with the refusal, in both the machine code and the
	// operator's text. A refusal that does not say why is not an answer.
	counted := f.countedRecord(t, run)
	if counted.UnscanReason != domain.UnscanReasonTargetLoadFailed {
		t.Errorf("UnscanReason = %q, want %q", counted.UnscanReason, domain.UnscanReasonTargetLoadFailed)
	}
	if !strings.Contains(counted.ErrorDetail, "module lookup disabled by GOPROXY=off") {
		t.Errorf("ErrorDetail = %q, want the govulncheck load error", counted.ErrorDetail)
	}
	if coverage, _ := domain.RecordAxes(counted); coverage != domain.CoverageUnscannable {
		t.Errorf("counted record coverage = %v, want Unscannable", coverage)
	}
}

// TestScanWalk_DoesNotCountARecordFromAnotherFrameAsCoverage is the frame-matched
// counting regression, and it reproduces the live failure exactly: a warm store
// already holds an isolated, analysed, clean record for the target from an
// UNRELATED walk. The isolated fallback reuses it and runs no scan at all, so
// the run performs zero analyses — and used to report Complete, Clean on the
// strength of the other walk's record.
func TestScanWalk_DoesNotCountARecordFromAnotherFrameAsCoverage(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{
		targetRooted: true,
		targetStatus: domain.StatusScanFailed,
		targetReason: loadError,
	}
	f := newSoleTargetFixture(t, scanner)

	reused := f.seedIsolatedRecordFromAnotherWalk(t)

	run, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if scanner.scanCalls != 0 {
		t.Fatalf("the isolated fallback scanned %d times; the seeded record was not reused, so this is not the reproduction", scanner.scanCalls)
	}
	if run.CoverageStatus != domain.CoveragePartial {
		t.Errorf("CoverageStatus = %v, want Partial: this run measured nothing", run.CoverageStatus)
	}
	if run.Counts.Analysed != 0 {
		t.Errorf("Counts.Analysed = %d, want 0", run.Counts.Analysed)
	}

	counted := f.countedRecord(t, run)
	if counted.ContentHash == reused.ContentHash {
		t.Fatalf("the run counted the reused record from walk %q as its own coverage", reused.WalkID)
	}
	// The counted record must name the run's own frame. That is what makes the
	// refusal checkable: a reader can see which question went unanswered.
	if got, want := domain.RecordRooting(counted), domain.TargetRootedAt(f.target); got != want {
		t.Errorf("counted record rooting = %q, want the run's own frame %q", got, want)
	}
	if counted.WalkID != f.walkID {
		t.Errorf("counted record was written by walk %q, want this run's walk %q", counted.WalkID, f.walkID)
	}
	// The reused record is not destroyed. It is a real measurement in its own
	// frame and a reader asking the isolated question still gets it; only the
	// run's coverage claim changes.
	isolated, ok, err := f.vulnStore.GetVulnerabilityRecordAt(ctx, f.target, "v1", f.snapshot, domain.RootingIsolated)
	if err != nil || !ok {
		t.Fatalf("isolated record no longer readable: ok=%v err=%v", ok, err)
	}
	if isolated.ContentHash != reused.ContentHash {
		t.Errorf("isolated frame now serves %q, want the seeded record %q", isolated.ContentHash, reused.ContentHash)
	}
}

// countedRecord returns the record the run recorded as its verdict for the
// target — the one its coverage counters were computed from.
func (f soleTargetFixture) countedRecord(t *testing.T, run domain.WalkScanRun) domain.VulnerabilityRecord {
	t.Helper()
	hash, ok := run.PerModuleResults[f.target]
	if !ok {
		t.Fatalf("the run recorded no result for its own target")
	}
	rec, ok, err := f.vulnStore.GetVulnerabilityRecordAt(t.Context(), f.target, "v1", f.snapshot, domain.TargetRootedAt(f.target))
	if err != nil || !ok {
		t.Fatalf("no record in the run's own frame: ok=%v err=%v", ok, err)
	}
	if rec.ContentHash != hash {
		t.Fatalf("the run counted %q, which is not the record in its own frame (%q)", hash, rec.ContentHash)
	}
	return rec
}

// seedIsolatedRecordFromAnotherWalk writes the cache hit: an isolated, analysed,
// clean record for the target, attributed to a different walk, under this run's
// pipeline version and snapshot so the reuse check matches it.
func (f soleTargetFixture) seedIsolatedRecordFromAnotherWalk(t *testing.T) domain.VulnerabilityRecord {
	t.Helper()
	rec := domain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       f.target,
		WalkID:           "walk-somebody-elses",
		OverallStatus:    domain.StatusClean,
		DatabaseSnapshot: f.snapshot,
		ScannedAt:        time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC),
		FirstScannedAt:   time.Date(2023, 12, 31, 0, 0, 0, 0, time.UTC),
		PipelineVersion:  "v1",
		Rooting:          domain.RootingIsolated,
		AnalysisSurface:  domain.AnalysisSurfaceFetched,
	}
	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the seeded record: %v", err)
	}
	if err := f.vulnStore.PutVulnerabilityRecord(t.Context(), sealed); err != nil {
		t.Fatalf("seeding the reused record: %v", err)
	}
	return sealed
}
