package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	vulnreach "github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// buildIncompatibleScanErr is the toolchain failure an isolated scan records
// when the module's own build selects a version the walk never resolved.
const buildIncompatibleScanErr = "govulncheck: loading packages: \n" +
	"server.go:8:2: module lookup disabled by GOPROXY=off\n" +
	"/tmp/x/github.com/foo/bar@v1.0.0/server.go:8:2: could not import golang.org/x/crypto/acme (invalid package name: \"\")"

// projectionLoader serves one fixed call graph, or a fixed error.
type projectionLoader struct {
	proj ports.CallGraphProjection
	err  error
}

func (l projectionLoader) Load(_ context.Context, _ coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	return l.proj, l.err
}

// exportedVulnGraph is a graph of github.com/foo/bar whose exported Vuln is the
// advisory's symbol, built at the given completeness.
func exportedVulnGraph(completeness string, nodes ...ports.CallGraphNode) ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Nodes:              nodes,
		Completeness:       completeness,
		Algorithm:          "CHA",
		PipelineVersion:    "0.10.0",
		ArtifactKind:       "Library",
		ServableAsCacheHit: true,
	}
}

var vulnNode = ports.CallGraphNode{
	ID: "github.com/foo/bar.Vuln", Module: "github.com/foo/bar", Package: "github.com/foo/bar",
	Symbol: "Vuln", IsExportedAPI: true,
}

// unscannableScan runs an isolated scan that falls back to metadata-only, with
// the advisory matched by coordinate naming symbols.
func unscannableScan(t *testing.T, loader ports.CallGraphLoader, spawner *fakeCallGraphSpawner, findings []domain.VulnerabilityFinding, enable bool) domain.VulnerabilityRecord {
	t.Helper()
	ctx := t.Context()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("test", "v1")
	mustSucceed(t, vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader("")))
	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-2024-0001"}},
		findings:    map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{coord: findings},
	}
	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil,
		&fakeScanner{err: errors.New(buildIncompatibleScanErr)}, db, vulnreach.New(),
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}, "v1",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithCallGraphLoader(loader)
	if spawner != nil {
		uc = uc.WithCallGraphSpawner(spawner)
	}
	rec, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Snapshot: &snap, EnableReachability: enable, Force: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if coverage, _ := domain.RecordAxes(rec); coverage != domain.CoverageUnscannable || rec.CoverageStatus != domain.CoverageUnscannable {
		t.Fatalf("coverage = %q (stored %q), want Unscannable: the call graph must never turn a coverage gap into an analysis", coverage, rec.CoverageStatus)
	}
	return rec
}

func symbolFinding() []domain.VulnerabilityFinding {
	return []domain.VulnerabilityFinding{{ID: "GO-2024-0001", AffectedSymbols: []string{"Vuln"}}}
}

// TestUnscannableRecord_ReachabilityComesFromTheCallGraph: under --reachability a
// metadata-only record takes the analysed record's step, and the answer names
// the call-graph method, the graph's completeness and its pipeline.
func TestUnscannableRecord_ReachabilityComesFromTheCallGraph(t *testing.T) {
	rec := unscannableScan(t, projectionLoader{proj: exportedVulnGraph("BUILT_WITH_BODIES", vulnNode)}, nil, symbolFinding(), true)
	f := rec.Findings[0]
	if f.Reachable == nil {
		t.Fatalf("Reachable = nil, want a call-graph answer; note %q", f.ReachabilityNote)
	}
	if got := domain.FindingReachabilityState(f); got != domain.StateReachable {
		t.Errorf("state = %s, want reachable", got)
	}
	d := f.Reachable.DerivedBy
	if d.Analyser != domain.AnalyserCallGraphBFS || d.Fidelity != "BUILT_WITH_BODIES" || d.GraphPipeline != "0.10.0" {
		t.Errorf("derivation = %+v, want callgraph-bfs at BUILT_WITH_BODIES from pipeline 0.10.0", d)
	}
	if d.Rooting != domain.RootingIsolated {
		t.Errorf("derivation rooting = %q, want the record's isolated frame", d.Rooting)
	}
	if rec.CallGraphCompleteness != "BUILT_WITH_BODIES" || rec.CallGraphAlgorithm != "CHA" {
		t.Errorf("record fidelity = %q/%q, want BUILT_WITH_BODIES/CHA", rec.CallGraphCompleteness, rec.CallGraphAlgorithm)
	}
	if rec.UnscanReason == "" || rec.ErrorDetail == "" {
		t.Errorf("the coverage gap lost its evidence: reason %q, detail %q", rec.UnscanReason, rec.ErrorDetail)
	}
}

// TestUnscannableRecord_GraphBelowBodiesGivesNoConfidentNegative: a graph built
// without bodies finds nothing and says so as an unconfirmed negative.
func TestUnscannableRecord_GraphBelowBodiesGivesNoConfidentNegative(t *testing.T) {
	rec := unscannableScan(t, projectionLoader{proj: exportedVulnGraph("METADATA_ONLY")}, nil, symbolFinding(), true)
	f := rec.Findings[0]
	if f.Reachable == nil || f.Reachable.IsReachable {
		t.Fatalf("Reachable = %+v, want the graph's negative", f.Reachable)
	}
	if got, _ := domain.NegativeSoundness(f); got != domain.SoundnessUnconfirmed {
		t.Errorf("soundness = %s, want unconfirmed for a METADATA_ONLY graph", got)
	}
}

// TestUnscannableRecord_FailedExtractionLeavesNoAnswer: no graph stored and the
// on-demand extraction failing leaves Reachable nil with the reason on the finding.
func TestUnscannableRecord_FailedExtractionLeavesNoAnswer(t *testing.T) {
	spawner := &fakeCallGraphSpawner{err: errors.New("exit status 2"), stderr: []byte("LoadFailed")}
	notFound := projectionLoader{err: ports.ErrCallGraphNotFound}
	rec := unscannableScan(t, notFound, spawner, symbolFinding(), true)
	f := rec.Findings[0]
	if spawner.callCount() != 1 {
		t.Errorf("spawn calls = %d, want the on-demand extraction an analysed record gets", spawner.callCount())
	}
	if f.Reachable != nil {
		t.Errorf("Reachable = %+v, want nil: nothing was determined", f.Reachable)
	}
	if !strings.Contains(f.ReachabilityNote, "callgraph subprocess failed") {
		t.Errorf("note = %q, want the failed extraction named", f.ReachabilityNote)
	}
	if got := domain.FindingReachabilityState(f); got != domain.StateNotComputed {
		t.Errorf("state = %s, want not_computed", got)
	}
}

// TestUnscannableRecord_StepOnlyRunsWhenAsked: zero findings, or reachability
// not requested, leave the metadata-only record exactly as before.
func TestUnscannableRecord_StepOnlyRunsWhenAsked(t *testing.T) {
	for name, tc := range map[string]struct {
		findings []domain.VulnerabilityFinding
		enable   bool
	}{
		"zero findings":          {findings: []domain.VulnerabilityFinding{}, enable: true},
		"reachability not asked": {findings: symbolFinding(), enable: false},
	} {
		t.Run(name, func(t *testing.T) {
			spawner := &fakeCallGraphSpawner{}
			rec := unscannableScan(t, projectionLoader{err: ports.ErrCallGraphNotFound}, spawner, tc.findings, tc.enable)
			if spawner.callCount() != 0 {
				t.Errorf("spawn calls = %d, want none", spawner.callCount())
			}
			for _, f := range rec.Findings {
				if f.Reachable != nil || f.ReachabilityNote != "" {
					t.Errorf("finding %s carries reachability %+v / %q, want none", f.ID, f.Reachable, f.ReachabilityNote)
				}
			}
			if rec.CallGraphCompleteness != "" {
				t.Errorf("CallGraphCompleteness = %q, want empty: no graph was read", rec.CallGraphCompleteness)
			}
		})
	}
}

// TestUnfetchedRecord_TakesTheSameStep: the other metadata-only entry, a module
// with no source in the store, reaches the same step.
func TestUnfetchedRecord_TakesTheSameStep(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	vulnStore := newFakeVulnStore()
	snap := vulntest.MustNew("test", "v1")
	mustSucceed(t, vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader("")))
	db := &fakeDatabase{
		snapshot: snap,
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{coord: symbolFinding()},
	}
	uc := application.NewScanModuleUseCase(
		newFakeFacts(), newFakeBlob(), vulnStore, nil,
		&fakeScanner{}, db, vulnreach.New(),
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}, "v1",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithCallGraphLoader(projectionLoader{proj: exportedVulnGraph("BUILT_WITH_BODIES", vulnNode)})
	rec, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate: coord, WalkID: "walk-1", Snapshot: &snap, EnableReachability: true, Force: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rec.UnscanReason != domain.UnscanReasonSourceNotInStore || rec.CoverageStatus != domain.CoverageUnscannable {
		t.Fatalf("record = %q/%q, want the source-not-in-store coverage gap", rec.UnscanReason, rec.CoverageStatus)
	}
	if f := rec.Findings[0]; f.Reachable == nil || f.Reachable.DerivedBy.Analyser != domain.AnalyserCallGraphBFS {
		t.Errorf("finding = %+v, want a call-graph answer", f.Reachable)
	}
}
