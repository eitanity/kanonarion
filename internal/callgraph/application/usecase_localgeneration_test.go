package application_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// localZipRecord is what the analyser hands back for a working tree that was
// ingested as an artefact: the project-walk root, materialised into a zip and
// analysed through the published route. AnalysisSource and the artefact
// identity are what production stamps, and the test would prove nothing without
// them — the identity is the only thing that names which bytes were read.
func localZipRecord(nodes ...domain2.CallNode) domain2.CallGraphRecord {
	return domain2.CallGraphRecord{
		SchemaVersion:  domain2.CallGraphSchemaVersion,
		Algorithm:      domain2.AlgorithmCHA,
		Completeness:   domain2.CompletenessBuiltWithBodies,
		OverallStatus:  domain2.CallGraphStatusExtracted,
		AnalysisSource: domain2.AnalysisSourceModuleZip,
		Nodes:          nodes,
	}
}

func localUseCase(t *testing.T) (*application.ExtractCallGraphUseCase, *fakeCallGraphStore, *fakeAnalyser, *fakeFactStore, coordinate.ModuleCoordinate) {
	t.Helper()
	coord, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: localZipRecord(
		domain2.CallNode{ID: "example.com/mod.Root", Symbol: "Root"},
	)}
	storeFetchRecord(t, facts, blobs, coord)

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts: facts, Blobs: blobs, Store: store, Analyser: analyser,
		Clock: &advancingClock{t: testTime}, Stopwatch: fakeStopwatch{},
		PipelineVersion: testPipelineV, Logger: slog.Default(),
	})
	return uc, store, analyser, facts, coord
}

// reIngest rewrites the coordinate's fetch record as a later walk would: the
// same bytes under the same artefact identity, sealed under a new clock. It is
// what makes SourceContentHash move without anything about the source changing.
func reIngest(t *testing.T, facts *fakeFactStore, coord coordinate.ModuleCoordinate, at time.Time) {
	t.Helper()
	before, _, err := facts.GetFetchRecord(context.Background(), coord, testFetchPipV)
	if err != nil {
		t.Fatalf("GetFetchRecord: %v", err)
	}
	if err := facts.PutFetchRecord(context.Background(), fetchtest.Sealed(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(testFetchPipV),
		fetchtest.Content("blob:test"),
		fetchtest.FetchedAt(at),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
	after, _, err := facts.GetFetchRecord(context.Background(), coord, testFetchPipV)
	if err != nil {
		t.Fatalf("GetFetchRecord: %v", err)
	}
	if before.ContentHash == after.ContentHash {
		t.Fatal("the re-ingest did not move the fetch seal; the fixture proves nothing")
	}
	if before.ModuleHash != after.ModuleHash {
		t.Fatal("the re-ingest moved the module hash; it must name the same bytes")
	}
}

// TestExecute_ReExtractingAnUnchangedLocalTreeAppendsNothing.
//
// A local coordinate is never served from cache: a local version pins no
// content and the working tree mutates, so the analysis runs again on every
// run. That is correct and this does not change it. What it stops is the
// SECOND question being skipped: the re-analysis came back stating what the
// ledger already states, and appending it again writes a full blob and its
// whole edge set to record nothing new.
func TestExecute_ReExtractingAnUnchangedLocalTreeAppendsNothing(t *testing.T) {
	uc, store, analyser, _, coord := localUseCase(t)

	first, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if first.Reused {
		t.Fatal("the first run reported a reuse; there was nothing to reuse")
	}

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if analyser.calls != 2 {
		t.Fatalf("the analyser ran %d times; a local tree must be re-read on every run", analyser.calls)
	}
	if !second.Reused {
		t.Error("the second run did not report that its measurement matched the stored generation")
	}
	if second.FromCache {
		t.Error("the second run reported a cache hit; the analysis did run")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations were written for two reads of one unchanged tree, want 1", len(store.puts))
	}
	if second.Record.ContentHash != first.Record.ContentHash {
		t.Error("the second run served a different record from the one already held")
	}
}

// TestExecute_AChangedLocalTreeIsStillAppended is the control, and it is the
// half that matters most: a rule that suppressed a real re-analysis would make
// the project's own graph permanently stale.
func TestExecute_AChangedLocalTreeIsStillAppended(t *testing.T) {
	uc, store, analyser, _, coord := localUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The tree was edited between the runs and the analysis now reaches a symbol
	// that did not exist before.
	analyser.record.Nodes = append(analyser.record.Nodes,
		domain2.CallNode{ID: "example.com/mod.Added", Symbol: "Added"})

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if second.Reused {
		t.Error("a re-analysis of an edited tree was discarded as a repeat")
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written for two different trees, want 2", len(store.puts))
	}
}

// TestExecute_ForceAppendsALocalGenerationEvenWhenIdentical. --force is how a
// caller re-measures because something OUTSIDE the tree changed — a different
// toolchain, a repopulated module cache — and asks for the result to be
// recorded. Collapsing it into the held generation would leave that caller with
// no way to record a measurement at all.
func TestExecute_ForceAppendsALocalGenerationEvenWhenIdentical(t *testing.T) {
	uc, store, _, _, coord := localUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	forced, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if forced.Reused {
		t.Error("--force reported a reuse; it asks for the measurement to be recorded")
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written, want 2: --force records what it measured", len(store.puts))
	}
}

// TestExecute_AnUnnamedAnalysisMatchesNothing. A record that does not say WHICH
// content it read is not evidence that it read the same bytes as any other,
// including another that says nothing. Without that rule the ledger would
// collapse two analyses of two different trees into one on the strength of an
// absent field.
func TestExecute_AnUnnamedAnalysisMatchesNothing(t *testing.T) {
	uc, store, analyser, _, coord := localUseCase(t)
	// A record that names no source has no discriminator, which is exactly the
	// shape every generation written before the source field existed carries.
	analyser.record.AnalysisSource = domain2.AnalysisSourceUnrecorded

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if second.Reused {
		t.Error("two records naming no analysed content were treated as the same analysis")
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written, want 2: an absent name matches nothing", len(store.puts))
	}
}

// TestExecute_AnUnreadableLedgerStillRecordsTheMeasurement is the fault seam.
//
// The lookup runs AFTER the analysis, so a store that cannot answer it must not
// cost the run its answer: the measurement is recorded, and the fault is stated
// rather than swallowed. Losing a measured graph to protect an optimisation
// would be the worse failure by far.
func TestExecute_AnUnreadableLedgerStillRecordsTheMeasurement(t *testing.T) {
	uc, store, _, _, coord := localUseCase(t)
	store.getErr = errors.New("ledger unreadable")

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Reused {
		t.Error("a store that could not answer was read as agreement")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations were written, want 1: the measurement must still be recorded", len(store.puts))
	}
}

// TestExecute_ReIngestingTheRootBetweenRunsAppendsNothing is the realistic
// workflow, and the one a repeated `extract` against a single walk cannot
// reach.
//
// `walk --analyse-root` re-ingests the project's own tree on every run, because
// a local coordinate is never served from the fetch cache either. Each run
// therefore seals a fresh fetch record under its own clock, and the call graph
// record it produces points at that new fetch measurement through
// SourceContentHash — while reading byte-identical source, under an artefact
// identity that has not moved.
func TestExecute_ReIngestingTheRootBetweenRunsAppendsNothing(t *testing.T) {
	uc, store, analyser, facts, coord := localUseCase(t)

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(store.puts) != 1 {
		t.Fatalf("%d generations after the first run, want 1", len(store.puts))
	}

	// The next walk re-ingested the same tree: same bytes, same artefact, a fetch
	// record sealed a minute later.
	reIngest(t, facts, coord, testTime.Add(time.Minute))

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if analyser.calls != 2 {
		t.Fatalf("the analyser ran %d times; the tree must be re-read on every run", analyser.calls)
	}
	if !second.Reused {
		t.Error("a re-ingest of identical bytes was recorded as a new analysis")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations were written across two walk-then-extract runs, want 1", len(store.puts))
	}
}
