package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// seedModuleFault stores the record a pre-modules module was left with before a
// build list could reach the analysis: the load resolved metadata, type-checked
// nothing, and the failure was attributed to the module — which is what makes it
// cacheable, and therefore permanent.
func seedModuleFault(t *testing.T, store *fakeCallGraphStore, coord coordinate.ModuleCoordinate) domain2.CallGraphRecord {
	t.Helper()
	var h domain2.CallGraphRecordHasher
	rec := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Coordinate:      coord,
		Algorithm:       domain2.AlgorithmCHA,
		OverallStatus:   domain2.CallGraphStatusLoadFailed,
		Completeness:    domain2.CompletenessMetadataOnly,
		FailureCause:    domain2.FailureCauseModule,
		FailureDetail:   "no packages successfully loaded",
		PipelineVersion: testPipelineV,
		ExtractedAt:     testTime,
	}
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing the seeded record: %v", err)
	}
	if err := store.PutCallGraphRecord(context.Background(), rec); err != nil {
		t.Fatalf("seeding the cached module fault: %v", err)
	}
	return rec
}

// TestExecute_CachedModuleFaultDoesNotBlockAnAnalysisWithABuildList is the claim
// that makes the feature reachable at all.
//
// A module fault is cacheable by design — the module will fail the same way
// tomorrow — so once one is written nothing re-analyses the module naturally.
// For a pre-modules module that is the wrong permanent answer: the failure was
// never a property of the artefact, it was the absence of require directives,
// and a request carrying a resolved build list can now supply them. The cached
// record must therefore not be served back to such a request.
func TestExecute_CachedModuleFaultDoesNotBlockAnAnalysisWithABuildList(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}
	storeFetchRecord(t, facts, blobs, testCoord)
	seedModuleFault(t, store, testCoord)

	dep, err := coordinate.NewModuleCoordinate("example.com/dep", "v1.2.3")
	if err != nil {
		t.Fatalf("building the build-list coordinate: %v", err)
	}
	inputs := domain2.AnalysisInputs{
		BuildList: map[coordinate.ModuleCoordinate]struct{}{dep: {}},
		Source:    "01WALKAAAAAAAAAAAAAAAAAAAA",
	}

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: testCoord,
		Inputs:     inputs,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Fatal("the cached module fault was served back to a request carrying a build list; " +
			"nothing would ever re-derive the module and the failure is permanent")
	}
	if analyser.calls == 0 {
		t.Fatal("no analysis ran, so the build list reached nothing")
	}
	if analyser.lastInputs.Source != inputs.Source {
		t.Errorf("analysis was offered build list source %q, want %q",
			analyser.lastInputs.Source, inputs.Source)
	}
	if len(analyser.lastInputs.BuildList) != 1 {
		t.Errorf("analysis was offered %d build-list entries, want 1", len(analyser.lastInputs.BuildList))
	}
	// The control that must be non-zero: the record written names the build list
	// it was offered, which is what stops a THIRD request re-analysing again.
	if result.Record.BuildListSource != inputs.Source {
		t.Errorf("persisted record names build list %q, want %q",
			result.Record.BuildListSource, inputs.Source)
	}
}

// TestExecute_RecordFromTheSameBuildListIsStillServed pins the other half. The
// bypass above is a one-time upgrade, not a permanent cache defeat: once a
// record says which build list it was offered, a request from that same build
// list is answered from the ledger exactly as before.
func TestExecute_RecordFromTheSameBuildListIsStillServed(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}
	storeFetchRecord(t, facts, blobs, testCoord)

	const walkID = "01WALKAAAAAAAAAAAAAAAAAAAA"
	var h domain2.CallGraphRecordHasher
	rec := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Coordinate:      testCoord,
		Algorithm:       domain2.AlgorithmCHA,
		OverallStatus:   domain2.CallGraphStatusLoadFailed,
		Completeness:    domain2.CompletenessMetadataOnly,
		FailureCause:    domain2.FailureCauseModule,
		PipelineVersion: testPipelineV,
		ExtractedAt:     testTime,
		BuildListSource: walkID,
	}
	rec, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if err := store.PutCallGraphRecord(context.Background(), rec); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	dep, _ := coordinate.NewModuleCoordinate("example.com/dep", "v1.2.3") //nolint:errcheck // fixed literal
	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: testCoord,
		Inputs: domain2.AnalysisInputs{
			BuildList: map[coordinate.ModuleCoordinate]struct{}{dep: {}},
			Source:    walkID,
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("a record already offered this build list was re-analysed; the bypass is " +
			"an upgrade path, not a standing cache defeat")
	}
	if analyser.calls != 0 {
		t.Errorf("analyser ran %d time(s) for a question the ledger had already answered", analyser.calls)
	}
}

// TestExecute_CachedModuleFaultIsStillServedWithoutABuildList is the control for
// the zero above. Nothing about the cache changed for a request that offers no
// build list: it has nothing new to bring, so re-analysing would be pure cost.
func TestExecute_CachedModuleFaultIsStillServedWithoutABuildList(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}
	storeFetchRecord(t, facts, blobs, testCoord)
	seedModuleFault(t, store, testCoord)

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("a module fault was re-analysed for a request that could not improve on it")
	}
	if analyser.calls != 0 {
		t.Errorf("analyser ran %d time(s) with nothing new to offer", analyser.calls)
	}
}
