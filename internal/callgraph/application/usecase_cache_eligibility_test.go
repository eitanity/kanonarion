package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// storeFailureRecord seeds the call-graph store with a no-graph record carrying
// the given cause, as the analyser would have written it.
func storeFailureRecord(t *testing.T, store *fakeCallGraphStore, cause domain2.FailureCause) {
	t.Helper()
	var h domain2.CallGraphRecordHasher
	rec := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Coordinate:      testCoord,
		Algorithm:       domain2.AlgorithmCHA,
		Completeness:    domain2.CompletenessFailed,
		OverallStatus:   domain2.CallGraphStatusLoadFailed,
		FailureCause:    cause,
		FailureDetail:   "meta load: err: exit status 1",
		PipelineVersion: testPipelineV,
		ExtractedAt:     testTime,
	}
	sealed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := store.PutCallGraphRecord(context.Background(), sealed); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}
}

// TestExecute_EnvironmentFailureIsNotServedFromCache is the defect this axis
// exists for: a run whose toolchain could not start wrote a failure record, and
// every later run was served it back instead of re-attempting.
func TestExecute_EnvironmentFailureIsNotServedFromCache(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}

	storeFetchRecord(t, facts, blobs, testCoord)
	storeFailureRecord(t, store, domain2.FailureCauseEnvironment)

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Fatal("an environment failure was served as a cache hit; the run never re-attempts and only --force clears it")
	}
	if result.Record.OverallStatus == domain2.CallGraphStatusLoadFailed &&
		result.Record.FailureCause == domain2.FailureCauseEnvironment {
		t.Error("the re-attempt returned the stored failure rather than a fresh analysis")
	}
}

// TestExecute_ModuleFailureIsStillServedFromCache is the other half of the rule.
// A module that genuinely cannot be built is a stable finding, and re-deriving
// it on every walk would pay full analysis cost to rediscover it.
func TestExecute_ModuleFailureIsStillServedFromCache(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}

	storeFetchRecord(t, facts, blobs, testCoord)
	storeFailureRecord(t, store, domain2.FailureCauseModule)

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("a module failure was re-analysed; a stable finding must be served from cache")
	}
}

// TestExecute_UnattributedFailureIsReAttemptedOnce covers the records that
// predate the axis. They state no cause, so nothing about them says the module
// was at fault, and the re-attempt writes one that does state its cause.
func TestExecute_UnattributedFailureIsReAttemptedOnce(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}

	storeFetchRecord(t, facts, blobs, testCoord)
	storeFailureRecord(t, store, domain2.FailureCauseUnrecorded)

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("a failure record stating no cause was served as a cache hit")
	}
}
