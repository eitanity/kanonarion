package sqlite_test

import (
	"context"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func sealedFailure(t *testing.T, cause domain2.FailureCause) domain2.CallGraphRecord {
	t.Helper()
	r := domain2.CallGraphRecord{
		SchemaVersion:    domain2.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       testCoord,
		Algorithm:        domain2.AlgorithmCHA,
		Completeness:     domain2.CompletenessFailed,
		AnalysisSource:   domain2.AnalysisSourceModuleZip,
		ArtefactIdentity: "zip:h1:failing",
		OverallStatus:    domain2.CallGraphStatusLoadFailed,
		FailureCause:     cause,
		FailureDetail:    "meta load: err: exit status 1",
		ExtractedAt:      testTime,
		PipelineVersion:  testPipeline,
	}
	r.Sort()
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// TestFailureCauseSurvivesTheStore is the round trip that matters for the gate:
// the cause must come back off disk, or every read would decide eligibility from
// a zero value the decoder dropped.
func TestFailureCauseSurvivesTheStore(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.PutCallGraphRecord(ctx, sealedFailure(t, domain2.FailureCauseEnvironment)); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	got, found, err := s.GetCallGraphRecord(ctx, testCoord, testPipeline)
	if err != nil {
		t.Fatalf("GetCallGraphRecord: %v", err)
	}
	if !found {
		t.Fatal("the failure record was not found; it must be kept as evidence, only made ineligible")
	}
	if got.FailureCause != domain2.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q off disk, want %q", got.FailureCause, domain2.FailureCauseEnvironment)
	}
	if domain2.RecordIsCacheable(got) {
		t.Error("an environment failure read back as cacheable")
	}
}

// TestFailureCauseIsReadableAsAColumn pins the denormalised copy, which is what
// lets the population be counted without decompressing a blob per row — the
// measurement the ticket for this axis had to write a Go program to take.
func TestFailureCauseIsReadableAsAColumn(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.PutCallGraphRecord(ctx, sealedFailure(t, domain2.FailureCauseEnvironment)); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_records WHERE failure_cause = 'environment'`)
	if n != 1 {
		t.Errorf("failure_cause column holds %d environment rows, want 1", n)
	}
}

// TestFailureCauseColumnIsEmptyForASuccessfulRecord keeps the column honest: a
// record that did not fail states no cause, exactly as its blob does.
func TestFailureCauseColumnIsEmptyForASuccessfulRecord(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
	})
	if err := s.PutCallGraphRecord(ctx, rec); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	n := countRows(t, s, `SELECT COUNT(*) FROM callgraph_records WHERE failure_cause = ''`)
	if n != 1 {
		t.Errorf("%d rows carry an empty failure_cause, want 1", n)
	}
}
