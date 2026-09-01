package application_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestLocalExecute_StatesTheWorktreeGateThatGovernedTheAppend: the local route
// consults the tree-scoped gate, and a record it appends says so — and says
// whether this run asked that gate or forced past it.
func TestLocalExecute_StatesTheWorktreeGateThatGovernedTheAppend(t *testing.T) {
	cases := []struct {
		name  string
		force bool
		want  domain2.GateOutcome
	}{
		{"gate consulted", false, domain2.GateOutcomeConsulted},
		{"gate bypassed", true, domain2.GateOutcomeBypassed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeCallGraphStore{}
			analyser := &fakeAnalyser{record: domain2.CallGraphRecord{
				OverallStatus: domain2.CallGraphStatusExtracted,
			}}
			uc := buildLocalUseCase(store, analyser)

			res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
				Dir:        "/work/tree",
				Coordinate: testCoord,
				Force:      tc.force,
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := res.Record.DerivedBy.Gate; got != domain2.ReuseGateWorktree {
				t.Errorf("gate = %q, want %q", got, domain2.ReuseGateWorktree)
			}
			if got := res.Record.DerivedBy.Outcome; got != tc.want {
				t.Errorf("outcome = %q, want %q", got, tc.want)
			}
			if len(store.puts) != 1 {
				t.Fatalf("%d generations appended, want 1", len(store.puts))
			}
			if store.puts[0].DerivedBy != res.Record.DerivedBy {
				t.Error("the appended generation states a different derivation from the served one")
			}
		})
	}
}

// TestExecute_StatesTheLedgerGateThatGovernedTheAppend: the artefact route
// consults the identical-generation check, and its records say which gate that
// was — a reader must be able to tell the two routes apart.
func TestExecute_StatesTheLedgerGateThatGovernedTheAppend(t *testing.T) {
	cases := []struct {
		name  string
		force bool
		want  domain2.GateOutcome
	}{
		{"gate consulted", false, domain2.GateOutcomeConsulted},
		{"gate bypassed", true, domain2.GateOutcomeBypassed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := &fakeFactStore{}
			blobs := &fakeBlobStore{}
			store := &fakeCallGraphStore{}
			analyser := &fakeAnalyser{record: domain2.CallGraphRecord{
				SchemaVersion: domain2.CallGraphSchemaVersion,
				Algorithm:     domain2.AlgorithmCHA,
				Completeness:  domain2.CompletenessBuiltWithBodies,
				OverallStatus: domain2.CallGraphStatusExtracted,
				Nodes:         []domain2.CallNode{{ID: "example.com/mod.Reached", Symbol: "Reached"}},
			}}
			storeFetchRecord(t, facts, blobs, testCoord)

			uc := application.NewExtractCallGraphUseCase(application.Config{
				Facts: facts, Blobs: blobs, Store: store, Analyser: analyser,
				Clock: &advancingClock{t: testTime}, Stopwatch: fakeStopwatch{},
				PipelineVersion: testPipelineV, Logger: slog.Default(),
			})

			res, err := uc.Execute(context.Background(), application.ExtractRequest{
				Coordinate: testCoord,
				Force:      tc.force,
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := res.Record.DerivedBy.Gate; got != domain2.ReuseGateLedger {
				t.Errorf("gate = %q, want %q", got, domain2.ReuseGateLedger)
			}
			if got := res.Record.DerivedBy.Outcome; got != tc.want {
				t.Errorf("outcome = %q, want %q", got, tc.want)
			}
			if len(store.puts) != 1 {
				t.Fatalf("%d generations appended, want 1", len(store.puts))
			}
		})
	}
}

// TestExecute_AForcedRunStillAppendsNoDuplicateForAGatedOne is the dedup guard
// at the application seam: the gate on the SECOND run must still recognise the
// generation the first appended, whichever way each was derived.
func TestExecute_AForcedRunStillAppendsNoDuplicateForAGatedOne(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Algorithm:     domain2.AlgorithmCHA,
		Completeness:  domain2.CompletenessBuiltWithBodies,
		OverallStatus: domain2.CallGraphStatusPartial,
		FailureCause:  domain2.FailureCauseEnvironment,
		FailureDetail: "lib/hooks.go:10:2: could not import example.com/dep",
		Nodes:         []domain2.CallNode{{ID: "example.com/mod.Reached", Symbol: "Reached"}},
	}}
	storeFetchRecord(t, facts, blobs, testCoord)

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts: facts, Blobs: blobs, Store: store, Analyser: analyser,
		Clock: &advancingClock{t: testTime}, Stopwatch: fakeStopwatch{},
		PipelineVersion: testPipelineV, Logger: slog.Default(),
	})

	// A forced run first, so the held generation says it was forced.
	if _, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: testCoord, Force: true,
	}); err != nil {
		t.Fatalf("Execute forced: %v", err)
	}
	// Then a gated one. The environment failure is never cache-eligible, so the
	// analysis runs again and the comparison decides.
	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !second.Reused {
		t.Error("a gated run appended a second copy of a generation a forced run had already recorded")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations written for one measurement, want 1", len(store.puts))
	}
}
