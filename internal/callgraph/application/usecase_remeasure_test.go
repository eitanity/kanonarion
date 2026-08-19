package application_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// advancingClock hands out a later time on every reading, which is what a real
// clock does and what a fixed test clock hides: two runs a second apart carry
// different extracted_at values, and extracted_at is inside the record's seal.
type advancingClock struct {
	t time.Time
	n int
}

func (c *advancingClock) Now() time.Time {
	c.n++
	return c.t.Add(time.Duration(c.n) * time.Second)
}

// TestExecute_ReMeasuringAnEnvironmentFailureAppendsNothing.
//
// A record the environment cut short is never eligible as a cache hit, by
// design, so every later run of the coordinate re-derives it. Each of those runs
// used to append a generation — a full blob plus its edge rows — for ever, on a
// module that will keep failing until the cache is warmed. The re-measurement
// still happens; what stops is recording the same fact again.
func TestExecute_ReMeasuringAnEnvironmentFailureAppendsNothing(t *testing.T) {
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

	first, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if first.Reused {
		t.Fatal("the first run reported a reuse; there was nothing to reuse")
	}

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if analyser.calls != 2 {
		t.Fatalf("the analyser ran %d times; an environment failure must be re-attempted", analyser.calls)
	}
	if !second.Reused {
		t.Error("the second run did not report that its measurement matched the stored generation")
	}
	if len(store.puts) != 1 {
		t.Errorf("%d generations were written for two identical measurements, want 1", len(store.puts))
	}
	if second.Record.ContentHash != first.Record.ContentHash {
		t.Error("the second run served a different record from the one already held")
	}
}

// TestExecute_AMeasurementThatDiffersIsStillAppended is the control. The rule
// suppresses a repeat, never a change: a run that got further than the one
// before it is a new fact and the ladder needs it in the ledger.
func TestExecute_AMeasurementThatDiffersIsStillAppended(t *testing.T) {
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
	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The cache was warmed between the runs, and the analysis now reaches the
	// whole module.
	analyser.record.OverallStatus = domain2.CallGraphStatusExtracted
	analyser.record.FailureCause = domain2.FailureCauseUnrecorded
	analyser.record.FailureDetail = ""
	analyser.record.Nodes = append(analyser.record.Nodes,
		domain2.CallNode{ID: "example.com/mod.Everything", Symbol: "Everything"})

	second, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if second.Reused {
		t.Error("a measurement that reached further was discarded as a repeat")
	}
	if len(store.puts) != 2 {
		t.Errorf("%d generations were written for two different measurements, want 2", len(store.puts))
	}
}
