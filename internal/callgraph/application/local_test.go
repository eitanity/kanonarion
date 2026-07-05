package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

func buildLocalUseCase(store *fakeCallGraphStore, analyser *fakeAnalyser) *application.ExtractLocalCallGraphUseCase {
	return application.NewExtractLocalCallGraphUseCase(application.LocalConfig{
		Store:           store,
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// TestLocalExecute_PersistsAndForwardsDir guards 'local' must
// analyse the working tree (forwarding the dir) and persist a record so
// callers/callees can later resolve internal symbols. No fetch/blob needed.
func TestLocalExecute_PersistsAndForwardsDir(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{
		OverallStatus: domain.CallGraphStatusExtracted,
	}}
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Errorf("expected fresh extraction, got FromCache=true")
	}
	if analyser.lastDir != "/work/tree" {
		t.Errorf("analyser dir = %q, want /work/tree", analyser.lastDir)
	}
	if _, ok, _ := store.GetCallGraphRecord(context.Background(), testCoord, testPipelineV); !ok {
		t.Errorf("local record not persisted; callers/callees cannot resolve internal symbols")
	}
}

// TestLocalExecute_AlwaysReanalyses guards the core freshness invariant: a
// working tree mutates between runs, so a stored record for the local
// coordinate must never short-circuit analysis. Even with a record already in
// the store, every Execute re-runs the analyser and overwrites the record —
// otherwise an edited working tree would resolve against a stale snapshot.
func TestLocalExecute_AlwaysReanalyses(t *testing.T) {
	store := &fakeCallGraphStore{}
	// A stale record from a previous run, distinguishable by node count.
	stale := domain.CallGraphRecord{Coordinate: testCoord, PipelineVersion: testPipelineV, NodeCount: 99}
	if err := store.PutCallGraphRecord(context.Background(), stale); err != nil {
		t.Fatalf("seed: %v", err)
	}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{
		OverallStatus: domain.CallGraphStatusExtracted,
	}}
	uc := buildLocalUseCase(store, analyser)

	// Two runs, both with the stale record present in the store.
	for i := 1; i <= 2; i++ {
		res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
			Dir:        "/work/tree",
			Coordinate: testCoord,
		})
		if err != nil {
			t.Fatalf("Execute run %d: %v", i, err)
		}
		if res.FromCache {
			t.Errorf("run %d: FromCache=true, want a fresh re-analysis", i)
		}
		if res.Record.NodeCount == 99 {
			t.Errorf("run %d: returned the stale cached record, want fresh analysis", i)
		}
	}
	if analyser.calls != 2 {
		t.Errorf("analyser invoked %d times across two runs, want 2 (never served from cache)", analyser.calls)
	}
}

// TestLocalExecute_AnalyserInfraError guards that infrastructure errors
// from the analyser surface as errors (not a silent empty record).
func TestLocalExecute_AnalyserInfraError(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{err: errors.New("analyser crashed")}
	uc := buildLocalUseCase(store, analyser)

	if _, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	}); err == nil {
		t.Fatalf("expected error from analyser infra failure, got nil")
	}
}
