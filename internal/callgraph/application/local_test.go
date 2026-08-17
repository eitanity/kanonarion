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

// TestLocalExecute_ReanalysesARecordThatNamesNoTree: a generation written before
// the scan digest existed states nothing about which tree it was handed, and
// absence cannot show that this run would be asking the same question. It is
// re-derived, which is what every run did before reuse existed.
func TestLocalExecute_ReanalysesARecordThatNamesNoTree(t *testing.T) {
	store := &fakeCallGraphStore{}
	// A record from a previous run, distinguishable by node count, naming no tree.
	stale := domain.CallGraphRecord{Coordinate: testCoord, PipelineVersion: testPipelineV, NodeCount: 99}
	if err := store.PutCallGraphRecord(context.Background(), stale); err != nil {
		t.Fatalf("seed: %v", err)
	}
	analyser := &fakeAnalyser{record: domain.CallGraphRecord{
		OverallStatus: domain.CallGraphStatusExtracted,
	}}
	uc := buildLocalUseCase(store, analyser)

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
			t.Errorf("run %d: returned the record that named no tree, want fresh analysis", i)
		}
	}
	if analyser.calls != 2 {
		t.Errorf("analyser invoked %d times across two runs, want 2", analyser.calls)
	}
}

// seededTree returns a store already holding one worktree generation of the tree
// at root, and the analyser that reports that tree.
func seededTree(t *testing.T, root, digest string, held domain.CallGraphRecord) (*fakeCallGraphStore, *fakeAnalyser) {
	t.Helper()
	held.Coordinate = testCoord
	held.PipelineVersion = testPipelineV
	held.AnalysisSource = domain.AnalysisSourceWorktree
	held.AnalysisRoot = root
	held.WorktreeScanDigest = digest
	store := &fakeCallGraphStore{}
	if err := store.PutCallGraphRecord(context.Background(), held); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store.puts = nil // the seed is the previous run, not a write under test
	analyser := &fakeAnalyser{
		record:   domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted, NodeCount: 7},
		identity: domain.WorktreeIdentity{Root: root, ScanDigest: digest},
	}
	return store, analyser
}

// TestLocalExecute_ReusesTheRecordOfAnUnchangedTree: the tree in front of the run
// is the tree the held record was taken of, so the analysis is not run again and
// nothing is appended. Re-deriving it would cost a full analysis and a second
// copy of an identical graph, per run, forever.
func TestLocalExecute_ReusesTheRecordOfAnUnchangedTree(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted, NodeCount: 42})
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.FromCache {
		t.Error("FromCache=false: an unchanged tree was analysed again")
	}
	if res.Record.NodeCount != 42 {
		t.Errorf("node count = %d, want the held record's 42", res.Record.NodeCount)
	}
	if analyser.calls != 0 {
		t.Errorf("analyser invoked %d times, want 0", analyser.calls)
	}
	if len(store.puts) != 0 {
		t.Errorf("%d record(s) appended on a reuse, want 0", len(store.puts))
	}
}

// TestLocalExecute_ReanalysesAChangedTree: the digest is the whole of the reuse
// key, so an edited tree is a different question and is measured again.
func TestLocalExecute_ReanalysesAChangedTree(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted, NodeCount: 42})
	analyser.identity.ScanDigest = "scanned-sha256:bbb"
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("FromCache=true: an edited tree was answered from the record of the tree before the edit")
	}
	if res.Record.WorktreeScanDigest != "scanned-sha256:bbb" {
		t.Errorf("stamped digest = %q, want the tree as it was when the run started",
			res.Record.WorktreeScanDigest)
	}
}

// TestLocalExecute_AnotherTreeDoesNotAnswer: two checkouts of one module path are
// two trees. Identical contents do not make one of them the other, and a run
// pointed at a directory asked about that directory.
func TestLocalExecute_AnotherTreeDoesNotAnswer(t *testing.T) {
	store, analyser := seededTree(t, "/other/checkout", "scanned-sha256:aaa",
		domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted, NodeCount: 42})
	analyser.identity.Root = "/work/tree"
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("FromCache=true: another checkout's record answered for this tree")
	}
}

// TestLocalExecute_ForceReanalysesAnUnchangedTree: what the tree's digest cannot
// see — a different toolchain, a repopulated module cache — is exactly what
// --force is for.
func TestLocalExecute_ForceReanalysesAnUnchangedTree(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusExtracted, NodeCount: 42})
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
		Force:      true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("FromCache=true under --force: the flag did not bypass reuse")
	}
	if analyser.calls != 1 {
		t.Errorf("analyser invoked %d times under --force, want 1", analyser.calls)
	}
}

// TestLocalExecute_DoesNotReuseAnEnvironmentFailure: a run that failed because
// the analysis environment failed measured nothing about the tree. Serving it
// back would make one bad run permanent, with only --force ever clearing it.
func TestLocalExecute_DoesNotReuseAnEnvironmentFailure(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{
			OverallStatus: domain.CallGraphStatusLoadFailed,
			Completeness:  domain.CompletenessFailed,
			FailureCause:  domain.FailureCauseEnvironment,
		})
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("FromCache=true: an environment failure was served back as this tree's graph")
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

// TestLocalExecute_DoesNotReuseAPartialLimitedByTheEnvironment is the defect this
// guards. A graph left incomplete because this host's module cache did not hold
// a dependency is not a statement about the tree, and the tree's own digest
// cannot see the difference: warming the cache leaves the source identical, so
// reuse keyed on the tree alone serves the incomplete graph back to the one run
// that would finally have measured the whole thing.
func TestLocalExecute_DoesNotReuseAPartialLimitedByTheEnvironment(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{
			OverallStatus:  domain.CallGraphStatusPartial,
			FailureCause:   domain.FailureCauseEnvironment,
			FailedPackages: []string{"example.com/mod/needsdep"},
			NodeCount:      42,
		})
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("FromCache=true: a graph cut short by a cold module cache was served back, " +
			"so warming the cache and re-running changes nothing")
	}
	if analyser.calls != 1 {
		t.Errorf("analyser invoked %d times, want 1", analyser.calls)
	}
}

// TestLocalExecute_DoesNotReuseAPartialThatStatesNoCause: the records written
// before the cause reached partial extractions say nothing about what limited
// them, and "we do not know" is not "the module is at fault". Each is
// re-attempted once; the re-attempt writes a record that does state its cause.
func TestLocalExecute_DoesNotReuseAPartialThatStatesNoCause(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{
			OverallStatus:  domain.CallGraphStatusPartial,
			FailedPackages: []string{"example.com/mod/needsdep"},
			NodeCount:      42,
		})
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.FromCache {
		t.Error("FromCache=true: an incompleteness of unestablished cause answered for this tree")
	}
}

// TestLocalExecute_ReusesAPartialTheModuleItselfCaused is the control that keeps
// the rule from degenerating into never caching a partial graph. A package that
// does not typecheck on its own terms is a stable finding, and an unchanged tree
// rediscovering it every run would pay a full analysis for an answer already
// held.
func TestLocalExecute_ReusesAPartialTheModuleItselfCaused(t *testing.T) {
	store, analyser := seededTree(t, "/work/tree", "scanned-sha256:aaa",
		domain.CallGraphRecord{
			OverallStatus:  domain.CallGraphStatusPartial,
			FailureCause:   domain.FailureCauseModule,
			FailedPackages: []string{"example.com/mod/broken"},
			NodeCount:      42,
		})
	uc := buildLocalUseCase(store, analyser)

	res, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        "/work/tree",
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.FromCache {
		t.Error("FromCache=false: a module's own compile error was re-analysed on an unchanged tree")
	}
	if analyser.calls != 0 {
		t.Errorf("analyser invoked %d times, want 0", analyser.calls)
	}
}
