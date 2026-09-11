package application

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// recordingExtractionStore keeps every write in order, so a test can see what a
// run put in the store BEFORE it finished rather than only what it left there.
type recordingExtractionStore struct {
	mu      sync.Mutex
	writes  []domain.ExtractionRun
	failAll error
}

func (r *recordingExtractionStore) PutExtractionRun(_ context.Context, run domain.ExtractionRun) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failAll != nil {
		return r.failAll
	}
	r.writes = append(r.writes, run)
	return nil
}

func (r *recordingExtractionStore) GetExtractionRun(context.Context, string) (domain.ExtractionRun, error) {
	return domain.ExtractionRun{}, ports.ErrExtractionRunNotFound
}

func (r *recordingExtractionStore) ListExtractionRuns(context.Context, ports.ExtractionRunFilter) ([]ports.ExtractionRunSummary, error) {
	return nil, nil
}

func (r *recordingExtractionStore) snapshot() []domain.ExtractionRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.ExtractionRun(nil), r.writes...)
}

// blockingExtractor releases one module at a time, so a test can hold a run
// half-finished and look at the store while it is there.
//
// entered is buffered to the walk's size: a module that has entered must never
// wait for the test to notice, or a run the test has finished with deadlocks
// behind an unread signal.
type blockingExtractor struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingExtractor) Extract(ctx context.Context, _ coordinate.ModuleCoordinate, stage string, _ bool, _ string) (ports.StageResult, error) {
	select {
	case b.entered <- struct{}{}:
	case <-ctx.Done():
		return ports.StageResult{}, ctx.Err() //nolint:wrapcheck // the test's own fake
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return ports.StageResult{}, ctx.Err() //nolint:wrapcheck // the test's own fake
	}
	return ports.StageResult{Status: domain.StageSucceeded, RecordID: "rec-" + stage}, nil
}

func walkOf(t *testing.T, n int) (walkdomain.WalkRecord, []coordinate.ModuleCoordinate) {
	t.Helper()
	var nodes []walkdomain.GraphNode
	var coords []coordinate.ModuleCoordinate
	for i := range n {
		c, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0."+string(rune('0'+i)))
		if err != nil {
			t.Fatalf("building the coordinate: %v", err)
		}
		coords = append(coords, c)
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: c})
	}
	return walkdomain.WalkRecord{Target: coords[0], Graph: walkdomain.Graph{Nodes: nodes}}, coords
}

func checkpointUseCase(runs ports.ExtractionStore, walks *mockWalkStore, ex ports.Extractor, every time.Duration) *ExtractUseCase {
	return NewExtractUseCase(Config{
		Runs:      runs,
		Walks:     walks,
		Extractor: ex,
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
		Workers:   1,
	}).WithCheckpointInterval(every)
}

// TestExtract_LeavesARunBeforeItReachesTheFirstModule is the property a killed
// run depends on: the record exists in the store before there is anything to put
// in it, so a process ended at any later point has already been accounted for.
func TestExtract_LeavesARunBeforeItReachesTheFirstModule(t *testing.T) {
	walk, _ := walkOf(t, 3)
	runs := &recordingExtractionStore{}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{"walk-1": walk}}
	ex := &blockingExtractor{entered: make(chan struct{}, 3), release: make(chan struct{})}

	uc := checkpointUseCase(runs, walks, ex, -1) // no ticker: the opening write is what is under test

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = uc.Execute(t.Context(), ExtractRequest{WalkID: "walk-1", Stages: []string{"license"}})
	}()

	<-ex.entered // the first module is inside the extractor, so nothing has completed

	writes := runs.snapshot()
	if len(writes) == 0 {
		t.Fatal("the store held no run while one was in progress; a process ended here would leave nothing")
	}
	first := writes[0]
	if first.OverallStatus != domain.ExtractionRunInProgress {
		t.Errorf("the opening record says %v, want in_progress", first.OverallStatus)
	}
	if !first.CompletedAt.IsZero() {
		t.Errorf("CompletedAt = %v on a run that has not completed, want the zero time", first.CompletedAt)
	}
	if len(first.PerModuleResults) != 0 {
		t.Errorf("the opening record claims %d module results before any module finished", len(first.PerModuleResults))
	}
	if first.WalkID != "walk-1" || first.ID == "" {
		t.Errorf("the opening record does not name its run and walk: id=%q walk=%q", first.ID, first.WalkID)
	}

	close(ex.release)
	<-done
}

// A run's checkpoint names the modules it has actually completed, so what a
// killed run left behind is readable rather than merely present.
func TestExtract_CheckpointNamesWhatItHasCompleted(t *testing.T) {
	walk, coords := walkOf(t, 3)
	runs := &recordingExtractionStore{}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{"walk-1": walk}}
	ex := &blockingExtractor{entered: make(chan struct{}, 3), release: make(chan struct{}, 3)}

	uc := checkpointUseCase(runs, walks, ex, 5*time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = uc.Execute(t.Context(), ExtractRequest{WalkID: "walk-1", Stages: []string{"license"}})
	}()

	// Let exactly one module through, then hold the second inside the extractor.
	<-ex.entered
	ex.release <- struct{}{}
	<-ex.entered

	var withOne domain.ExtractionRun
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, w := range runs.snapshot() {
			if w.OverallStatus == domain.ExtractionRunInProgress && len(w.PerModuleResults) == 1 {
				withOne = w
			}
		}
		if withOne.ID != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if withOne.ID == "" {
		t.Fatal("no checkpoint ever named the one module that had completed")
	}
	if _, ok := withOne.PerModuleResults[coords[0]]; !ok {
		t.Errorf("the checkpoint names %v, not the module that completed", withOne.PerModuleResults)
	}
	// Every checkpoint is a sealed record, or the store would refuse it.
	var h domain.ExtractionRunHasher
	if err := h.VerifyContentHash(withOne); err != nil {
		t.Errorf("the checkpoint is not sealed: %v", err)
	}

	close(ex.release)
	<-done
}

// The control: a run that finishes normally must end saying what it came to,
// not in_progress. A checkpoint that outlived the seal would report every
// successful run as unfinished.
func TestExtract_AFinishedRunOverwritesItsCheckpoint(t *testing.T) {
	walk, _ := walkOf(t, 2)
	runs := &recordingExtractionStore{}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{"walk-1": walk}}

	uc := checkpointUseCase(runs, walks, &mockExtractor{}, 5*time.Millisecond)
	run, err := uc.Execute(t.Context(), ExtractRequest{WalkID: "walk-1", Stages: []string{"license"}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if run.OverallStatus != domain.ExtractionRunSucceeded {
		t.Fatalf("returned status = %v, want succeeded", run.OverallStatus)
	}

	writes := runs.snapshot()
	last := writes[len(writes)-1]
	if last.OverallStatus == domain.ExtractionRunInProgress {
		t.Error("the last write to the store says in_progress on a run that finished")
	}
	if last.CompletedAt.IsZero() {
		t.Error("the sealed run has no CompletedAt")
	}
	if last.ID != run.ID {
		t.Errorf("the last write is run %s, not the run Execute returned (%s)", last.ID, run.ID)
	}
	// Every write is the same run: checkpointing must not scatter a run across
	// several ids, which would make `extract list` count one run many times.
	for _, w := range writes {
		if w.ID != run.ID {
			t.Fatalf("a checkpoint was written under id %s, want %s", w.ID, run.ID)
		}
	}
}

// A store that will not take a checkpoint is a reason to say so, not a reason to
// throw the extraction away.
func TestExtract_ACheckpointThatCannotBeWrittenDoesNotFailTheRun(t *testing.T) {
	walk, _ := walkOf(t, 2)
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{"walk-1": walk}}
	runs := &recordingExtractionStore{failAll: errors.New("database is locked")}

	uc := checkpointUseCase(runs, walks, &mockExtractor{}, -1)
	_, err := uc.Execute(t.Context(), ExtractRequest{WalkID: "walk-1", Stages: []string{"license"}})
	// The final seal still fails — that is the run's own record and always has
	// been — but the checkpoint must not be what fails it.
	if err == nil || !strings.Contains(err.Error(), "persisting run") {
		t.Fatalf("Execute error = %v, want the FINAL persist to be what failed", err)
	}
}
