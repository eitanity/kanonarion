package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// fakeStopwatch is a deterministic ports.Stopwatch: every lap reports d.
type fakeStopwatch struct{ d time.Duration }

func (s fakeStopwatch) Start() fetchports.Lap { return fakeLap(s) }

type fakeLap struct{ d time.Duration }

func (l fakeLap) Elapsed() time.Duration { return l.d }

// fakeClock is a deterministic ports.Clock returning a fixed instant.
type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

var testClockTime = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

var testStages = []string{"license", "interface", "callgraph", "example"}

type mockStageRegistry struct{}

func (mockStageRegistry) Stages() []string { return testStages }
func (mockStageRegistry) Has(name string) bool {
	for _, s := range testStages {
		if s == name {
			return true
		}
	}
	return false
}

type mockExtractionStore struct {
	runs map[string]domain.ExtractionRun
}

func (m *mockExtractionStore) PutExtractionRun(ctx context.Context, run domain.ExtractionRun) error {
	if run.WalkID == "fail-me" {
		return errors.New("persistence error")
	}
	m.runs[run.ID] = run
	return nil
}

func (m *mockExtractionStore) GetExtractionRun(ctx context.Context, id string) (domain.ExtractionRun, error) {
	run, ok := m.runs[id]
	if !ok {
		return domain.ExtractionRun{}, ports.ErrExtractionRunNotFound
	}
	return run, nil
}

func (m *mockExtractionStore) ListExtractionRuns(ctx context.Context, filter ports.ExtractionRunFilter) ([]ports.ExtractionRunSummary, error) {
	return nil, nil
}

type mockWalkStore struct {
	walks map[string]walkdomain.WalkRecord
}

func (m *mockWalkStore) GetWalk(ctx context.Context, id string) (walkdomain.WalkRecord, error) {
	walk, ok := m.walks[id]
	if !ok {
		return walkdomain.WalkRecord{}, walkports.ErrWalkNotFound
	}
	return walk, nil
}

func (m *mockWalkStore) PutWalk(ctx context.Context, walk walkdomain.WalkRecord) error {
	return nil
}

func (m *mockWalkStore) ListWalks(ctx context.Context, filter walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return nil, nil
}

type mockExtractor struct {
	calls     []extractorCall
	onExtract func()
}

type extractorCall struct {
	coord coordinate.ModuleCoordinate
	stage string
}

func (m *mockExtractor) Extract(ctx context.Context, coord coordinate.ModuleCoordinate, stage string, force bool) (ports.StageResult, error) {
	if m.onExtract != nil {
		m.onExtract()
	}
	m.calls = append(m.calls, extractorCall{coord, stage})
	if stage == "license" && force {
		return ports.StageResult{Status: domain.StageFailed, Error: "forced failure"}, nil
	}
	if stage == "interface" && coord.Version == "v2.0.0" {
		return ports.StageResult{}, errors.New("unexpected error")
	}
	return ports.StageResult{
		Status:   domain.StageSucceeded,
		RecordID: "rec-" + stage,
	}, nil
}

func TestExtractUseCase_Execute(t *testing.T) {
	ctx := t.Context()
	coord1, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	walkID := "walk-123"

	walk := walkdomain.WalkRecord{
		Target: coord1,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: coord1},
			},
		},
	}

	runs := &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{walkID: walk}}
	extractor := &mockExtractor{}

	uc := NewExtractUseCase(Config{
		Runs:      runs,
		Walks:     walks,
		Extractor: extractor,
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
		PipelineVersions: map[string]string{
			"license": "v1",
		},
	})

	t.Run("Success all stages", func(t *testing.T) {
		req := ExtractRequest{
			WalkID: walkID,
			Stages: []string{"license", "interface"},
		}

		run, err := uc.Execute(ctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		if run.OverallStatus != domain.ExtractionRunSucceeded {
			t.Errorf("OverallStatus = %v, want %v", run.OverallStatus, domain.ExtractionRunSucceeded)
		}

		if len(extractor.calls) != 2 {
			t.Errorf("Extractor called %d times, want 2", len(extractor.calls))
		}

		// Verify stages are in result
		res, ok := run.PerModuleResults[coord1]
		if !ok {
			t.Fatal("Result for coord1 missing")
		}
		if res.Stages["license"].Status != domain.StageSucceeded {
			t.Errorf("license status = %v, want succeeded", res.Stages["license"].Status)
		}
		if res.Stages["interface"].Status != domain.StageSucceeded {
			t.Errorf("interface status = %v, want succeeded", res.Stages["interface"].Status)
		}
	})

	t.Run("Deterministic timestamps via injected clock", func(t *testing.T) {
		req := ExtractRequest{
			WalkID: walkID,
			Stages: []string{"license"},
		}

		run, err := uc.Execute(ctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		if !run.StartedAt.Equal(testClockTime) {
			t.Errorf("StartedAt = %v, want %v", run.StartedAt, testClockTime)
		}
		if !run.CompletedAt.Equal(testClockTime) {
			t.Errorf("CompletedAt = %v, want %v", run.CompletedAt, testClockTime)
		}
	})

	t.Run("Stage ordering", func(t *testing.T) {
		extractor.calls = nil
		req := ExtractRequest{
			WalkID: walkID,
			// Intentionally out of order
			Stages: []string{"example", "license", "callgraph", "interface"},
		}

		_, err := uc.Execute(ctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		// Expected order: license, interface, callgraph, example
		expectedOrder := []string{"license", "interface", "callgraph", "example"}
		if len(extractor.calls) != 4 {
			t.Fatalf("Extractor called %d times, want 4", len(extractor.calls))
		}
		for i, call := range extractor.calls {
			if call.stage != expectedOrder[i] {
				t.Errorf("Call %d stage = %s, want %s", i, call.stage, expectedOrder[i])
			}
		}
	})

	t.Run("Partial failure", func(t *testing.T) {
		extractor.calls = nil
		req := ExtractRequest{
			WalkID: walkID,
			Stages: []string{"license"},
			Force:  true,
		}

		run, err := uc.Execute(ctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		if run.OverallStatus != domain.ExtractionRunPartial {
			t.Errorf("OverallStatus = %v, want %v", run.OverallStatus, domain.ExtractionRunPartial)
		}

		res := run.PerModuleResults[coord1]
		if res.Stages["license"].Status != domain.StageFailed {
			t.Errorf("license stage status = %v, want failed", res.Stages["license"].Status)
		}
	})

	t.Run("Walk not found", func(t *testing.T) {
		req := ExtractRequest{WalkID: "non-existent", Stages: []string{"license"}}
		_, err := uc.Execute(ctx, req)
		if !errors.Is(err, walkports.ErrWalkNotFound) {
			t.Errorf("err = %v, want ErrWalkNotFound", err)
		}
	})

	t.Run("Invalid stage", func(t *testing.T) {
		req := ExtractRequest{WalkID: walkID, Stages: []string{"invalid"}}
		_, err := uc.Execute(ctx, req)
		if err == nil {
			t.Fatal("expected error for invalid stage")
		}
	})

	t.Run("Empty walk", func(t *testing.T) {
		emptyWalkID := "empty-walk"
		walks.walks[emptyWalkID] = walkdomain.WalkRecord{
			Target: coord1,
			Graph:  walkdomain.Graph{Nodes: nil},
		}
		req := ExtractRequest{WalkID: emptyWalkID, Stages: []string{"license"}}
		_, err := uc.Execute(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty walk")
		}
	})

	t.Run("Persistence error", func(t *testing.T) {
		req := ExtractRequest{WalkID: "fail-me", Stages: []string{"license"}}
		_, err := uc.Execute(ctx, req)
		if err == nil {
			t.Fatal("expected error for persistence failure")
		}
	})

	t.Run("Context cancelled", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		req := ExtractRequest{WalkID: walkID, Stages: []string{"license"}}
		run, err := uc.Execute(cctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}
		if run.OverallStatus != domain.ExtractionRunCancelled {
			t.Errorf("OverallStatus = %v, want %v", run.OverallStatus, domain.ExtractionRunCancelled)
		}
	})

	t.Run("Empty stages", func(t *testing.T) {
		req := ExtractRequest{WalkID: walkID, Stages: []string{}}
		_, err := uc.Execute(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty stages")
		}
	})

	t.Run("Unexpected error", func(t *testing.T) {
		coord2, _ := coordinate.NewModuleCoordinate("github.com/foo/baz", "v2.0.0")
		walks.walks["unexpected-walk"] = walkdomain.WalkRecord{
			Target: coord2,
			Graph: walkdomain.Graph{
				Nodes: []walkdomain.GraphNode{{Coordinate: coord2}},
			},
		}
		req := ExtractRequest{WalkID: "unexpected-walk", Stages: []string{"interface"}}
		run, err := uc.Execute(ctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}
		res := run.PerModuleResults[coord2]
		if res.Stages["interface"].Status != domain.StageFailed {
			t.Errorf("status = %v, want failed", res.Stages["interface"].Status)
		}
		if res.Stages["interface"].Error != "unexpected error" {
			t.Errorf("error = %q, want 'unexpected error'", res.Stages["interface"].Error)
		}
	})

	t.Run("Context cancelled during stages", func(t *testing.T) {
		extractor.calls = nil
		cctx, cancel := context.WithCancel(ctx)
		extractor.onExtract = func() {
			cancel()
		}
		defer func() { extractor.onExtract = nil }()

		req := ExtractRequest{WalkID: walkID, Stages: []string{"license", "interface"}}
		run, err := uc.Execute(cctx, req)
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}
		if run.OverallStatus != domain.ExtractionRunCancelled {
			t.Errorf("OverallStatus = %v, want %v", run.OverallStatus, domain.ExtractionRunCancelled)
		}
		// Should only have one call because it was cancelled after/during the first one
		if len(extractor.calls) > 1 {
			// Note: depending on where the cancel is checked, it might be 1.
			// In our implementation, we check BEFORE the stage call.
			// So if we cancel DURING/AFTER the first call, it should stop before the second.
			t.Errorf("expected at most 1 call, got %d", len(extractor.calls))
		}
	})
}

// nodes that arrived in the graph via a local-path replace have no
// fetchable artefact; the extract use case must emit StageSkipped for every
// requested stage rather than calling the extractor (which would fail with
// ErrModuleNotFetched).
func TestExtractUseCase_localReplaceNodesSkipped(t *testing.T) {
	ctx := t.Context()
	target, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	localDep, _ := coordinate.NewModuleCoordinate("example.com/dep", "v1.0.0")
	walkID := "walk-localreplace"

	walk := walkdomain.WalkRecord{
		Target: target,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: target},
				{
					Coordinate:       localDep,
					ResolutionSource: walkdomain.ResolutionLocalReplace,
					LocalPath:        "../local/dep",
				},
			},
		},
	}

	runs := &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{walkID: walk}}
	extractor := &mockExtractor{}

	uc := NewExtractUseCase(Config{
		Runs:      runs,
		Walks:     walks,
		Extractor: extractor,
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
	})

	run, err := uc.Execute(ctx, ExtractRequest{
		WalkID: walkID,
		Stages: []string{"license", "interface"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Extractor must never be called for the local-replace node.
	for _, c := range extractor.calls {
		if c.coord == localDep {
			t.Errorf("extractor called for local-replace node %s stage %s; should be skipped", c.coord, c.stage)
		}
	}

	depResult, ok := run.PerModuleResults[localDep]
	if !ok {
		t.Fatalf("no PerModuleResults entry for local-replace node %s", localDep)
	}
	for _, stage := range []string{"license", "interface"} {
		sr := depResult.Stages[stage]
		if sr.Status != domain.StageSkipped {
			t.Errorf("stage %s status = %v, want skipped", stage, sr.Status)
		}
		if sr.Error == "" {
			t.Errorf("stage %s error should explain the skip (local replace at <path>)", stage)
		}
	}
	if run.OverallStatus != domain.ExtractionRunSucceeded {
		t.Errorf("OverallStatus = %v, want succeeded (skips are not failures)", run.OverallStatus)
	}
}

// The project-walk root (the local main module) is the working tree itself and
// is never proxy-fetched, so it has no module artefact. The extract use case
// must skip it with a reason — like a non-analysed local replace — rather than
// attempting a fetch-record lookup that can only miss and mislabelling the run
// partial.
func TestExtractUseCase_localMainModuleRootSkippedNotFailed(t *testing.T) {
	ctx := t.Context()
	root := coordinate.ModuleCoordinate{Path: "example.com/project", Version: coordinate.LocalVersion}
	dep, _ := coordinate.NewModuleCoordinate("github.com/foo/bar", "v1.0.0")
	walkID := "walk-localroot"

	walk := walkdomain.WalkRecord{
		Target: root,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
				{Coordinate: dep, ResolutionSource: walkdomain.ResolutionMVS},
			},
		},
	}

	runs := &mockExtractionStore{runs: make(map[string]domain.ExtractionRun)}
	walks := &mockWalkStore{walks: map[string]walkdomain.WalkRecord{walkID: walk}}
	extractor := &mockExtractor{}

	uc := NewExtractUseCase(Config{
		Runs:      runs,
		Walks:     walks,
		Extractor: extractor,
		Stages:    mockStageRegistry{},
		Clock:     fakeClock{t: testClockTime},
		Stopwatch: fakeStopwatch{},
	})

	run, err := uc.Execute(ctx, ExtractRequest{
		WalkID: walkID,
		Stages: []string{"license", "interface"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// The extractor must never be called for the un-fetchable root.
	for _, c := range extractor.calls {
		if c.coord == root {
			t.Errorf("extractor called for local main-module root %s stage %s; should be skipped", c.coord, c.stage)
		}
	}

	rootResult, ok := run.PerModuleResults[root]
	if !ok {
		t.Fatalf("no PerModuleResults entry for local main-module root %s", root)
	}
	for _, stage := range []string{"license", "interface"} {
		sr := rootResult.Stages[stage]
		if sr.Status != domain.StageSkipped {
			t.Errorf("root stage %s status = %v, want skipped", stage, sr.Status)
		}
		if sr.Error == "" {
			t.Errorf("root stage %s error should explain the skip", stage)
		}
	}

	// The real dependency still extracts normally.
	if depResult, ok := run.PerModuleResults[dep]; !ok {
		t.Errorf("no PerModuleResults entry for dependency %s", dep)
	} else if depResult.Stages["license"].Status != domain.StageSucceeded {
		t.Errorf("dependency license stage = %v, want succeeded", depResult.Stages["license"].Status)
	}

	if run.OverallStatus != domain.ExtractionRunSucceeded {
		t.Errorf("OverallStatus = %v, want succeeded (an un-fetchable root is a skip, not a failure)", run.OverallStatus)
	}
}
