package application_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/gotoolchain"
)

// openLedger opens a real call graph ledger. These tests need one: a conflict is
// raised by composing the generations a store holds, and the fake keeps one
// record per coordinate, so it can never produce the state under test.
func openLedger(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := s.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})
	return s
}

// testArtefact is the artefact identity the fetch record storeFetchRecord files
// carries, so a generation written by hand names the same bytes the extraction
// under test will name.
func testArtefact(t *testing.T) string {
	t.Helper()
	id, err := fetchdomain.ArtefactIdentityOf(fetchtest.Record(
		t,
		fetchtest.Coordinate(testCoord),
		fetchtest.PipelineVersion(testFetchPipV),
		fetchtest.Content("blob:test"),
	))
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}
	return id.String()
}

// generation builds one stored analysis of testCoord. callee varies the graph;
// toolchain, when recorded, is what the record says built it.
func generation(t *testing.T, callee string, toolchain gotoolchain.Version, stdlibNode bool) domain2.CallGraphRecord {
	t.Helper()
	r := domain2.CallGraphRecord{
		SchemaVersion:    domain2.CallGraphSchemaVersion,
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       testCoord,
		Algorithm:        domain2.AlgorithmCHA,
		AnalysisSource:   domain2.AnalysisSourceModuleZip,
		Completeness:     domain2.CompletenessBuiltWithBodies,
		OverallStatus:    domain2.CallGraphStatusExtracted,
		Toolchain:        toolchain,
		ArtefactIdentity: testArtefact(t),
		PipelineVersion:  testPipelineV,
		ExtractedAt:      testTime,
		Nodes: []domain2.CallNode{
			{ID: "example.com/mod.Foo", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Foo"},
		},
		Edges: []domain2.CallEdge{
			{
				FromID:     "example.com/mod.Foo",
				ToID:       callee,
				CallSite:   domain2.SourcePosition{File: "foo.go", Line: 10},
				Confidence: domain2.ConfidenceDirect,
			},
		},
	}
	if stdlibNode {
		// A stdlib node under a plain GOROOT is what a record that names no
		// toolchain still says about where its stdlib was read: evidence of a
		// location, never of a version.
		r.Nodes = append(r.Nodes, domain2.CallNode{
			ID:       "fmt.Println",
			Package:  "fmt",
			Symbol:   "Println",
			Position: domain2.SourcePosition{File: "/usr/local/go/src/fmt/print.go", Line: 305},
		})
	}
	r.NodeCount = len(r.Nodes)
	r.EdgeCount = len(r.Edges)
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// disagreeingLedger files two generations of one coordinate that describe
// different graphs and read their stdlib from different trees: one names its
// toolchain, the other only its GOROOT. Composition refuses to pick between
// them.
func disagreeingLedger(t *testing.T, s *sqlite.Store) (named, unnamed domain2.CallGraphRecord) {
	t.Helper()
	named = generation(t, "example.com/mod.Bar", gotoolchain.Version("go1.26.6"), false)
	unnamed = generation(t, "fmt.Println", gotoolchain.Unrecorded, true)
	for _, r := range []domain2.CallGraphRecord{named, unnamed} {
		if err := s.PutCallGraphRecord(context.Background(), r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	if _, _, err := s.GetCallGraphRecord(context.Background(), testCoord, testPipelineV); !errors.Is(err, ports.ErrCallGraphConflict) {
		t.Fatalf("the ledger is not in the state under test: GetCallGraphRecord err = %v, want ErrCallGraphConflict", err)
	}
	return named, unnamed
}

func extractUseCase(t *testing.T, s *sqlite.Store, analyser *fakeAnalyser) *application.ExtractCallGraphUseCase {
	t.Helper()
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	storeFetchRecord(t, facts, blobs, testCoord)
	return application.NewExtractCallGraphUseCase(application.Config{
		Facts:           facts,
		Blobs:           blobs,
		Store:           s,
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          slog.Default(),
	})
}

// measuringAnalyser produces a graph unlike either stored generation, so the
// generation it appends is distinguishable from both.
func measuringAnalyser() *fakeAnalyser {
	return &fakeAnalyser{record: domain2.CallGraphRecord{
		SchemaVersion:  domain2.CallGraphSchemaVersion,
		Ecosystem:      fetchdomain.EcosystemGo,
		Algorithm:      domain2.AlgorithmCHA,
		AnalysisSource: domain2.AnalysisSourceModuleZip,
		Completeness:   domain2.CompletenessBuiltWithBodies,
		OverallStatus:  domain2.CallGraphStatusExtracted,
		Toolchain:      gotoolchain.Version("go1.27.0"),
		Nodes: []domain2.CallNode{
			{ID: "example.com/mod.Foo", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Foo"},
			{ID: "example.com/mod.Baz", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Baz"},
		},
		Edges: []domain2.CallEdge{
			{
				FromID:     "example.com/mod.Foo",
				ToID:       "example.com/mod.Baz",
				CallSite:   domain2.SourcePosition{File: "foo.go", Line: 11},
				Confidence: domain2.ConfidenceDirect,
			},
		},
	}}
}

// TestExecute_AConflictingLedgerIsACacheMissNotAFailure.
//
// Two stored generations that disagree mean no single one answers the
// coordinate. For a path about to MEASURE one, that is a cache miss: extraction
// runs, appends, and leaves both prior generations where they are.
func TestExecute_AConflictingLedgerIsACacheMissNotAFailure(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	named, unnamed := disagreeingLedger(t, s)

	analyser := measuringAnalyser()
	uc := extractUseCase(t, s, analyser)

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("a composition refusal was reported as an extraction failure: %v", err)
	}
	if result.FromCache {
		t.Error("extraction served a cached answer from a ledger that holds no single answer")
	}
	if analyser.calls != 1 {
		t.Fatalf("the analyser ran %d times, want 1: the run must measure", analyser.calls)
	}

	held, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipelineV)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(held) != 3 {
		t.Fatalf("the ledger holds %d generations, want 3: extraction appends", len(held))
	}
	byHash := make(map[string]bool, len(held))
	for _, r := range held {
		byHash[r.ContentHash] = true
	}
	for _, want := range []domain2.CallGraphRecord{named, unnamed} {
		if !byHash[want.ContentHash] {
			t.Errorf("generation %s is no longer readable; extraction must not overwrite or delete", want.ContentHash)
		}
	}
	if !byHash[result.Record.ContentHash] {
		t.Errorf("the measured generation %s was not appended", result.Record.ContentHash)
	}
}

// TestGetCallGraphRecord_StillRefusesAConflictAfterExtraction is the read-path
// control. Measuring a new generation is allowed; SERVING an ambiguous answer is
// not, and appending does not make the disagreement go away.
func TestGetCallGraphRecord_StillRefusesAConflictAfterExtraction(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	disagreeingLedger(t, s)

	uc := extractUseCase(t, s, measuringAnalyser())
	if _, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	_, _, err := s.GetCallGraphRecord(ctx, testCoord, testPipelineV)
	if !errors.Is(err, ports.ErrCallGraphConflict) {
		t.Fatalf("the read path returned %v, want ErrCallGraphConflict", err)
	}
	for _, want := range []string{"conflicting call graph records", "toolchain disagrees"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal no longer says %q: %s", want, err)
		}
	}
}

// TestExecute_OneCacheableGenerationIsStillACacheHit is the control that matters
// most: the fix must turn a REFUSAL into a miss, and nothing else into one. A
// coordinate with a single cacheable generation is still served without
// measuring.
func TestExecute_OneCacheableGenerationIsStillACacheHit(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	only := generation(t, "example.com/mod.Bar", gotoolchain.Version("go1.26.6"), false)
	if err := s.PutCallGraphRecord(ctx, only); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	analyser := measuringAnalyser()
	uc := extractUseCase(t, s, analyser)

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Fatal("a coordinate with one cacheable generation re-measured; every run would re-extract everything")
	}
	if analyser.calls != 0 {
		t.Errorf("the analyser ran %d times on a cache hit, want 0", analyser.calls)
	}
	if result.Record.ContentHash != only.ContentHash {
		t.Errorf("served %s, want the held generation %s", result.Record.ContentHash, only.ContentHash)
	}
	held, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipelineV)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(held) != 1 {
		t.Errorf("the ledger holds %d generations, want 1: a cache hit writes nothing", len(held))
	}
}

// TestExecute_ForceStillSkipsTheLedgerEntirely is the --force control. Force
// means measure without consulting the ledger, and this change does not widen it:
// a cacheable generation is still bypassed, and a conflicting ledger is still
// measured past.
func TestExecute_ForceStillSkipsTheLedgerEntirely(t *testing.T) {
	t.Run("one cacheable generation", func(t *testing.T) {
		ctx := context.Background()
		s := openLedger(t)
		only := generation(t, "example.com/mod.Bar", gotoolchain.Version("go1.26.6"), false)
		if err := s.PutCallGraphRecord(ctx, only); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
		analyser := measuringAnalyser()
		uc := extractUseCase(t, s, analyser)

		result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord, Force: true})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if result.FromCache {
			t.Error("Force served a cached answer")
		}
		if analyser.calls != 1 {
			t.Errorf("the analyser ran %d times under Force, want 1", analyser.calls)
		}
		held, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipelineV)
		if err != nil {
			t.Fatalf("ListCallGraphRecordsFor: %v", err)
		}
		if len(held) != 2 {
			t.Errorf("the ledger holds %d generations, want 2", len(held))
		}
	})

	t.Run("a conflicting ledger", func(t *testing.T) {
		ctx := context.Background()
		s := openLedger(t)
		disagreeingLedger(t, s)
		analyser := measuringAnalyser()
		uc := extractUseCase(t, s, analyser)

		result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord, Force: true})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if result.FromCache {
			t.Error("Force served a cached answer")
		}
		if analyser.calls != 1 {
			t.Errorf("the analyser ran %d times under Force, want 1", analyser.calls)
		}
	})
}

// TestLocalExecute_AnUnreadableHeldGenerationIsMeasuredNotRefused pins the
// working-tree route's half of the same rule. It already tolerated both
// refusals; what it did not do was say so, and a run that silently re-measures
// hides the ledger state that caused it.
func TestLocalExecute_AnUnreadableHeldGenerationIsMeasuredNotRefused(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"a conflict", fmt.Errorf("%w: two generations", ports.ErrCallGraphConflict)},
		{"a failed integrity check", fmt.Errorf("%w: hash mismatch", ports.ErrCallGraphIntegrity)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			store := &fakeCallGraphStore{getErr: tc.err}
			analyser := &fakeAnalyser{record: domain2.CallGraphRecord{
				SchemaVersion:  domain2.CallGraphSchemaVersion,
				Ecosystem:      fetchdomain.EcosystemGo,
				Algorithm:      domain2.AlgorithmCHA,
				AnalysisSource: domain2.AnalysisSourceWorktree,
				OverallStatus:  domain2.CallGraphStatusExtracted,
			}}
			uc := application.NewExtractLocalCallGraphUseCase(application.LocalConfig{
				Store:           store,
				Analyser:        analyser,
				Clock:           fakeClock{t: testTime},
				Stopwatch:       fakeStopwatch{},
				PipelineVersion: testPipelineV,
				Logger:          slog.New(slog.NewTextHandler(&buf, nil)),
			})

			result, rerr := uc.Execute(context.Background(), application.LocalExtractRequest{
				Dir:        t.TempDir(),
				Coordinate: local,
			})
			if rerr != nil {
				t.Fatalf("an unreadable held generation refused the measurement: %v", rerr)
			}
			if result.FromCache {
				t.Error("a generation the ledger could not read was served")
			}
			if analyser.calls != 1 {
				t.Errorf("the analyser ran %d times, want 1", analyser.calls)
			}
			if !strings.Contains(buf.String(), "callgraph_local_cache_unreadable_remeasuring") {
				t.Error("the run re-measured without saying why")
			}
		})
	}
}

// namedToolchain builds a use case that knows which Go this run analyses under.
func toolchainUseCase(t *testing.T, s *sqlite.Store, analyser *fakeAnalyser, name string) *application.ExtractCallGraphUseCase {
	t.Helper()
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	storeFetchRecord(t, facts, blobs, testCoord)
	return application.NewExtractCallGraphUseCase(application.Config{
		Facts:           facts,
		Blobs:           blobs,
		Store:           s,
		Analyser:        analyser,
		Clock:           fakeClock{t: testTime},
		Stopwatch:       fakeStopwatch{},
		PipelineVersion: testPipelineV,
		Logger:          slog.Default(),
		Toolchain: func(context.Context) gotoolchain.Version {
			return gotoolchain.Version(name)
		},
	})
}

// TestExecute_AGenerationBuiltByThisRunsToolchainIsACacheHit is the whole point.
//
// A coordinate holding an old generation that names no toolchain and one
// measured under the Go this run analyses under has an answer to the question
// the cache lookup is actually asking. Re-measuring it appends a graph identical
// to one already held, every run, for ever.
func TestExecute_AGenerationBuiltByThisRunsToolchainIsACacheHit(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	named, _ := disagreeingLedger(t, s)

	analyser := measuringAnalyser()
	uc := toolchainUseCase(t, s, analyser, "go1.26.6")

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Fatal("the run re-measured a coordinate it already holds a generation of, built by the Go it is running")
	}
	if analyser.calls != 0 {
		t.Errorf("the analyser ran %d times, want 0", analyser.calls)
	}
	if result.Record.ContentHash != named.ContentHash {
		t.Errorf("served %s, want the generation built by this toolchain %s", result.Record.ContentHash, named.ContentHash)
	}
	held, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipelineV)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(held) != 2 {
		t.Errorf("the ledger holds %d generations, want 2: a cache hit appends nothing", len(held))
	}
}

// TestExecute_NoGenerationUnderThisToolchainStillMeasures is the control. The
// resolution answers a disagreement; where it has no answer, the refusal stands
// and the run measures, exactly as it did before.
func TestExecute_NoGenerationUnderThisToolchainStillMeasures(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	disagreeingLedger(t, s)

	analyser := measuringAnalyser()
	uc := toolchainUseCase(t, s, analyser, "go1.99.0")

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("a coordinate holding nothing built by this toolchain was served from cache")
	}
	if analyser.calls != 1 {
		t.Errorf("the analyser ran %d times, want 1", analyser.calls)
	}
	held, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipelineV)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(held) != 3 {
		t.Errorf("the ledger holds %d generations, want 3: the measurement is appended", len(held))
	}
}

// TestExecute_OneUnnamedGenerationIsStillACacheHit is the regression this field
// choice exists to avoid, and the reason the lookup PREFERS a toolchain rather
// than restricting to one.
//
// Almost every generation in a ledger predates the toolchain field or was built
// by a Go since upgraded. Restricting the read would answer "no record" for all
// of them and re-analyse an entire build on every run. Preferring one is
// consulted only where the generations already disagree, so a coordinate that
// composes cleanly is served exactly as it was.
func TestExecute_OneUnnamedGenerationIsStillACacheHit(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	only := generation(t, "fmt.Println", gotoolchain.Unrecorded, true)
	if err := s.PutCallGraphRecord(ctx, only); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	analyser := measuringAnalyser()
	uc := toolchainUseCase(t, s, analyser, "go1.26.6")

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Fatal("a clean coordinate whose generation names no toolchain re-measured; every run would re-extract everything")
	}
	if analyser.calls != 0 {
		t.Errorf("the analyser ran %d times, want 0", analyser.calls)
	}
	held, err := s.ListCallGraphRecordsFor(ctx, testCoord, testPipelineV)
	if err != nil {
		t.Fatalf("ListCallGraphRecordsFor: %v", err)
	}
	if len(held) != 1 {
		t.Errorf("the ledger holds %d generations, want 1", len(held))
	}
}

// TestExecute_ADisagreementWithinOneToolchainStillMeasures pins the inner half
// of the resolution: a preference resolves the toolchain and nothing else, so
// two generations of ONE toolchain that describe different graphs still refuse,
// and the run measures.
func TestExecute_ADisagreementWithinOneToolchainStillMeasures(t *testing.T) {
	ctx := context.Background()
	s := openLedger(t)
	for _, r := range []domain2.CallGraphRecord{
		generation(t, "example.com/mod.Bar", gotoolchain.Version("go1.26.6"), false),
		generation(t, "example.com/mod.Other", gotoolchain.Version("go1.26.6"), false),
	} {
		if err := s.PutCallGraphRecord(ctx, r); err != nil {
			t.Fatalf("PutCallGraphRecord: %v", err)
		}
	}
	if _, _, err := s.GetCallGraphRecord(ctx, testCoord, testPipelineV); !errors.Is(err, ports.ErrCallGraphConflict) {
		t.Fatalf("the ledger is not in the state under test: %v", err)
	}

	analyser := measuringAnalyser()
	uc := toolchainUseCase(t, s, analyser, "go1.26.6")

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("two generations of one toolchain that disagree were resolved by naming that toolchain")
	}
	if analyser.calls != 1 {
		t.Errorf("the analyser ran %d times, want 1", analyser.calls)
	}
}

// TestExecute_AStoreWithoutTheScopedReadStillMeasures pins the degradation. The
// dimension-scoped read is an optional store capability, so a store that cannot
// answer it loses the resolution and measures — time, not correctness.
func TestExecute_AStoreWithoutTheScopedReadStillMeasures(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	storeFetchRecord(t, facts, blobs, testCoord)
	// fakeCallGraphStore implements CallGraphStore and not CallGraphSourceReader.
	store := &fakeCallGraphStore{getErr: fmt.Errorf("%w: toolchain disagrees", ports.ErrCallGraphConflict)}
	analyser := measuringAnalyser()

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts: facts, Blobs: blobs, Store: store, Analyser: analyser,
		Clock: fakeClock{t: testTime}, Stopwatch: fakeStopwatch{},
		PipelineVersion: testPipelineV, Logger: slog.Default(),
		Toolchain: func(context.Context) gotoolchain.Version { return "go1.26.6" },
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("a store that cannot answer the scoped read served a cached answer")
	}
	if analyser.calls != 1 {
		t.Errorf("the analyser ran %d times, want 1", analyser.calls)
	}
}
