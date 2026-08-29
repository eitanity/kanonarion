package application_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/iface/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/iface/application"
	domain3 "github.com/eitanity/kanonarion/internal/iface/domain"
	"github.com/eitanity/kanonarion/internal/iface/ports"
)

// openLedger opens a real interface ledger. These tests need one: a conflict is
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

// conflictArtefact is the artefact identity putFactWithBlob's fetch record
// carries, so a generation written by hand names the same bytes the extraction
// under test will name.
func conflictArtefact(t *testing.T, coord coordinate.ModuleCoordinate) string {
	t.Helper()
	id, err := fetchdomain.ArtefactIdentityOf(fetchtest.Record(
		t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(application.PipelineVersion),
		fetchtest.Content("zip"),
		fetchtest.Status(fetchdomain.Verified),
	))
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}
	return id.String()
}

// apiGeneration builds one stored extraction of coord stating funcs as the
// module's exported API.
func apiGeneration(t *testing.T, coord coordinate.ModuleCoordinate, at time.Time, funcs ...string) domain3.InterfaceRecord {
	t.Helper()
	decls := make([]domain3.FuncDecl, 0, len(funcs))
	for _, n := range funcs {
		decls = append(decls, domain3.FuncDecl{Name: n, Signature: "func " + n + "()"})
	}
	r := domain3.InterfaceRecord{
		SchemaVersion: domain3.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Packages: []domain3.PackageInterface{{
			ImportPath: coord.Path(),
			Name:       "pkg",
			Funcs:      decls,
		}},
		OverallStatus:    domain3.InterfaceStatusExtracted,
		ExtractedAt:      at,
		PipelineVersion:  application.PipelineVersion,
		ArtefactIdentity: conflictArtefact(t, coord),
	}
	var h domain3.InterfaceRecordHasher
	sealed, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed
}

// disagreeingLedger files two extractions of one artefact, at one status, that
// state different exported APIs. Composition refuses to pick between them.
func disagreeingLedger(t *testing.T, s *sqlite.Store, coord coordinate.ModuleCoordinate) (first, second domain3.InterfaceRecord) {
	t.Helper()
	ctx := context.Background()
	first = apiGeneration(t, coord, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "New")
	second = apiGeneration(t, coord, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), "New", "Close")
	for _, r := range []domain3.InterfaceRecord{first, second} {
		if err := s.PutInterfaceRecord(ctx, r); err != nil {
			t.Fatalf("PutInterfaceRecord: %v", err)
		}
	}
	if _, _, err := s.GetInterfaceRecord(ctx, coord, application.PipelineVersion); !errors.Is(err, ports.ErrInterfaceConflict) {
		t.Fatalf("the ledger is not in the state under test: GetInterfaceRecord err = %v, want ErrInterfaceConflict", err)
	}
	return first, second
}

// ledgerUseCase wires the extraction stage onto a real ledger.
func ledgerUseCase(
	t *testing.T,
	s *sqlite.Store,
	coord coordinate.ModuleCoordinate,
	ext *fakeExtractor,
) *application.ExtractInterfaceUseCase {
	t.Helper()
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	putFactWithBlob(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"pkg.go": "package pkg\nfunc New() {}\n",
	}))
	clk := fakeClock{t: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	return application.NewExtractInterfaceUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Store:     s,
		Extractor: ext,
		Clock:     clk,
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// measuringExtractor states an API unlike either stored generation, so the
// generation it appends is distinguishable from both.
func measuringExtractor() *fakeExtractor {
	return &fakeExtractor{record: domain3.InterfaceRecord{
		SchemaVersion: domain3.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Packages: []domain3.PackageInterface{{
			ImportPath: "example.com/pkg",
			Name:       "pkg",
			Funcs: []domain3.FuncDecl{
				{Name: "New", Signature: "func New()"},
				{Name: "Close", Signature: "func Close()"},
				{Name: "Open", Signature: "func Open()"},
			},
		}},
		OverallStatus: domain3.InterfaceStatusExtracted,
		ExtractedAt:   time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}}
}

// TestExecute_AConflictingLedgerIsACacheMissNotAFailure.
//
// The interface stage held the same defect as the call graph stage: a
// composition refusal at the cache lookup was returned as an extraction failure.
// Two stored generations that disagree mean no single one answers the
// coordinate, and for a path about to MEASURE one that is a cache miss.
func TestExecute_AConflictingLedgerIsACacheMissNotAFailure(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	s := openLedger(t)
	first, second := disagreeingLedger(t, s, coord)

	ext := measuringExtractor()
	uc := ledgerUseCase(t, s, coord, ext)

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("a composition refusal was reported as an extraction failure: %v", err)
	}
	if result.FromCache {
		t.Error("extraction served a cached answer from a ledger that holds no single answer")
	}
	if ext.calls != 1 {
		t.Fatalf("the extractor ran %d times, want 1: the run must measure", ext.calls)
	}

	held, err := s.ListInterfaceRecordsFor(ctx, coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("ListInterfaceRecordsFor: %v", err)
	}
	if len(held) != 3 {
		t.Fatalf("the ledger holds %d generations, want 3: extraction appends", len(held))
	}
	byHash := make(map[string]bool, len(held))
	for _, r := range held {
		byHash[r.ContentHash] = true
	}
	for _, want := range []domain3.InterfaceRecord{first, second} {
		if !byHash[want.ContentHash] {
			t.Errorf("generation %s is no longer readable; extraction must not overwrite or delete", want.ContentHash)
		}
	}
	if !byHash[result.Record.ContentHash] {
		t.Errorf("the measured generation %s was not appended", result.Record.ContentHash)
	}
}

// TestGetInterfaceRecord_StillRefusesAConflictAfterExtraction is the read-path
// control. Measuring a new generation is allowed; SERVING an ambiguous answer is
// not, and appending does not make the disagreement go away.
func TestGetInterfaceRecord_StillRefusesAConflictAfterExtraction(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	s := openLedger(t)
	disagreeingLedger(t, s, coord)

	uc := ledgerUseCase(t, s, coord, measuringExtractor())
	if _, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: coord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	_, _, err := s.GetInterfaceRecord(ctx, coord, application.PipelineVersion)
	if !errors.Is(err, ports.ErrInterfaceConflict) {
		t.Fatalf("the read path returned %v, want ErrInterfaceConflict", err)
	}
	if !strings.Contains(err.Error(), "conflicting interface records") {
		t.Errorf("the refusal message changed: %s", err)
	}
}

// TestExecute_OneCacheableGenerationIsStillACacheHit is the control that matters
// most: the fix must turn a REFUSAL into a miss, and nothing else into one.
func TestExecute_OneCacheableGenerationIsStillACacheHit(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	s := openLedger(t)
	only := apiGeneration(t, coord, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "New")
	if err := s.PutInterfaceRecord(ctx, only); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}

	ext := measuringExtractor()
	uc := ledgerUseCase(t, s, coord, ext)

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Fatal("a coordinate with one cacheable generation re-measured; every run would re-extract everything")
	}
	if ext.calls != 0 {
		t.Errorf("the extractor ran %d times on a cache hit, want 0", ext.calls)
	}
	if result.Record.ContentHash != only.ContentHash {
		t.Errorf("served %s, want the held generation %s", result.Record.ContentHash, only.ContentHash)
	}
	held, err := s.ListInterfaceRecordsFor(ctx, coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("ListInterfaceRecordsFor: %v", err)
	}
	if len(held) != 1 {
		t.Errorf("the ledger holds %d generations, want 1: a cache hit writes nothing", len(held))
	}
}

// TestExecute_ForceStillSkipsTheLedgerEntirely is the --force control. Force
// means measure without consulting the ledger, and this change does not widen it.
func TestExecute_ForceStillSkipsTheLedgerEntirely(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	s := openLedger(t)
	only := apiGeneration(t, coord, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), "New")
	if err := s.PutInterfaceRecord(ctx, only); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}

	ext := measuringExtractor()
	uc := ledgerUseCase(t, s, coord, ext)

	result, err := uc.Execute(ctx, application.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("Force served a cached answer")
	}
	if ext.calls != 1 {
		t.Errorf("the extractor ran %d times under Force, want 1", ext.calls)
	}
	held, err := s.ListInterfaceRecordsFor(ctx, coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("ListInterfaceRecordsFor: %v", err)
	}
	if len(held) != 2 {
		t.Errorf("the ledger holds %d generations, want 2", len(held))
	}
}

// TestExecute_AStoreFailureIsStillAnExtractionFailure is the other half of the
// rule. Only a composition refusal became a cache miss; a store that cannot be
// read at all is still a fault, and the run must not report a measurement it
// could not check the ledger for.
func TestExecute_AStoreFailureIsStillAnExtractionFailure(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	putFactWithBlob(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"pkg.go": "package pkg\nfunc New() {}\n",
	}))
	unreadable := errors.New("store unavailable")
	ext := measuringExtractor()
	uc := application.NewExtractInterfaceUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Store:     &fakeInterfaceStore{getErr: unreadable},
		Extractor: ext,
		Clock:     fakeClock{t: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, unreadable) {
		t.Fatalf("Execute returned %v, want the store failure", err)
	}
	if ext.calls != 0 {
		t.Errorf("the extractor ran %d times after an unreadable store, want 0", ext.calls)
	}
}
