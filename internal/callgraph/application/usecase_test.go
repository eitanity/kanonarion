package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

var (
	testCoord, _  = domain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	testPipelineV = "0.1.0"
	testFetchPipV = "0.1.0"
	testTime      = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
)

func buildUseCase(facts *fakeFactStore, blobs *fakeBlobStore, store *fakeCallGraphStore, analyser *fakeAnalyser) *application.ExtractCallGraphUseCase {
	return application.NewExtractCallGraphUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Store:                store,
		Analyser:             analyser,
		Clock:                fakeClock{t: testTime},
		Stopwatch:            fakeStopwatch{},
		PipelineVersion:      testPipelineV,
		FetchPipelineVersion: testFetchPipV,
		Logger:               slog.Default(),
	})
}

func storeFetchRecord(facts *fakeFactStore, blobs *fakeBlobStore, coord domain.ModuleCoordinate) fetchports.BlobHandle {
	// Create a minimal zip blob.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Close() //nolint:errcheck,gosec
	handle := fetchports.BlobHandle("blob:test")
	blobs.blobs = map[fetchports.BlobHandle][]byte{handle: buf.Bytes()}

	r := domain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: testFetchPipV,
		ContentLocation: string(handle),
	}
	facts.PutFetchRecord(context.Background(), r) //nolint:errcheck,gosec
	return handle
}

func TestExecute_CacheHit(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}

	storeFetchRecord(facts, blobs, testCoord)

	// Pre-populate the store with a cached record.
	var h domain2.CallGraphRecordHasher
	cached := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Coordinate:      testCoord,
		Algorithm:       domain2.AlgorithmCHA,
		OverallStatus:   domain2.CallGraphStatusExtracted,
		PipelineVersion: testPipelineV,
		ExtractedAt:     testTime,
	}
	cached, _ = h.SetContentHash(cached)
	store.PutCallGraphRecord(context.Background(), cached) //nolint:errcheck,gosec

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("expected FromCache=true on cache hit")
	}
}

func TestExecute_ModuleNotFetched(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}

	uc := buildUseCase(facts, blobs, store, analyser)
	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error for unfetched module, got nil")
	}
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Errorf("expected ErrModuleNotFetched, got %v", err)
	}
}

func TestExecute_AnalyserFailureRecorded(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	storeFetchRecord(facts, blobs, testCoord)

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusLoadFailed,
			FailureDetail: "no go toolchain available",
		},
	}

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.CallGraphStatusLoadFailed {
		t.Errorf("expected LoadFailed status, got %s", result.Record.OverallStatus)
	}
	if result.FromCache {
		t.Error("expected FromCache=false for new extraction")
	}
}

func TestExecute_PersistsRecord(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	storeFetchRecord(facts, blobs, testCoord)

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
			Nodes: []domain2.CallNode{
				{ID: "example.com/mod.Foo", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Foo"},
			},
		},
	}

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ContentHash == "" {
		t.Error("ContentHash should be set after Execute")
	}
	if result.Record.ExtractedAt.IsZero() {
		t.Error("ExtractedAt should be set")
	}
	if result.Record.NodeCount != 1 {
		t.Errorf("NodeCount = %d, want 1", result.Record.NodeCount)
	}

	// Verify it was persisted.
	persisted, found, err := store.GetCallGraphRecord(context.Background(), testCoord, testPipelineV)
	if err != nil {
		t.Fatalf("GetCallGraphRecord: %v", err)
	}
	if !found {
		t.Fatal("record not found in store after Execute")
	}
	if persisted.ContentHash != result.Record.ContentHash {
		t.Errorf("persisted hash %q != result hash %q", persisted.ContentHash, result.Record.ContentHash)
	}
}

func TestExecute_Force(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	storeFetchRecord(facts, blobs, testCoord)

	var h domain2.CallGraphRecordHasher
	cached := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Coordinate:      testCoord,
		Algorithm:       domain2.AlgorithmCHA,
		OverallStatus:   domain2.CallGraphStatusExtracted,
		PipelineVersion: testPipelineV,
		ExtractedAt:     testTime,
	}
	cached, _ = h.SetContentHash(cached)
	store.PutCallGraphRecord(context.Background(), cached) //nolint:errcheck,gosec

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
		},
	}

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("expected FromCache=false when Force=true")
	}
}

func TestExecute_StoreError(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{putErr: errors.New("disk full")}

	storeFetchRecord(facts, blobs, testCoord)

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
		},
	}

	uc := buildUseCase(facts, blobs, store, analyser)
	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error from store, got nil")
	}
}

func TestExecute_DefaultPipelineVersion(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	storeFetchRecord(facts, blobs, testCoord)

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
		},
	}

	// Config with empty PipelineVersion should use the constant default.
	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Store:                store,
		Analyser:             analyser,
		Clock:                fakeClock{t: testTime},
		Stopwatch:            fakeStopwatch{},
		PipelineVersion:      "", // empty → use default
		FetchPipelineVersion: testFetchPipV,
		Logger:               testLogger(),
	})
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.PipelineVersion != application.PipelineVersion {
		t.Errorf("PipelineVersion = %q, want %q", result.Record.PipelineVersion, application.PipelineVersion)
	}
}

func TestExecute_SameFetchAndCallgraphPipelineVersion(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	// Use identical pipeline versions — requireFetchRecord should de-duplicate.
	const samePV = "0.1.0"
	r := domain.FactRecord{
		ModulePath:      testCoord.Path,
		ModuleVersion:   testCoord.Version,
		PipelineVersion: samePV,
		ContentLocation: "blob:test",
	}
	facts.PutFetchRecord(context.Background(), r) //nolint:errcheck,gosec

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Close() //nolint:errcheck,gosec
	blobs.blobs = map[fetchports.BlobHandle][]byte{"blob:test": buf.Bytes()}

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
		},
	}

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Store:                store,
		Analyser:             analyser,
		Clock:                fakeClock{t: testTime},
		Stopwatch:            fakeStopwatch{},
		PipelineVersion:      samePV,
		FetchPipelineVersion: samePV, // same as pipeline version
		Logger:               testLogger(),
	})
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.CallGraphStatusExtracted {
		t.Errorf("status = %s, want Extracted", result.Record.OverallStatus)
	}
}

func TestExecute_AnalyserInfraError(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	storeFetchRecord(facts, blobs, testCoord)

	analyser := &fakeAnalyser{err: errors.New("analyser crashed")}

	uc := buildUseCase(facts, blobs, store, analyser)
	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error from analyser infra failure, got nil")
	}
}

func TestExecute_EmptyFetchPipelineVersion(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}

	// Register fetch record with one specific pipeline version.
	r := domain.FactRecord{
		ModulePath:      testCoord.Path,
		ModuleVersion:   testCoord.Version,
		PipelineVersion: testPipelineV,
		ContentLocation: "blob:test",
	}
	facts.PutFetchRecord(context.Background(), r) //nolint:errcheck,gosec

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Close() //nolint:errcheck,gosec
	blobs.blobs = map[fetchports.BlobHandle][]byte{"blob:test": buf.Bytes()}

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
		},
	}

	// Empty FetchPipelineVersion forces requireFetchRecord to only check the
	// callgraph pipeline version, exercising the v == "" skip branch.
	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Store:                store,
		Analyser:             analyser,
		Clock:                fakeClock{t: testTime},
		Stopwatch:            fakeStopwatch{},
		PipelineVersion:      testPipelineV,
		FetchPipelineVersion: "", // empty — exercises the v == "" branch
		Logger:               testLogger(),
	})
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.CallGraphStatusExtracted {
		t.Errorf("status = %s, want Extracted", result.Record.OverallStatus)
	}
}

func TestExecute_StoreCheckError(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	store.getErr = errors.New("store unavailable")

	storeFetchRecord(facts, blobs, testCoord)

	analyser := &fakeAnalyser{
		record: domain2.CallGraphRecord{
			SchemaVersion: domain2.CallGraphSchemaVersion,
			Algorithm:     domain2.AlgorithmCHA,
			OverallStatus: domain2.CallGraphStatusExtracted,
		},
	}

	uc := buildUseCase(facts, blobs, store, analyser)
	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected error from store check, got nil")
	}
}

func testLogger() *slog.Logger {
	return slog.Default()
}

func TestExecute_ExcludedByConfig(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	// Sentinel error: if the analyser is invoked the excluded path is broken
	// and Execute would surface this error instead of skipping cleanly.
	analyser := &fakeAnalyser{err: errors.New("analyser must not run for excluded module")}

	storeFetchRecord(facts, blobs, testCoord)

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Store:                store,
		Analyser:             analyser,
		Clock:                fakeClock{t: testTime},
		Stopwatch:            fakeStopwatch{},
		PipelineVersion:      testPipelineV,
		FetchPipelineVersion: testFetchPipV,
		Exclusions:           []string{"other/mod", testCoord.Path, ""},
		Logger:               slog.Default(),
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v (analyser should have been skipped)", err)
	}
	if result.FromCache {
		t.Error("FromCache = true, want false for a freshly-produced excluded record")
	}
	r := result.Record
	if r.OverallStatus != domain2.CallGraphStatusExcludedByConfig {
		t.Errorf("status = %s, want ExcludedByConfig", r.OverallStatus)
	}
	if r.ExclusionReason != domain2.ExclusionReasonConfig {
		t.Errorf("reason = %q, want %q", r.ExclusionReason, domain2.ExclusionReasonConfig)
	}
	if len(r.Nodes) != 0 || len(r.Edges) != 0 {
		t.Errorf("excluded record must have no nodes/edges, got %d/%d", len(r.Nodes), len(r.Edges))
	}
	// Normalised: sorted, de-duplicated, blanks dropped.
	// testCoord.Path is "example.com/mod", which sorts before "other/mod".
	wantList := []string{testCoord.Path, "other/mod"}
	if len(r.ExclusionList) != len(wantList) {
		t.Fatalf("ExclusionList = %v, want %v", r.ExclusionList, wantList)
	}
	for i := range wantList {
		if r.ExclusionList[i] != wantList[i] {
			t.Fatalf("ExclusionList = %v, want %v", r.ExclusionList, wantList)
		}
	}
	if r.ContentHash == "" {
		t.Error("excluded record must have a content hash")
	}
	if _, ok, _ := store.GetCallGraphRecord(context.Background(), testCoord, testPipelineV); !ok {
		t.Error("excluded record was not persisted")
	}
}

// pathlessBlobStore is a BlobStore that does NOT implement BlobPathOptimizer,
// modelling an object-store backend. It forces the use case to materialise the
// blob to a temp file before handing a path to the analyser.
type pathlessBlobStore struct {
	blobs map[fetchports.BlobHandle][]byte
}

func (s *pathlessBlobStore) Put(_ context.Context, r io.Reader) (fetchports.BlobHandle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err //nolint:wrapcheck // test fake
	}
	h := fetchports.BlobHandle("blob:test")
	if s.blobs == nil {
		s.blobs = map[fetchports.BlobHandle][]byte{}
	}
	s.blobs[h] = data
	return h, nil
}

func (s *pathlessBlobStore) Get(_ context.Context, h fetchports.BlobHandle) (io.ReadCloser, error) {
	data, ok := s.blobs[h]
	if !ok {
		return nil, errBlobNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (s *pathlessBlobStore) Exists(_ context.Context, h fetchports.BlobHandle) (bool, error) {
	_, ok := s.blobs[h]
	return ok, nil
}

// pathReadingAnalyser reads the file at the path it is handed, asserting the use
// case materialised the blob to a real, readable filesystem path.
type pathReadingAnalyser struct {
	record   domain2.CallGraphRecord
	gotBytes []byte
	gotPath  string
}

func (a *pathReadingAnalyser) AnalyserMetadata() ports.AnalyserMetadata {
	return ports.AnalyserMetadata{Algorithm: domain2.AlgorithmCHA, Version: "test"}
}

func (a *pathReadingAnalyser) Analyse(_ context.Context, path string, coord domain.ModuleCoordinate) (domain2.CallGraphRecord, error) {
	a.gotPath = path
	b, err := os.ReadFile(path) // #nosec G304 -- path produced by the use case from a temp file
	if err != nil {
		return domain2.CallGraphRecord{}, err //nolint:wrapcheck // test fake
	}
	a.gotBytes = b
	r := a.record
	r.Coordinate = coord
	return r, nil
}

// TestExecute_MaterialisesBlobWhenNoPathOptimizer verifies the fallback: when
// the blob store cannot expose a filesystem path, the use case writes the blob
// bytes to a temp file, hands that path to the analyser, and removes it after.
func TestExecute_MaterialisesBlobWhenNoPathOptimizer(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("mod/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("module example.com/mod\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipBytes := buf.Bytes()

	handle := fetchports.BlobHandle("blob:test")
	blobs := &pathlessBlobStore{blobs: map[fetchports.BlobHandle][]byte{handle: zipBytes}}
	facts := &fakeFactStore{}
	facts.PutFetchRecord(context.Background(), domain.FactRecord{ //nolint:errcheck,gosec
		ModulePath: testCoord.Path, ModuleVersion: testCoord.Version,
		PipelineVersion: testFetchPipV, ContentLocation: string(handle),
	})
	analyser := &pathReadingAnalyser{record: domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Algorithm:     domain2.AlgorithmCHA,
		OverallStatus: domain2.CallGraphStatusExtracted,
	}}

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts: facts, Blobs: blobs, Store: &fakeCallGraphStore{}, Analyser: analyser,
		Clock: fakeClock{t: testTime}, Stopwatch: fakeStopwatch{},
		PipelineVersion: testPipelineV, FetchPipelineVersion: testFetchPipV, Logger: slog.Default(),
	})

	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !bytes.Equal(analyser.gotBytes, zipBytes) {
		t.Errorf("analyser read %d bytes, want the %d-byte blob", len(analyser.gotBytes), len(zipBytes))
	}
	// The temp file must be cleaned up once Execute returns.
	if _, err := os.Stat(analyser.gotPath); !os.IsNotExist(err) {
		t.Errorf("temp blob file %s should be removed after Execute, stat err = %v", analyser.gotPath, err)
	}
}

// Compile-time check: pathlessBlobStore is a BlobStore but deliberately not a
// BlobPathOptimizer.
var _ fetchports.BlobStore = (*pathlessBlobStore)(nil)
