package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
)

// A module ingested from a local working tree (a local-replace target or the
// project-walk root) persists its FactRecord under the local-ingest pipeline
// version, not the proxy fetch pipeline version. Extraction must still find it.
func TestExecute_FindsFactRecordUnderLocalIngestPipelineVersion(t *testing.T) {
	const localPipeline = "local-0.1.0"
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Algorithm:     domain2.AlgorithmCHA,
		OverallStatus: domain2.CallGraphStatusExtracted,
	}}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	handle := fetchports.BlobHandle("blob:local")
	blobs.blobs = map[fetchports.BlobHandle][]byte{handle: buf.Bytes()}

	// The record exists ONLY under the local-ingest pipeline version.
	if err := facts.PutFetchRecord(context.Background(), domain.FactRecord{
		ModulePath:      testCoord.Path,
		ModuleVersion:   testCoord.Version,
		PipelineVersion: localPipeline,
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:                     facts,
		Blobs:                     blobs,
		Store:                     store,
		Analyser:                  analyser,
		Clock:                     fakeClock{t: testTime},
		Stopwatch:                 fakeStopwatch{},
		PipelineVersion:           testPipelineV,
		FetchPipelineVersion:      "0.3.0",
		LocalFetchPipelineVersion: localPipeline,
		Logger:                    slog.Default(),
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.CallGraphStatusExtracted {
		t.Errorf("OverallStatus: got %v, want Extracted", result.Record.OverallStatus)
	}
}

// The project-walk root pins the synthetic local version, which does not pin
// content. A cached call-graph record for a local coordinate must never be
// served — the working tree is re-analysed fresh on every run.
func TestExecute_LocalCoordinateBypassesRecordCache(t *testing.T) {
	const localPipeline = "local-0.1.0"
	localCoord := domain.ModuleCoordinate{Path: "example.com/project", Version: domain.LocalVersion}
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{record: domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Algorithm:     domain2.AlgorithmCHA,
		OverallStatus: domain2.CallGraphStatusExtracted,
	}}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	handle := fetchports.BlobHandle("blob:localroot")
	blobs.blobs = map[fetchports.BlobHandle][]byte{handle: buf.Bytes()}

	if err := facts.PutFetchRecord(context.Background(), domain.FactRecord{
		ModulePath:      localCoord.Path,
		ModuleVersion:   localCoord.Version,
		PipelineVersion: localPipeline,
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	// A stale cached record from a previous run.
	var h domain2.CallGraphRecordHasher
	stale := domain2.CallGraphRecord{
		SchemaVersion:   domain2.CallGraphSchemaVersion,
		Coordinate:      localCoord,
		Algorithm:       domain2.AlgorithmCHA,
		OverallStatus:   domain2.CallGraphStatusExtracted,
		PipelineVersion: testPipelineV,
		ExtractedAt:     testTime,
	}
	stale, _ = h.SetContentHash(stale)
	if err := store.PutCallGraphRecord(context.Background(), stale); err != nil {
		t.Fatalf("PutCallGraphRecord: %v", err)
	}

	uc := application.NewExtractCallGraphUseCase(application.Config{
		Facts:                     facts,
		Blobs:                     blobs,
		Store:                     store,
		Analyser:                  analyser,
		Clock:                     fakeClock{t: testTime},
		Stopwatch:                 fakeStopwatch{},
		PipelineVersion:           testPipelineV,
		FetchPipelineVersion:      "0.3.0",
		LocalFetchPipelineVersion: localPipeline,
		Logger:                    slog.Default(),
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: localCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("FromCache = true for a local coordinate, want a fresh re-extraction")
	}
}
