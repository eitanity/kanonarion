package application_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/example/adapters/parser/goast"
	"github.com/eitanity/kanonarion/internal/example/application"
	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// A module ingested from a local working tree (a local-replace target or the
// project-walk root) persists its FactRecord under the local-ingest pipeline
// version, not the proxy fetch pipeline version. Extraction must still find it.
func TestExecute_FindsFactRecordUnderLocalIngestPipelineVersion(t *testing.T) {
	const localPipeline = "local-0.1.0"
	coord := mustCoord(t, "example.com/localmod", "v0.0.0")
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	examples := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"go.mod": "module example.com/localmod\n",
	})
	handle, err := blobs.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// The record exists ONLY under the local-ingest pipeline version.
	if perr := facts.PutFetchRecord(context.Background(), domain.FactRecord{
		SchemaVersion:      "2",
		ModulePath:         coord.Path,
		ModuleVersion:      coord.Version,
		PipelineVersion:    localPipeline,
		ContentLocation:    string(handle),
		ContentHash:        "sha256:placeholder",
		VerificationStatus: "LocalSource",
	}); perr != nil {
		t.Fatalf("PutFetchRecord: %v", perr)
	}

	uc := application.NewExtractExampleUseCase(application.Config{
		Facts:                     facts,
		Blobs:                     blobs,
		Examples:                  examples,
		Parser:                    goast.New(),
		Clock:                     fakeClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch:                 fakeStopwatch{},
		FetchPipelineVersion:      "0.3.0",
		LocalFetchPipelineVersion: localPipeline,
		Logger:                    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.ExampleStatusNone {
		t.Errorf("OverallStatus: got %v, want None (zip has no examples)", result.Record.OverallStatus)
	}
}

// The project-walk root pins the synthetic local version, which does not pin
// content. A cached example record for a local coordinate must never be
// served — the working tree is re-analysed fresh on every run.
func TestExecute_LocalCoordinateBypassesRecordCache(t *testing.T) {
	const localPipeline = "local-0.1.0"
	coord := mustCoord(t, "example.com/project", coordinate.LocalVersion)
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	examples := &fakeExampleStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"go.mod": "module example.com/project\n",
	})
	handle, err := blobs.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if perr := facts.PutFetchRecord(context.Background(), domain.FactRecord{
		SchemaVersion:      "2",
		ModulePath:         coord.Path,
		ModuleVersion:      coord.Version,
		PipelineVersion:    localPipeline,
		ContentLocation:    string(handle),
		ContentHash:        "sha256:placeholder",
		VerificationStatus: "LocalSource",
	}); perr != nil {
		t.Fatalf("PutFetchRecord: %v", perr)
	}

	// A stale cached record from a previous run.
	if perr := examples.PutExampleRecord(context.Background(), domain2.ExampleRecord{
		SchemaVersion:   domain2.ExampleSchemaVersion,
		Coordinate:      coord,
		OverallStatus:   domain2.ExampleStatusFound,
		PipelineVersion: application.PipelineVersion,
	}); perr != nil {
		t.Fatalf("PutExampleRecord: %v", perr)
	}

	uc := application.NewExtractExampleUseCase(application.Config{
		Facts:                     facts,
		Blobs:                     blobs,
		Examples:                  examples,
		Parser:                    goast.New(),
		Clock:                     fakeClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch:                 fakeStopwatch{},
		FetchPipelineVersion:      "0.3.0",
		LocalFetchPipelineVersion: localPipeline,
		Logger:                    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("FromCache = true for a local coordinate, want a fresh re-extraction")
	}
}
