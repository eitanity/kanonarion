package application_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/application"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// A module ingested from a local working tree (a local-replace target or the
// project-walk root) persists its FactRecord under the local-ingest pipeline
// version, not the proxy fetch pipeline version. Extraction must still find it.
func TestExecute_FindsFactRecordUnderLocalIngestPipelineVersion(t *testing.T) {
	const localPipeline = "local-0.1.0"
	coord := mustCoord(t, "example.com/localmod", "v0.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// The record exists ONLY under the local-ingest pipeline version.
	if perr := factStore.PutFetchRecord(context.Background(), domain.FactRecord{
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

	uc := application.NewExtractLicenseUseCase(application.Config{
		Facts:                     factStore,
		Blobs:                     blobStore,
		Licenses:                  licenseStore,
		Detector:                  &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}},
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
	if result.Record.OverallStatus != domain2.LicenseStatusDetected {
		t.Errorf("OverallStatus: got %v, want Detected", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", result.Record.PrimarySPDX)
	}
}

// The project-walk root pins the synthetic local version, which does not pin
// content. A cached licence record for a local coordinate must never be
// served — the working tree is re-analysed fresh on every run.
func TestExecute_LocalCoordinateBypassesRecordCache(t *testing.T) {
	const localPipeline = "local-0.1.0"
	coord := mustCoord(t, "example.com/project", domain.LocalVersion)
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if perr := factStore.PutFetchRecord(context.Background(), domain.FactRecord{
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
	stale := domain2.LicenseRecord{
		SchemaVersion:   domain2.LicenseSchemaVersion,
		Ecosystem:       domain.EcosystemGo,
		Coordinate:      coord,
		PrimarySPDX:     "Apache-2.0",
		OverallStatus:   domain2.LicenseStatusDetected,
		ExtractedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: application.PipelineVersion,
	}
	var h domain2.LicenseRecordHasher
	stale, err = h.SetContentHash(stale)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if perr := licenseStore.PutLicenseRecord(context.Background(), stale); perr != nil {
		t.Fatalf("PutLicenseRecord: %v", perr)
	}

	uc := application.NewExtractLicenseUseCase(application.Config{
		Facts:                     factStore,
		Blobs:                     blobStore,
		Licenses:                  licenseStore,
		Detector:                  &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}},
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
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT (fresh extraction, not the stale Apache-2.0 record)", result.Record.PrimarySPDX)
	}
	// The root's record is the project's own outbound declaration, not an
	// inbound dependency obligation.
	if result.Record.Role != domain2.LicenseRoleRootDeclaration {
		t.Errorf("Role = %q, want %q for a local coordinate", result.Record.Role, domain2.LicenseRoleRootDeclaration)
	}
}
