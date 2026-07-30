package application_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// Symptom A, at the stage that showed it worst. A module measured under a retired
// fetch pipeline version was refused with "module not fetched" while its zip sat
// in the blob store; on the maintainer's store that was 1357 of 5652 fetched
// coordinates. The version here is deliberately neither the licence pipeline
// version nor anything the stage could name, because the point is that the stage
// names no fetch pipeline version at all.
func TestExecute_ExtractsFromARetiredFetchPipelineVersion(t *testing.T) {
	coord := mustCoord(t, "example.com/retired", "v1.6.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}

	zipData := buildModuleZip(t, coord, map[string]string{"LICENSE": "MIT License text"})
	seed := []fetchtest.Option{
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("retired-fetch-0.0.1"),
		fetchtest.Content("zip"),
		fetchtest.Status(domain.Verified),
	}
	if err := blobStore.Put(context.Background(), fetchtest.ZipIdentity(t, fetchtest.Record(t, seed...)), bytes.NewReader(zipData)); err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	if err := factStore.PutFetchRecord(context.Background(), fetchtest.Sealed(t, seed...)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	result, err := newComposedFetchLicenceUC(t, factStore, blobStore, &fakeLicenseStore{}).
		Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX = %q, want MIT", result.Record.PrimarySPDX)
	}
}

// Symptom B, which no amount of adding versions to a fallback list would have
// fixed: the list returned on its first hit, so the measurement it happened to
// name first won regardless of strength. Here the newer measurement's
// checksum-database lookup FAILED — a statement about the lookup, not the module
// — and the older one succeeded, so composition must serve the older record.
//
// Both measurements describe the same artefact, as two measurements of one pinned
// version must (two different zip hashes for one version is a divergence, and the
// read fails closed on that instead). What identifies which record extraction read
// is the licence record's SourceContentHash, which pins the exact fetch record the
// facts came from — the record actually read, not a version string.
func TestExecute_PrefersTheStrongerMeasurementOverTheNewerOne(t *testing.T) {
	coord := mustCoord(t, "example.com/twomeasurements", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}

	stronger := []fetchtest.Option{
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("fetch-old"),
		fetchtest.Content("zip"),
		fetchtest.Status(domain.Verified),
		fetchtest.FetchedAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	weaker := []fetchtest.Option{
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("fetch-new"),
		fetchtest.Content("zip"),
		fetchtest.Status(domain.Verified),
		fetchtest.SumDBLookupFailed(true),
		fetchtest.FetchedAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
	}
	strongerRecord := fetchtest.Record(t, stronger...)
	weakerRecord := fetchtest.Record(t, weaker...)

	zipData := buildModuleZip(t, coord, map[string]string{"LICENSE": "MIT License text"})
	if err := blobStore.Put(context.Background(), fetchtest.ZipIdentity(t, strongerRecord), bytes.NewReader(zipData)); err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	for _, opts := range [][]fetchtest.Option{stronger, weaker} {
		if err := factStore.PutFetchRecord(context.Background(), fetchtest.Sealed(t, opts...)); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}
	}

	result, err := newComposedFetchLicenceUC(t, factStore, blobStore, &fakeLicenseStore{}).
		Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.SourceContentHash == weakerRecord.ContentHash {
		t.Fatal("extraction read the newer measurement, whose checksum-database lookup failed, in preference to the older one that succeeded")
	}
	if result.Record.SourceContentHash != strongerRecord.ContentHash {
		t.Errorf("SourceContentHash = %q, want %q (the older measurement whose checksum-database lookup answered)",
			result.Record.SourceContentHash, strongerRecord.ContentHash)
	}
}

// Nothing measured is still nothing measured: the wider read must not turn a
// genuinely unfetched module into a success or into some other error.
func TestExecute_StillRefusesAnUnmeasuredModule(t *testing.T) {
	uc := newComposedFetchLicenceUC(t, &fakeFactStore{}, &fakeBlobStore{}, &fakeLicenseStore{})
	_, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: mustCoord(t, "example.com/never", "v1.0.0"),
	})
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Fatalf("Execute error = %v, want %v", err, ports.ErrModuleNotFetched)
	}
}

// A fact store with no composed read cannot be degraded to a version-keyed one
// without reinstating the guess, so the refusal is named rather than reported as
// absence — "this store cannot say what has been measured" is not "nothing has
// been measured", and only the second justifies re-fetching.
func TestExecute_NamesAStoreThatCannotAnswerTheComposedRead(t *testing.T) {
	uc := newComposedFetchLicenceUC(t, versionKeyedOnlyFacts{}, &fakeBlobStore{}, &fakeLicenseStore{})
	_, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: mustCoord(t, "example.com/anything", "v1.0.0"),
	})
	if !errors.Is(err, fetchports.ErrComposedReadUnsupported) {
		t.Fatalf("Execute error = %v, want %v", err, fetchports.ErrComposedReadUnsupported)
	}
	if errors.Is(err, ports.ErrModuleNotFetched) {
		t.Error("a store that cannot answer the composed read was reported as the module never having been fetched")
	}
}

// versionKeyedOnlyFacts is a FactStore that implements the version-keyed read and
// NOT the optional composed one — the shape every fake had before this change.
type versionKeyedOnlyFacts struct{}

func (versionKeyedOnlyFacts) PutFetchRecord(context.Context, domain.SealedRecord) error {
	return nil
}

func (versionKeyedOnlyFacts) GetFetchRecord(context.Context, coordinate.ModuleCoordinate, string) (domain.CompositeRecord, bool, error) {
	return domain.CompositeRecord{}, false, nil
}

func newComposedFetchLicenceUC(
	t *testing.T,
	facts fetchports.FactStore,
	blobs fetchports.BlobStore,
	licences *fakeLicenseStore,
) *application.ExtractLicenseUseCase {
	t.Helper()
	return application.NewExtractLicenseUseCase(application.Config{
		Facts:     facts,
		Blobs:     blobs,
		Licenses:  licences,
		Detector:  &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}},
		Clock:     fakeClock{t: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch: fakeStopwatch{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}
