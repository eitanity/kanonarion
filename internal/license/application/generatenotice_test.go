package application_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/license/application"
	"github.com/eitanity/kanonarion/internal/license/domain"
)

// buildNoticeUseCase is a test helper that wires a GenerateNoticeUseCase with
// fakes and pre-populated stores.
func buildNoticeUseCase(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	licences *fakeLicenseStore,
) *application.GenerateNoticeUseCase {
	t.Helper()
	if facts == nil {
		facts = &fakeFactStore{}
	}
	if blobs == nil {
		blobs = &fakeBlobStore{}
	}
	if licences == nil {
		licences = &fakeLicenseStore{}
	}
	return application.NewGenerateNoticeUseCase(
		licences, facts, blobs,
		application.PipelineVersion,
		application.PipelineVersion,
	)
}

// seedModule is a helper that stores a fact record, module zip, and license record
// for coord using the given SPDX identifier and copyright line.
func seedModule(
	t *testing.T,
	facts *fakeFactStore,
	blobs *fakeBlobStore,
	licences *fakeLicenseStore,
	coord coordinate.ModuleCoordinate,
	spdx string,
	copyright string,
	licenseText string,
	status domain.LicenseStatus,
	copyrightStatus domain.CopyrightStatus,
) {
	t.Helper()

	zipData := buildModuleZip(t, coord, map[string]string{"LICENSE": licenseText})
	handle, err := blobs.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put blob: %v", err)
	}

	putFact(t, facts, coord, string(handle))

	var stmts []domain.CopyrightStatement
	if copyright != "" {
		stmts = domain.ExtractCopyright("LICENSE", []byte(copyright+"\n"))
	}

	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     spdx,
		OverallStatus:   status,
		CopyrightStatus: copyrightStatus,
		PipelineVersion: application.PipelineVersion,
		LicenseFiles: []domain.LicenseFileEntry{
			{
				Path:                "LICENSE",
				SPDX:                spdx,
				Confidence:          0.99,
				CopyrightStatements: stmts,
			},
		},
	}

	var h domain.LicenseRecordHasher
	rec, err = h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licences.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}
}

// TestGenerateNotice_HappyPath verifies that two clean modules produce sorted
// NoticeEntries with verbatim license text and copyright statements.
func TestGenerateNotice_HappyPath(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	// Seed two modules in reverse alphabetical order to verify sort.
	coordB := mustCoord(t, "example.com/b", "v1.0.0")
	coordA := mustCoord(t, "example.com/a", "v2.0.0")

	seedModule(t, facts, blobs, licences, coordB, "Apache-2.0",
		"Copyright 2021 B Authors", "Apache License text", domain.LicenseStatusDetected, domain.CopyrightStatusFound)
	seedModule(t, facts, blobs, licences, coordA, "MIT",
		"Copyright 2020 A Authors", "MIT License text", domain.LicenseStatusDetected, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coordB, coordA},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(result.ReviewItems) != 0 {
		t.Fatalf("unexpected review items: %v", result.ReviewItems)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(result.Entries))
	}

	// Verify sorted order: a before b.
	if result.Entries[0].Coordinate.Path != "example.com/a" {
		t.Errorf("entries[0].Path = %q, want example.com/a", result.Entries[0].Coordinate.Path)
	}
	if result.Entries[1].Coordinate.Path != "example.com/b" {
		t.Errorf("entries[1].Path = %q, want example.com/b", result.Entries[1].Coordinate.Path)
	}

	// Verify verbatim text.
	if len(result.Entries[0].LicenseTexts) == 0 {
		t.Fatal("entries[0]: no license texts")
	}
	if result.Entries[0].LicenseTexts[0].Content != "MIT License text" {
		t.Errorf("entries[0] license text = %q, want MIT License text", result.Entries[0].LicenseTexts[0].Content)
	}

	// Verify copyright.
	if len(result.Entries[0].Copyrights) == 0 {
		t.Fatal("entries[0]: no copyrights")
	}
	if result.Entries[0].Copyrights[0] != "Copyright 2020 A Authors" {
		t.Errorf("entries[0] copyright = %q", result.Entries[0].Copyrights[0])
	}
}

// TestGenerateNotice_AmbiguousTriggersReview verifies that an Ambiguous module
// is added to ReviewItems, not Entries.
func TestGenerateNotice_AmbiguousTriggersReview(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/ambig", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"Copyright 2021 Someone", "License text", domain.LicenceStatusAmbiguous, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(result.Entries))
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(result.ReviewItems))
	}
	if result.ReviewItems[0].Coordinate != coord {
		t.Errorf("review item coordinate = %v, want %v", result.ReviewItems[0].Coordinate, coord)
	}
}

// TestGenerateNotice_MultipleProducesEntry verifies that a Multiple-license
// module is included verbatim in the notice (not flagged for review), since
// verbatim inclusion of all root-level license texts satisfies attribution for
// compound and multi-file distributions.
func TestGenerateNotice_MultipleProducesEntry(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/multi", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"Copyright 2021 Someone", "License text", domain.LicenseStatusMultiple, domain.CopyrightStatusFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("expected 0 review items, got %d", len(result.ReviewItems))
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 notice entry, got %d", len(result.Entries))
	}
}

// TestGenerateNotice_MissingCopyrightTriggersReview verifies that a module with
// NoneFound copyright status is flagged for review.
func TestGenerateNotice_MissingCopyrightTriggersReview(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/nocopy", "v1.0.0")
	seedModule(t, facts, blobs, licences, coord, "MIT",
		"", "MIT License\n", domain.LicenseStatusDetected, domain.CopyrightStatusNoneFound)

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(result.Entries))
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(result.ReviewItems))
	}
}

// TestGenerateNotice_MissingRecord verifies that a module with no license
// record is flagged for review rather than causing an error.
func TestGenerateNotice_MissingRecord(t *testing.T) {
	uc := buildNoticeUseCase(t, nil, nil, nil)
	coord := mustCoord(t, "example.com/unanalysed", "v1.0.0")

	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(result.ReviewItems))
	}
}

// TestGenerateNotice_EmbeddedComponentTexts verifies that a module with
// vendored/subdirectory embedded components has their license texts collected
// into NoticeEntry.EmbeddedComponents.
func TestGenerateNotice_EmbeddedComponentTexts(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coord := mustCoord(t, "example.com/bundle", "v1.0.0")

	// Build zip with root LICENSE and a vendored BSD-3-Clause component.
	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License text",
		"vendor/github.com/google/snappy/LICENSE": "BSD-3-Clause text",
	})
	handle, err := blobs.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put blob: %v", err)
	}
	putFact(t, facts, coord, string(handle))

	rootStmts := domain.ExtractCopyright("LICENSE", []byte("Copyright 2020 Authors\n"))
	licFiles := []domain.LicenseFileEntry{
		{
			Path:                "LICENSE",
			SPDX:                "MIT",
			Confidence:          0.99,
			IsVendored:          false,
			CopyrightStatements: rootStmts,
		},
		{
			Path:       "vendor/github.com/google/snappy/LICENSE",
			SPDX:       "BSD-3-Clause",
			Confidence: 0.97,
			IsVendored: true,
		},
	}
	rec := domain.LicenseRecord{
		SchemaVersion:   domain.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     "MIT",
		OverallStatus:   domain.LicenseStatusDetected,
		CopyrightStatus: domain.CopyrightStatusFound,
		PipelineVersion: application.PipelineVersion,
		LicenseFiles:    licFiles,
		EffectiveSet:    domain.DeriveEffectiveLicenseSet(licFiles),
	}
	var h domain.LicenseRecordHasher
	rec, err = h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licences.PutLicenseRecord(context.Background(), rec); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)
	result, err := uc.Generate(context.Background(), application.NoticeRequest{
		Coordinates: []coordinate.ModuleCoordinate{coord},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(result.ReviewItems) != 0 {
		t.Fatalf("unexpected review items: %v", result.ReviewItems)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(result.Entries))
	}

	entry := result.Entries[0]
	// Root license text must be present.
	if len(entry.LicenseTexts) != 1 || entry.LicenseTexts[0].Content != "MIT License text" {
		t.Errorf("root LicenseTexts: %v", entry.LicenseTexts)
	}
	// Embedded component must be present.
	if len(entry.EmbeddedComponents) != 1 {
		t.Fatalf("EmbeddedComponents: got %d, want 1", len(entry.EmbeddedComponents))
	}
	comp := entry.EmbeddedComponents[0]
	if comp.PathPrefix != "vendor/github.com/google/snappy" {
		t.Errorf("EmbeddedComponents[0].PathPrefix = %q", comp.PathPrefix)
	}
	if len(comp.SPDXs) != 1 || comp.SPDXs[0] != "BSD-3-Clause" {
		t.Errorf("EmbeddedComponents[0].SPDXs = %v", comp.SPDXs)
	}
	if len(comp.LicenseTexts) != 1 {
		t.Fatalf("EmbeddedComponents[0].LicenseTexts: got %d, want 1", len(comp.LicenseTexts))
	}
	if comp.LicenseTexts[0].Content != "BSD-3-Clause text" {
		t.Errorf("embedded license content = %q, want BSD-3-Clause text", comp.LicenseTexts[0].Content)
	}
}

// TestGenerateNotice_Deterministic verifies that repeated calls with the same
// input produce identical ordering (regression test for sort stability).
func TestGenerateNotice_Deterministic(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	licences := &fakeLicenseStore{}

	coords := []coordinate.ModuleCoordinate{
		mustCoord(t, "example.com/z", "v1.0.0"),
		mustCoord(t, "example.com/a", "v1.0.0"),
		mustCoord(t, "example.com/m", "v1.0.0"),
	}
	for _, c := range coords {
		seedModule(t, facts, blobs, licences, c, "MIT",
			"Copyright 2021 Author", "MIT License text",
			domain.LicenseStatusDetected, domain.CopyrightStatusFound)
	}

	uc := buildNoticeUseCase(t, facts, blobs, licences)

	var paths1, paths2 []string
	for i := 0; i < 2; i++ {
		result, err := uc.Generate(context.Background(), application.NoticeRequest{Coordinates: coords})
		if err != nil {
			t.Fatalf("run %d: Generate: %v", i, err)
		}
		var paths []string
		for _, e := range result.Entries {
			paths = append(paths, e.Coordinate.Path)
		}
		if i == 0 {
			paths1 = paths
		} else {
			paths2 = paths
		}
	}

	for i := range paths1 {
		if paths1[i] != paths2[i] {
			t.Errorf("non-deterministic: run1[%d]=%q run2[%d]=%q", i, paths1[i], i, paths2[i])
		}
	}
}
