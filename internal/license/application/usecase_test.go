package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/license/application"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

func TestExecute_ModuleNotFetched(t *testing.T) {
	uc := buildUseCase(t, nil, nil, nil)
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")

	_, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, ports.ErrModuleNotFetched) {
		t.Fatalf("expected ErrModuleNotFetched, got %v", err)
	}
}

func TestExecute_CacheHit(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	putFact(t, factStore, coord, "blob:fakecontent")

	// Pre-populate the license store with an existing record.
	existing := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Coordinate:        coord,
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 0.99,
		OverallStatus:     domain2.LicenseStatusDetected,
		ExtractedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion:   application.PipelineVersion,
	}
	var h domain2.LicenseRecordHasher
	var err error
	existing, err = h.SetContentHash(existing)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licenceStore.PutLicenseRecord(context.Background(), existing); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	uc := buildUseCase(t, factStore, nil, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.FromCache {
		t.Error("expected FromCache = true")
	}
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", result.Record.PrimarySPDX)
	}
}

func TestExecute_ForceBypassesCache(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License\n...",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	// Pre-populate cache.
	existing := domain2.LicenseRecord{
		SchemaVersion:   domain2.LicenseSchemaVersion,
		Coordinate:      coord,
		PrimarySPDX:     "Apache-2.0",
		OverallStatus:   domain2.LicenseStatusDetected,
		ExtractedAt:     time.Now().UTC(),
		PipelineVersion: application.PipelineVersion,
	}
	var hh domain2.LicenseRecordHasher
	existing, err = hh.SetContentHash(existing)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if err := licenceStore.PutLicenseRecord(context.Background(), existing); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord, Force: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.FromCache {
		t.Error("expected FromCache = false when Force=true")
	}
}

func TestExecute_DetectedLicense(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v2.0.0")
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
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
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
	if result.Record.ContentHash == "" {
		t.Error("ContentHash must not be empty")
	}

	// Verify the record is persisted.
	persisted, found, err := licenseStore.GetLicenseRecord(context.Background(), coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("GetLicenceRecord: %v", err)
	}
	if !found {
		t.Fatal("record was not persisted")
	}
	if persisted.PrimarySPDX != "MIT" {
		t.Errorf("persisted PrimarySPDX: got %q", persisted.PrimarySPDX)
	}
}

func TestExecute_NoLicenceFiles(t *testing.T) {
	coord := mustCoord(t, "example.com/nolit", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"main.go":   "package main",
		"README.md": "# Readme",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusNone {
		t.Errorf("OverallStatus: got %v, want None", result.Record.OverallStatus)
	}
}

func TestExecute_VendoredLicenseNotPrimary(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v3.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"vendor/dep/LICENSE": "Apache-2.0 text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "Apache-2.0", Confidence: 0.97}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Vendored license should be recorded but must not set the primary.
	if result.Record.OverallStatus != domain2.LicenseStatusNone {
		t.Errorf("OverallStatus: got %v, want None (only vendored files found)", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "" {
		t.Errorf("PrimarySPDX should be empty, got %q", result.Record.PrimarySPDX)
	}
	if len(result.Record.LicenseFiles) != 1 {
		t.Fatalf("expected 1 license file, got %d", len(result.Record.LicenseFiles))
	}
	if !result.Record.LicenseFiles[0].IsVendored {
		t.Error("expected vendored file to be marked IsVendored")
	}
}

// TestExecute_LowConfidenceThreadsToRecord asserts the detector's
// low-confidence fragment (a recognisable but sub-threshold match, e.g. a
// truncated AGPL-3.0) is carried onto the persisted file entry while the
// module stays Unclassified — so a present-but-unclassifiable root licence is
// recorded as a caveat, never as bare absence.
func TestExecute_LowConfidenceThreadsToRecord(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v4.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "truncated AGPL text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{
		LowConfidenceSPDX:     "AGPL-3.0-or-later",
		LowConfidenceCoverage: 0.0279,
	}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusUnclassified {
		t.Errorf("OverallStatus: got %v, want Unclassified", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "" {
		t.Errorf("PrimarySPDX should stay empty, got %q", result.Record.PrimarySPDX)
	}
	if len(result.Record.LicenseFiles) != 1 {
		t.Fatalf("expected 1 license file, got %d", len(result.Record.LicenseFiles))
	}
	f := result.Record.LicenseFiles[0]
	if f.SPDX != "" {
		t.Errorf("SPDX should be empty for an unclassified file, got %q", f.SPDX)
	}
	if f.LowConfidenceSPDX != "AGPL-3.0-or-later" || f.LowConfidenceCoverage != 0.0279 {
		t.Errorf("low-confidence fragment not threaded: spdx=%q coverage=%f",
			f.LowConfidenceSPDX, f.LowConfidenceCoverage)
	}
}

// TestExecute_EffectiveSet asserts that when a module bundles a
// differently-licensed embedded component, the effective set contains both
// the root license and the component license.
func TestExecute_EffectiveSet(t *testing.T) {
	coord := mustCoord(t, "example.com/bundle", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT text",
		"vendor/github.com/google/snappy/LICENSE": "BSD-3-Clause text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	call := 0
	detector := &callCountDetector{
		results: []ports.LicenseMatch{
			{SPDX: "MIT", Confidence: 0.99},
			{SPDX: "BSD-3-Clause", Confidence: 0.97},
		},
		call: &call,
	}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	es := result.Record.EffectiveSet
	if len(es.RootSPDXs) != 1 || es.RootSPDXs[0] != "MIT" {
		t.Errorf("RootSPDXs: got %v, want [MIT]", es.RootSPDXs)
	}
	if len(es.Components) != 1 {
		t.Fatalf("Components: got %d, want 1", len(es.Components))
	}
	comp := es.Components[0]
	if comp.PathPrefix != "vendor/github.com/google/snappy" {
		t.Errorf("Component.PathPrefix: got %q", comp.PathPrefix)
	}
	if len(comp.SPDXs) != 1 || comp.SPDXs[0] != "BSD-3-Clause" {
		t.Errorf("Component.SPDXs: got %v, want [BSD-3-Clause]", comp.SPDXs)
	}
	wantAll := []string{"BSD-3-Clause", "MIT"}
	if len(es.AllSPDXs) != 2 || es.AllSPDXs[0] != wantAll[0] || es.AllSPDXs[1] != wantAll[1] {
		t.Errorf("AllSPDXs: got %v, want %v", es.AllSPDXs, wantAll)
	}
}

func TestExecute_MultipleLicences(t *testing.T) {
	coord := mustCoord(t, "example.com/multi", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT text",
		"COPYING": "Apache-2.0 text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	// The fake detector returns different results based on content.
	call := 0
	detector := &callCountDetector{
		results: []ports.LicenseMatch{
			{SPDX: "MIT", Confidence: 0.98},
			{SPDX: "Apache-2.0", Confidence: 0.96},
		},
		call: &call,
	}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple", result.Record.OverallStatus)
	}
}

// TestExecute_HyphenatedLicenceFilenames is a regression test for
// LICENSE-MIT and LICENSE-BSD style filenames were not recognised by
// isLicenceFilename and caused an empty record (OverallStatus=None).
func TestExecute_HyphenatedLicenceFilenames(t *testing.T) {
	coord := mustCoord(t, "example.com/dual", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE-MIT": "MIT text",
		"LICENSE-BSD": "BSD text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	call := 0
	detector := &callCountDetector{
		results: []ports.LicenseMatch{
			{SPDX: "MIT", Confidence: 0.98},
			{SPDX: "BSD-2-Clause", Confidence: 0.96},
		},
		call: &call,
	}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple", result.Record.OverallStatus)
	}
	if len(result.Record.LicenseFiles) != 2 {
		t.Errorf("LicenseFiles: got %d, want 2", len(result.Record.LicenseFiles))
	}
}

// TestExecute_DottedLicenceFilename is a regression test for LICENSE.<variant>
// filenames (LICENSE.MIT) that carry an SPDX variant rather than a plain file
// extension. Before the fix isLicenceFilename only recognised a fixed set of
// extensions (.txt/.md/.rst), so go-errors/errors@v1.0.2 (LICENSE.MIT) was
// reported as unknown despite carrying a license file.
func TestExecute_DottedLicenceFilename(t *testing.T) {
	coord := mustCoord(t, "example.com/dotted", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE.MIT": "MIT License text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
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
	if len(result.Record.LicenseFiles) != 1 {
		t.Fatalf("LicenseFiles: got %d, want 1", len(result.Record.LicenseFiles))
	}
	if result.Record.LicenseFiles[0].Path != "LICENSE.MIT" {
		t.Errorf("LicenseFile path: got %q, want LICENSE.MIT", result.Record.LicenseFiles[0].Path)
	}
}

// TestExecute_ExcludesGoSourceFromLicenceFilenames is a regression test:
// license.go from github.com/google/licensecheck@v0.3.1 has a base name that
// satisfies the LICENSE.<suffix> dotted-form rule (LICENSE.GO), so its full Go
// source was embedded as a root-level license file alongside LICENSE. A .go
// file is never the license grant for a module.
func TestExecute_ExcludesGoSourceFromLicenceFilenames(t *testing.T) {
	coord := mustCoord(t, "example.com/gosource", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE":    "BSD-3-Clause License text",
		"license.go": "// Copyright 2019 The Go Authors. All rights reserved.\npackage licensecheck",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "BSD-3-Clause", Confidence: 0.98}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.LicenseFiles) != 1 {
		t.Fatalf("LicenseFiles: got %d, want 1", len(result.Record.LicenseFiles))
	}
	if result.Record.LicenseFiles[0].Path != "LICENSE" {
		t.Errorf("LicenseFile path: got %q, want LICENSE", result.Record.LicenseFiles[0].Path)
	}
}

// TestExecute_DottedMultiLicenceFilenames mirrors cyphar/filepath-securejoin,
// which dual-licenses via LICENSE.MPL-2.0 and LICENSE.BSD (plus an explanatory
// COPYING.md). All three must be recognised as license files so the module
// resolves to a Multiple status rather than unknown.
func TestExecute_DottedMultiLicenceFilenames(t *testing.T) {
	coord := mustCoord(t, "example.com/dualdotted", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE.MPL-2.0": "MPL text",
		"LICENSE.BSD":     "BSD text",
		"COPYING.md":      "This project is dual licensed.",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	call := 0
	detector := &callCountDetector{
		results: []ports.LicenseMatch{
			// Sorted by path: COPYING.md, LICENSE.BSD, LICENSE.MPL-2.0.
			{},
			{SPDX: "BSD-3-Clause", Confidence: 0.97},
			{SPDX: "MPL-2.0", Confidence: 0.96},
		},
		call: &call,
	}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Record.LicenseFiles) != 3 {
		t.Fatalf("LicenseFiles: got %d, want 3", len(result.Record.LicenseFiles))
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple", result.Record.OverallStatus)
	}
}

// TestExecute_PerFile_SPDXHeader checks that when a module has no
// dedicated license file but root-level.go files carry SPDX-License-Identifier
// headers, enabling --per-file yields OverallStatus=PerFile with the correct
// SPDX identifier.
func TestExecute_PerFile_SPDXHeader(t *testing.T) {
	coord := mustCoord(t, "example.com/spdxonly", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"main.go": "// SPDX-License-Identifier: Apache-2.0\n// Copyright 2024 Authors\npackage main\n",
		"doc.go":  "// SPDX-License-Identifier: Apache-2.0\npackage main\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: coord,
		PerFile:    true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusPerFile {
		t.Errorf("OverallStatus: got %v, want PerFile", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "Apache-2.0" {
		t.Errorf("PrimarySPDX: got %q, want Apache-2.0", result.Record.PrimarySPDX)
	}
	for _, f := range result.Record.LicenseFiles {
		if !f.IsPerFile {
			t.Errorf("file %q: IsPerFile should be true", f.Path)
		}
	}
}

// TestExecute_PerFile_DisabledYieldsNone checks that without --per-file,
// a module with only SPDX source headers still returns OverallStatus=None.
func TestExecute_PerFile_DisabledYieldsNone(t *testing.T) {
	coord := mustCoord(t, "example.com/spdxnoflag", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"main.go": "// SPDX-License-Identifier: MIT\npackage main\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: coord,
		PerFile:    false,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusNone {
		t.Errorf("OverallStatus: got %v, want None", result.Record.OverallStatus)
	}
}

// TestExecute_PerFile_Pass1Wins checks that when a dedicated license file
// exists, Pass 1 takes precedence and Pass 2 is not run.
func TestExecute_PerFile_Pass1Wins(t *testing.T) {
	coord := mustCoord(t, "example.com/pass1wins", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License\n",
		"main.go": "// SPDX-License-Identifier: Apache-2.0\npackage main\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.99}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{
		Coordinate: coord,
		PerFile:    true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusDetected {
		t.Errorf("OverallStatus: got %v, want Detected", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", result.Record.PrimarySPDX)
	}
	for _, f := range result.Record.LicenseFiles {
		if f.IsPerFile {
			t.Errorf("file %q: IsPerFile should be false when Pass 1 succeeds", f.Path)
		}
	}
}

func TestExecute_CorruptZip(t *testing.T) {
	coord := mustCoord(t, "example.com/bad", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	// Store garbage as the blob.
	handle, err := blobStore.Put(context.Background(), bytes.NewReader([]byte("not a zip")))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute should not error on corrupt zip; got %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusExtractionFailed {
		t.Errorf("OverallStatus: got %v, want ExtractionFailed", result.Record.OverallStatus)
	}
	if result.Record.FailureDetail == "" {
		t.Error("FailureDetail must not be empty for ExtractionFailed record")
	}
}

func TestExecute_Idempotent(t *testing.T) {
	coord := mustCoord(t, "example.com/idempotent", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{"LICENSE": "MIT"})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.99}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)

	r1, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("first Execute: %v", err)
	}
	r2, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if !r2.FromCache {
		t.Error("second Execute should be a cache hit")
	}
	if r1.Record.ContentHash != r2.Record.ContentHash {
		t.Errorf("content hashes differ: %q vs %q", r1.Record.ContentHash, r2.Record.ContentHash)
	}
}

// TestExecute_Copyright_WithNotice verifies that when a root LICENSE
// file contains a copyright line, the record carries CopyrightStatusFound and
// populated CopyrightStatements.
func TestExecute_Copyright_WithNotice(t *testing.T) {
	coord := mustCoord(t, "example.com/noticed", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License\n\nCopyright (c) 2024 Noticed Corp\n\nPermission is hereby granted...\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.99}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.CopyrightStatus != domain2.CopyrightStatusFound {
		t.Errorf("CopyrightStatus: got %v, want Found", result.Record.CopyrightStatus)
	}
	if len(result.Record.LicenseFiles) == 0 {
		t.Fatal("expected at least one license file")
	}
	stmts := result.Record.LicenseFiles[0].CopyrightStatements
	if len(stmts) == 0 {
		t.Fatal("expected CopyrightStatements to be populated")
	}
	if stmts[0].Verbatim != "Copyright (c) 2024 Noticed Corp" {
		t.Errorf("Verbatim: got %q", stmts[0].Verbatim)
	}
}

// TestExecute_Copyright_NoNotice verifies that a license file with no
// copyright line yields CopyrightStatusNoneFound — not NotAnalysed.
func TestExecute_Copyright_NoNotice(t *testing.T) {
	coord := mustCoord(t, "example.com/unnoticed", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "Permission is hereby granted, free of charge...\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.99}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.CopyrightStatus != domain2.CopyrightStatusNoneFound {
		t.Errorf("CopyrightStatus: got %v, want NoneFound", result.Record.CopyrightStatus)
	}
}

// TestExecute_Copyright_VendoredFilesSkipped verifies that copyright
// extraction is skipped for vendored license files (Phase 1 scope).
func TestExecute_Copyright_VendoredFilesSkipped(t *testing.T) {
	coord := mustCoord(t, "example.com/vendored", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		// Only a vendored license file — no root-level license file.
		"vendor/dep/LICENSE": "MIT License\nCopyright (c) 2020 Dep Author\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.99}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// CopyrightStatements must be nil for the vendored entry.
	for _, f := range result.Record.LicenseFiles {
		if f.IsVendored && len(f.CopyrightStatements) > 0 {
			t.Errorf("vendored file %q should have no CopyrightStatements", f.Path)
		}
	}
	// Overall status: NoneFound because no root-level files were scanned.
	if result.Record.CopyrightStatus != domain2.CopyrightStatusNoneFound {
		t.Errorf("CopyrightStatus: got %v, want NoneFound", result.Record.CopyrightStatus)
	}
}

// TestExecute_Copyright_FoundVsNotAnalysed is the regression
// pair: a persisted NoneFound record must round-trip as NoneFound, not as the
// NotAnalysed zero value, ensuring the two states remain distinguishable.
func TestExecute_Copyright_FoundVsNotAnalysed(t *testing.T) {
	coord := mustCoord(t, "example.com/regrpair", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "Permission is hereby granted, free of charge, to any person.\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.99}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	_, err = uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Retrieve the persisted record and verify CopyrightStatus survived.
	persisted, found, err := licenseStore.GetLicenseRecord(context.Background(), coord, application.PipelineVersion)
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found {
		t.Fatal("record not found after Execute")
	}
	if persisted.CopyrightStatus == domain2.CopyrightStatusNotAnalysed {
		t.Errorf("NoneFound must not round-trip as NotAnalysed: got %v", persisted.CopyrightStatus)
	}
	if persisted.CopyrightStatus != domain2.CopyrightStatusNoneFound {
		t.Errorf("CopyrightStatus: got %v, want NoneFound", persisted.CopyrightStatus)
	}
}

// TestExecute_NoticeFileExcludedFromStatus verifies that a NOTICE file at the
// module root does not drive the SPDX identity or produce Multiple/Ambiguous
// status — it should be stored for reproduction but excluded from deriveStatus.
// Regression for the yaml.v3 false-Multiple bug.
func TestExecute_NoticeFileExcludedFromStatus(t *testing.T) {
	coord := mustCoord(t, "example.com/noticebug", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT license text",
		"NOTICE":  "Apache attribution notice text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	// Detector returns MIT for LICENSE, Apache-2.0 for NOTICE.
	callN := 0
	detector := &callCountDetector{
		results: []ports.LicenseMatch{
			{SPDX: "MIT", Confidence: 0.99},       // LICENSE
			{SPDX: "Apache-2.0", Confidence: 1.0}, // NOTICE
		},
		call: &callN,
	}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusDetected {
		t.Errorf("OverallStatus: got %v, want Detected (NOTICE must not drive Multiple)", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", result.Record.PrimarySPDX)
	}
}

// TestExecute_HighConfidenceAltNotAmbiguous verifies that a single root
// LICENSE file with a high-confidence primary match and a distant secondary
// is Detected, not Ambiguous. Regression for the klauspost/compress
// false-Ambiguous bug.
func TestExecute_HighConfidenceAltNotAmbiguous(t *testing.T) {
	coord := mustCoord(t, "example.com/altbug", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "Apache 2.0 license text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	// Primary at 0.99, best alt at 0.50 — clearly not ambiguous.
	detector := &fakeDetector{match: ports.LicenseMatch{
		SPDX:       "Apache-2.0",
		Confidence: 0.99,
		AltMatches: []ports.LicenseMatch{{SPDX: "MIT", Confidence: 0.50}},
	}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusDetected {
		t.Errorf("OverallStatus: got %v, want Detected (distant alt must not cause Ambiguous)", result.Record.OverallStatus)
	}

	// Sanity-check: a genuinely ambiguous case (alt within delta) still fires.
	coord2 := mustCoord(t, "example.com/trueambig", "v1.0.0")
	blobStore2 := &fakeBlobStore{}
	factStore2 := &fakeFactStore{}
	licenseStore2 := &fakeLicenseStore{}
	zipData2 := buildModuleZip(t, coord2, map[string]string{"LICENSE": "text"})
	handle2, err := blobStore2.Put(context.Background(), bytes.NewReader(zipData2))
	if err != nil {
		t.Fatalf("Put2: %v", err)
	}
	putFactWithBlob(t, factStore2, coord2, string(handle2))
	detector2 := &fakeDetector{match: ports.LicenseMatch{
		SPDX:       "Apache-2.0",
		Confidence: 0.90,
		AltMatches: []ports.LicenseMatch{{SPDX: "MIT", Confidence: 0.85}}, // within 0.10
	}}
	uc2 := buildUseCaseWithDetector(t, factStore2, blobStore2, licenseStore2, detector2)
	result2, err := uc2.Execute(context.Background(), application.ExtractRequest{Coordinate: coord2})
	if err != nil {
		t.Fatalf("Execute2: %v", err)
	}
	if result2.Record.OverallStatus != domain2.LicenceStatusAmbiguous {
		t.Errorf("OverallStatus: got %v, want Ambiguous (close alt must still fire)", result2.Record.OverallStatus)
	}
}

// TestExecute_CompoundLicenseFileIsMultiple verifies that a single root
// LICENSE file whose alt matches share essentially the same confidence as the
// primary (delta <= compoundConfDelta) is classified as Multiple, not
// Ambiguous. Regression for yaml.v3 / klauspost/compress compound-file
// misclassification.
func TestExecute_CompoundLicenseFileIsMultiple(t *testing.T) {
	coord := mustCoord(t, "example.com/compound", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT and Apache compound license text",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	// Both at 0.85 (delta = 0.000) — compound file containing two full license texts.
	detector := &fakeDetector{match: ports.LicenseMatch{
		SPDX:       "MIT",
		Confidence: 0.85,
		AltMatches: []ports.LicenseMatch{{SPDX: "Apache-2.0", Confidence: 0.85}},
	}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple (compound file must not be Ambiguous)", result.Record.OverallStatus)
	}
}

// TestExecute_Provenance_InboundOutbound verifies that a CONTRIBUTING.md with
// an inbound=outbound declaration yields High chain-of-title confidence.
func TestExecute_Provenance_InboundOutbound(t *testing.T) {
	coord := mustCoord(t, "example.com/provenance", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE":         "MIT License text",
		"CONTRIBUTING.md": "Contributions are licensed under the same license as the project.\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	p := result.Record.Provenance
	if p.Confidence != domain2.ChainOfTitleHigh {
		t.Errorf("Provenance.Confidence: got %s, want high", p.Confidence)
	}
	if !p.HasSignal(domain2.ProvenanceSignalInboundOutbound) {
		t.Error("expected InboundOutbound signal")
	}
}

// TestExecute_Provenance_NoSignals_LowConfidence_Regression is the
// regression pair required by a module with neither a copyright notice
// nor a contribution statement must report Low ("claimed but unevidenced"),
// distinct from NotAnalysed.
func TestExecute_Provenance_NoSignals_LowConfidence_Regression(t *testing.T) {
	coord := mustCoord(t, "example.com/bare", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	// Zip contains only a LICENSE file — no copyright, no CONTRIBUTING, no AUTHORS.
	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License\n\nPermission is hereby granted...",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	// Detector returns no SPDX match (ensures CopyrightStatus = NoneFound too).
	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.97}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	p := result.Record.Provenance
	if p.Confidence != domain2.ChainOfTitleLow {
		t.Errorf("Provenance.Confidence: got %s, want low (unevidenced)", p.Confidence)
	}
	if p.Confidence == domain2.ChainOfTitleNotAnalysed {
		t.Error("Low must be distinct from NotAnalysed")
	}
}

// TestExecute_Provenance_AuthorsFile_MediumConfidence verifies that an AUTHORS
// file without a CONTRIBUTING licensing statement yields Medium confidence.
func TestExecute_Provenance_AuthorsFile_MediumConfidence(t *testing.T) {
	coord := mustCoord(t, "example.com/authors", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT License",
		"AUTHORS": "Jane Doe <jane@example.com>\n",
	})
	handle, err := blobStore.Put(context.Background(), bytes.NewReader(zipData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	putFactWithBlob(t, factStore, coord, string(handle))

	detector := &fakeDetector{match: ports.LicenseMatch{SPDX: "MIT", Confidence: 0.98}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	p := result.Record.Provenance
	if p.Confidence != domain2.ChainOfTitleMedium {
		t.Errorf("Provenance.Confidence: got %s, want medium", p.Confidence)
	}
	if !p.HasSignal(domain2.ProvenanceSignalAuthorsFile) {
		t.Error("expected AuthorsFile signal")
	}
}

// -- helpers --

func mustCoord(t *testing.T, path, version string) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate(%q, %q): %v", path, version, err)
	}
	return c
}

func buildUseCase(t *testing.T, facts *fakeFactStore, blobs *fakeBlobStore, licences *fakeLicenseStore) *application.ExtractLicenseUseCase {
	t.Helper()
	return buildUseCaseWithDetector(t, facts, blobs, licences, &fakeDetector{})
}

func buildUseCaseWithDetector(t *testing.T, facts *fakeFactStore, blobs *fakeBlobStore, licences *fakeLicenseStore, det ports.LicenseDetector) *application.ExtractLicenseUseCase {
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
	cfg := application.Config{
		Facts:                facts,
		Blobs:                blobs,
		Licenses:             licences,
		Detector:             det,
		Clock:                fakeClock{t: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)},
		Stopwatch:            fakeStopwatch{},
		FetchPipelineVersion: application.PipelineVersion,
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return application.NewExtractLicenseUseCase(cfg)
}

func putFact(t *testing.T, s *fakeFactStore, coord coordinate.ModuleCoordinate, blobHandle string) {
	t.Helper()
	putFactWithBlob(t, s, coord, blobHandle)
}

func putFactWithBlob(t *testing.T, s *fakeFactStore, coord coordinate.ModuleCoordinate, blobHandle string) {
	t.Helper()
	r := domain.FactRecord{
		SchemaVersion:      "2",
		ModulePath:         coord.Path,
		ModuleVersion:      coord.Version,
		PipelineVersion:    application.PipelineVersion,
		ContentLocation:    blobHandle,
		ContentHash:        "sha256:placeholder",
		VerificationStatus: "Verified",
	}
	if err := s.PutFetchRecord(context.Background(), r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func buildModuleZip(t *testing.T, coord coordinate.ModuleCoordinate, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	prefix := coord.Path + "@" + coord.Version + "/"
	for name, content := range files {
		f, err := w.Create(prefix + name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// callCountDetector returns results in order, cycling through them.
type callCountDetector struct {
	results []ports.LicenseMatch
	call    *int
}

func (d *callCountDetector) Detect(_ context.Context, _ []byte) (ports.LicenseMatch, error) {
	i := *d.call % len(d.results)
	*d.call++
	return d.results[i], nil
}

func (d *callCountDetector) DetectorMetadata() ports.DetectorMetadata {
	return ports.DetectorMetadata{Name: "fake"}
}

// Ensure fakeFactStore implements fetchports.FactStore.
var _ fetchports.FactStore = (*fakeFactStore)(nil)

// Ensure fakeBlobStore implements fetchports.BlobStore.
var _ fetchports.BlobStore = (*fakeBlobStore)(nil)
