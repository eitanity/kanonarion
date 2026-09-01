package application_test

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/application"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// contentDetector answers per file rather than per module, keyed on a marker in
// the file's own bytes, so one extraction can carry a code licence and a
// documentation or asset licence at once — which is the whole shape under test.
type contentDetector struct {
	byMarker map[string]ports.LicenseMatch
}

func (d *contentDetector) Detect(_ context.Context, content []byte) (ports.LicenseMatch, error) {
	for marker, m := range d.byMarker {
		if strings.Contains(string(content), marker) {
			return m, nil
		}
	}
	return ports.LicenseMatch{}, nil
}

func (d *contentDetector) DetectorMetadata() ports.DetectorMetadata {
	return ports.DetectorMetadata{}
}

// TestExtract_DocumentationLicenceIsNotStoredInTheExpression is the extraction
// leg of the fix, on go-digest's and docker/go-metrics' shape. The read
// surfaces correct a record already in the ledger; this is what a freshly
// extracted one stores, and the two must agree.
func TestExtract_DocumentationLicenceIsNotStoredInTheExpression(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE":      "APACHE-MARKER Apache License Version 2.0",
		"LICENSE.docs": "CC-MARKER Attribution-ShareAlike 4.0 International",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, &contentDetector{
		byMarker: map[string]ports.LicenseMatch{
			"APACHE-MARKER": {SPDX: "Apache-2.0", Confidence: 1},
			"CC-MARKER":     {SPDX: "CC-BY-SA-4.0", Confidence: 0.82},
		},
	})
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rec := result.Record
	if rec.Expression != "Apache-2.0" {
		t.Errorf("stored expression = %q, want Apache-2.0 — a documentation licence is not "+
			"an obligation on using the code", rec.Expression)
	}
	if rec.PrimarySPDX != "Apache-2.0" {
		t.Errorf("stored primary = %q, want Apache-2.0", rec.PrimarySPDX)
	}
	if !strings.Contains(rec.ExpressionBasis, "coverage:") {
		t.Errorf("stored basis = %q, must say coverage took part in the derivation", rec.ExpressionBasis)
	}
	want := map[string]domain2.LicenseCoverage{
		"LICENSE":      domain2.CoverageModuleCode,
		"LICENSE.docs": domain2.CoverageDocumentation,
	}
	for _, f := range rec.LicenseFiles {
		if got := f.Coverage; got != want[f.Path] {
			t.Errorf("%s coverage = %v, want %v", f.Path, got, want[f.Path])
		}
	}
}

// TestExtract_ACodeOnlyModuleStoresWhatItAlwaysDid is the control on the same
// leg: the overwhelming majority of extractions carry one root licence over the
// module's code, and nothing about them may change.
func TestExtract_ACodeOnlyModuleStoresWhatItAlwaysDid(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v2.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE": "MIT-MARKER Permission is hereby granted",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, &contentDetector{
		byMarker: map[string]ports.LicenseMatch{"MIT-MARKER": {SPDX: "MIT", Confidence: 0.98}},
	})
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rec := result.Record
	if rec.Expression != "MIT" || rec.PrimarySPDX != "MIT" || rec.ExpressionBasis != "" {
		t.Errorf("expression=%q primary=%q basis=%q, want MIT/MIT/empty",
			rec.Expression, rec.PrimarySPDX, rec.ExpressionBasis)
	}
	if rec.LicenseFiles[0].Coverage != domain2.CoverageModuleCode {
		t.Errorf("LICENSE coverage = %v, want ModuleCode", rec.LicenseFiles[0].Coverage)
	}
	// The record it stored must still verify: coverage is derived, so it never
	// reaches the seal.
	var h domain2.LicenseRecordHasher
	if err := h.VerifyContentHash(rec); err != nil {
		t.Errorf("the stored record does not verify: %v", err)
	}
}

// TestExtract_AFontPackageKeepsItsElection is the negative control on the
// extraction leg, matching codeberg.org/go-fonts/liberation: two root files
// named per licence, so the module elects between them and its OFL-1.1 covers
// the fonts the module is.
func TestExtract_AFontPackageKeepsItsElection(t *testing.T) {
	coord := mustCoord(t, "example.com/fonts", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenseStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE":     "BSD-MARKER Redistribution and use in source and binary forms",
		"LICENSE-SIL": "OFL-MARKER SIL OPEN FONT LICENSE Version 1.1",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenseStore, &contentDetector{
		byMarker: map[string]ports.LicenseMatch{
			"BSD-MARKER": {SPDX: "BSD-3-Clause", Confidence: 1},
			"OFL-MARKER": {SPDX: "OFL-1.1", Confidence: 1},
		},
	})
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rec := result.Record
	if rec.Expression != "BSD-3-Clause OR OFL-1.1" {
		t.Errorf("expression = %q, want the election untouched", rec.Expression)
	}
	for _, f := range rec.LicenseFiles {
		if f.Coverage != domain2.CoverageModuleCode {
			t.Errorf("%s coverage = %v, want ModuleCode — the module elected both", f.Path, f.Coverage)
		}
	}
}
