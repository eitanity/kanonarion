package application_test

import (
	"context"
	"strings"
	"testing"

	licensecheck "github.com/eitanity/kanonarion/internal/license/adapters/detector/licensecheck"
	"github.com/eitanity/kanonarion/internal/license/application"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

// contentKeyedDetector returns the match whose key is a substring of the
// scanned content, so a multi-file module can carry a different licence per
// file — which a fixed-match fake cannot express.
type contentKeyedDetector struct {
	matches map[string]ports.LicenseMatch // content substring → match
}

func (d *contentKeyedDetector) Detect(_ context.Context, content []byte) (ports.LicenseMatch, error) {
	for key, m := range d.matches {
		if strings.Contains(string(content), key) {
			return m, nil
		}
	}
	return ports.LicenseMatch{}, nil
}

func (d *contentKeyedDetector) DetectorMetadata() ports.DetectorMetadata {
	return ports.DetectorMetadata{}
}

// TestExecute_BareNameDualLicence guards the cronexpr shape: two bare
// licence-name files (APLv2 + GPLv3) at the module root. Before the matcher
// carried the permissive shorthands only the GPL file was seen, so the record
// read copyleft-only; both arms must now be detected and recorded as a
// disjunction the consumer elects from.
func TestExecute_BareNameDualLicence(t *testing.T) {
	coord := mustCoord(t, "example.com/dualbare", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"APLv2": "Apache License Version 2.0 text",
		"GPLv3": "GNU GENERAL PUBLIC LICENSE Version 3 text",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	detector := &contentKeyedDetector{matches: map[string]ports.LicenseMatch{
		"Apache": {SPDX: "Apache-2.0", Confidence: 0.99},
		"GNU":    {SPDX: "GPL-3.0", Confidence: 0.95},
	}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple", result.Record.OverallStatus)
	}
	if result.Record.Expression != "Apache-2.0 OR GPL-3.0" {
		t.Errorf("Expression: got %q, want Apache-2.0 OR GPL-3.0", result.Record.Expression)
	}
	if len(result.Record.LicenseFiles) != 2 {
		t.Fatalf("LicenseFiles: got %d, want 2 (both bare-name files detected)", len(result.Record.LicenseFiles))
	}
}

// TestExecute_ReversedNameBesidePlainLicence guards the sergi/go-diff shape:
// a plain LICENSE (MIT) beside APACHE-LICENSE-2.0. The Apache arm was
// invisible before the reversed/verbatim names were accepted.
func TestExecute_ReversedNameBesidePlainLicence(t *testing.T) {
	coord := mustCoord(t, "example.com/dualreversed", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"LICENSE":            "MIT licence text",
		"APACHE-LICENSE-2.0": "Apache License Version 2.0 text",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	detector := &contentKeyedDetector{matches: map[string]ports.LicenseMatch{
		"MIT":    {SPDX: "MIT", Confidence: 0.99},
		"Apache": {SPDX: "Apache-2.0", Confidence: 0.98},
	}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple", result.Record.OverallStatus)
	}
	if result.Record.Expression != "Apache-2.0 OR MIT" {
		t.Errorf("Expression: got %q, want Apache-2.0 OR MIT", result.Record.Expression)
	}
}

// TestExecute_ReversedNameOnly guards the mrjones/oauth shape: the module's
// only licence file is MIT-LICENSE.txt. Before the reversed form was accepted
// the module recorded no licence at all — an unlicensed reading of a licensed
// module, which an unknown_license=block policy would block.
func TestExecute_ReversedNameOnly(t *testing.T) {
	coord := mustCoord(t, "example.com/reversedonly", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"MIT-LICENSE.txt": "MIT licence text",
		"main.go":         "package main",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	detector := &contentKeyedDetector{matches: map[string]ports.LicenseMatch{
		"MIT": {SPDX: "MIT", Confidence: 0.98},
	}}
	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, detector)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusDetected {
		t.Errorf("OverallStatus: got %v, want Detected (not None)", result.Record.OverallStatus)
	}
	if result.Record.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", result.Record.PrimarySPDX)
	}
}

// TestExecute_BareNameDualLicence_RealDetector runs the cronexpr shape through
// the real licensecheck detector over the verbatim embedded licence texts —
// the same bytes the module ships — so the end-to-end answer (both files
// found, a real disjunction recorded) is measured rather than faked.
func TestExecute_BareNameDualLicence_RealDetector(t *testing.T) {
	apache, err := domain2.SPDXLicenseText("Apache-2.0")
	if err != nil {
		t.Fatalf("loading Apache-2.0 text: %v", err)
	}
	gpl3, err := domain2.SPDXLicenseText("GPL-3.0")
	if err != nil {
		t.Fatalf("loading GPL-3.0 text: %v", err)
	}

	coord := mustCoord(t, "example.com/dualreal", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"APLv2": apache,
		"GPLv3": gpl3,
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	uc := buildUseCaseWithDetector(t, factStore, blobStore, licenceStore, licensecheck.New())
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain2.LicenseStatusMultiple {
		t.Errorf("OverallStatus: got %v, want Multiple", result.Record.OverallStatus)
	}
	if len(result.Record.LicenseFiles) != 2 {
		t.Fatalf("LicenseFiles: got %d, want 2", len(result.Record.LicenseFiles))
	}
	arms := domain2.DisjunctionArms(result.Record.Expression)
	if len(arms) != 2 {
		t.Fatalf("Expression %q: got %d arms, want a two-arm disjunction", result.Record.Expression, len(arms))
	}
	if arms[0] != "Apache-2.0" {
		t.Errorf("first arm = %q, want Apache-2.0", arms[0])
	}
	if !strings.HasPrefix(arms[1], "GPL-3.0") {
		t.Errorf("second arm = %q, want a GPL-3.0 identifier", arms[1])
	}
}
