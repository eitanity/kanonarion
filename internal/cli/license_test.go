package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	domain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

var errTest = errors.New("test error")

func makeLicenseCoord(t *testing.T) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPrintLicenseRecord_TextBasic(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{
		Coordinate:      coord,
		OverallStatus:   domain.LicenseStatusDetected,
		PrimarySPDX:     "MIT",
		PipelineVersion: licapp.PipelineVersion,
	}
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "example.com/mod@v1.0.0") {
		t.Errorf("expected module coord in output, got: %q", got)
	}
	if !strings.Contains(got, "MIT") {
		t.Errorf("expected SPDX in output, got: %q", got)
	}
	if strings.Contains(got, "(cached)") {
		t.Errorf("unexpected '(cached)' when fromCache=false")
	}
}

func TestPrintLicenseRecord_TextCached(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{Coordinate: coord, OverallStatus: domain.LicenseStatusDetected, PrimarySPDX: "Apache-2.0"}
	var buf bytes.Buffer
	if err := printLicenseRecord(r, true, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(cached)") {
		t.Errorf("expected '(cached)' in output, got: %q", buf.String())
	}
}

func TestPrintLicenseRecord_TextFailure(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: domain.LicenseStatusExtractionFailed,
		FailureDetail: "zip not found",
	}
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "zip not found") {
		t.Errorf("expected failure detail in output, got: %q", buf.String())
	}
}

func TestPrintLicenseRecord_TextWithFiles(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: domain.LicenseStatusDetected,
		PrimarySPDX:   "MIT",
		LicenseFiles: []domain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", Confidence: 0.99},
			{Path: "vendor/lib/LICENSE", SPDX: "Apache-2.0", Confidence: 0.85, IsVendored: true},
		},
	}
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "LICENSE") {
		t.Errorf("expected license file path, got: %q", got)
	}
	if !strings.Contains(got, "[vendored]") {
		t.Errorf("expected [vendored] tag, got: %q", got)
	}
}

func TestPrintLicenseRecord_JSON(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{Coordinate: coord, OverallStatus: domain.LicenseStatusDetected, PrimarySPDX: "MIT"}
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, true, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"PrimarySPDX"`) {
		t.Errorf("expected JSON field in output, got: %q", buf.String())
	}
}

func TestPrintLicenseRecursive_NoWalks(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	extractUC := &testfakes.FakeExtractLicense{}
	queryUC := testfakes.NewFakeQueryLicense()

	err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no walk record") {
		t.Fatalf("expected no-walk error, got: %v", err)
	}
}

func TestPrintLicenseRecursive_ListWalksError(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.ListErr = errTest
	extractUC := &testfakes.FakeExtractLicense{}
	queryUC := testfakes.NewFakeQueryLicense()

	err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "listing walks") {
		t.Fatalf("expected listing-walks error, got: %v", err)
	}
}

func TestPrintLicenseRecursive_AllSameLicense(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.SetSummaries([]walkports.WalkSummary{
		{ID: "WALK001", Target: coord, StartedAt: time.Now(), OverallStatus: walkdomain.WalkSucceeded},
	})

	dep, _ := fetchdomain.NewModuleCoordinate("example.com/dep", "v1.0.0")
	queryUC := testfakes.NewFakeQueryLicense()
	queryUC.AddRecord(coord, licapp.PipelineVersion, domain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: domain.LicenseStatusDetected,
		PrimarySPDX:   "MIT",
	})
	queryUC.SetResolveResult([]licapp.DepLicenseResult{
		{Coordinate: dep, PrimarySPDX: "MIT"},
	})

	extractUC := &testfakes.FakeExtractLicense{}

	var buf bytes.Buffer
	if err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "All") {
		t.Errorf("expected 'All ... same license' summary, got: %q", buf.String())
	}
}

func TestPrintLicenseRecursive_DifferentLicenses(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.SetSummaries([]walkports.WalkSummary{
		{ID: "WALK001", Target: coord, StartedAt: time.Now(), OverallStatus: walkdomain.WalkSucceeded},
	})

	dep, _ := fetchdomain.NewModuleCoordinate("example.com/dep", "v1.0.0")
	queryUC := testfakes.NewFakeQueryLicense()
	queryUC.AddRecord(coord, licapp.PipelineVersion, domain.LicenseRecord{
		Coordinate: coord, OverallStatus: domain.LicenseStatusDetected, PrimarySPDX: "MIT",
	})
	queryUC.SetResolveResult([]licapp.DepLicenseResult{
		{Coordinate: dep, PrimarySPDX: "Apache-2.0"},
	})

	extractUC := &testfakes.FakeExtractLicense{}

	var buf bytes.Buffer
	if err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Apache-2.0") {
		t.Errorf("expected Apache-2.0 in summary, got: %q", buf.String())
	}
}

func TestPrintLicenseRecursive_AllFlag(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.SetSummaries([]walkports.WalkSummary{
		{ID: "WALK001", Target: coord, StartedAt: time.Now(), OverallStatus: walkdomain.WalkSucceeded},
	})

	dep, _ := fetchdomain.NewModuleCoordinate("example.com/dep", "v1.0.0")
	queryUC := testfakes.NewFakeQueryLicense()
	queryUC.SetResolveResult([]licapp.DepLicenseResult{
		{Coordinate: dep, PrimarySPDX: "MIT"},
	})

	extractUC := &testfakes.FakeExtractLicense{}

	var buf bytes.Buffer
	if err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{all: true}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "example.com/dep") {
		t.Errorf("expected dep in --all output, got: %q", buf.String())
	}
}

func TestPrintLicenseRecursive_AllFlagWithError(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.SetSummaries([]walkports.WalkSummary{
		{ID: "WALK001", Target: coord, StartedAt: time.Now(), OverallStatus: walkdomain.WalkSucceeded},
	})

	dep, _ := fetchdomain.NewModuleCoordinate("example.com/failing", "v1.0.0")
	queryUC := testfakes.NewFakeQueryLicense()
	queryUC.SetResolveResult([]licapp.DepLicenseResult{
		{Coordinate: dep, Err: errTest},
	})

	extractUC := &testfakes.FakeExtractLicense{}

	var buf bytes.Buffer
	if err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{all: true}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Error:") {
		t.Errorf("expected 'Error:' in --all output for failed dep, got: %q", buf.String())
	}
}

func TestPrintLicenseRecursive_EmptyDepResults(t *testing.T) {
	coord := makeLicenseCoord(t)
	walksUC := testfakes.NewFakeQueryWalks()
	walksUC.SetSummaries([]walkports.WalkSummary{
		{ID: "WALK001", Target: coord, StartedAt: time.Now(), OverallStatus: walkdomain.WalkSucceeded},
	})

	queryUC := testfakes.NewFakeQueryLicense()
	// SetResolveResult with empty slice → depResults == 0 → should return nil
	queryUC.SetResolveResult([]licapp.DepLicenseResult{})
	extractUC := &testfakes.FakeExtractLicense{}

	var buf bytes.Buffer
	if err := printLicenseRecursive(context.Background(), coord, walksUC, extractUC, queryUC, licenseFlags{}, &buf); err != nil {
		t.Fatalf("expected nil for empty deps, got: %v", err)
	}
}

func TestLicenseList_EmptyStore(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"license-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "no license records found") {
		t.Errorf("expected empty message, got: %q", stdout.String())
	}
}

func TestRunLicenseList_WithRecords(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licenseports.LicenseSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PrimarySPDX: "MIT", OverallStatus: domain.LicenseStatusDetected},
	})
	var buf bytes.Buffer
	err := runLicenseList(context.Background(), "", "", 50, uc, domain.NewLicenseOverrideSet(nil), &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app@v1.0.0") {
		t.Errorf("expected module in output, got: %q", out)
	}
	if !strings.Contains(out, "MIT") {
		t.Errorf("expected SPDX in output, got: %q", out)
	}
	if !strings.Contains(out, "Detected") {
		t.Errorf("expected status in output, got: %q", out)
	}
	if !strings.Contains(out, "scanner") {
		t.Errorf("expected scanner provenance in output, got: %q", out)
	}
}

func TestRunLicenseList_OverrideProvenance(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	uc.SetList([]licenseports.LicenseSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PrimarySPDX: "Unknown", OverallStatus: domain.LicenseStatusNone},
	})
	ovSet := domain.NewLicenseOverrideSet(map[string]string{"example.com/app": "MIT"})
	var buf bytes.Buffer
	if err := runLicenseList(context.Background(), "", "", 50, uc, ovSet, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "MIT") {
		t.Errorf("expected overridden SPDX in output, got: %q", out)
	}
	if !strings.Contains(out, "override") {
		t.Errorf("expected override provenance in output, got: %q", out)
	}
}

func TestRunLicenseList_SPDXFilter_NoMatch(t *testing.T) {
	uc := testfakes.NewFakeQueryLicense()
	var buf bytes.Buffer
	err := runLicenseList(context.Background(), "Apache-2.0", "", 50, uc, domain.NewLicenseOverrideSet(nil), &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "no license records found") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func TestPrintCopyrightSection_NotAnalysed(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{Coordinate: coord, CopyrightStatus: domain.CopyrightStatusNotAnalysed}
	var buf bytes.Buffer
	if err := printCopyrightSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "not analysed") {
		t.Errorf("expected 'not analysed', got: %q", buf.String())
	}
}

func TestPrintCopyrightSection_NoneFound(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{Coordinate: coord, CopyrightStatus: domain.CopyrightStatusNoneFound}
	var buf bytes.Buffer
	if err := printCopyrightSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "none found") {
		t.Errorf("expected 'none found', got: %q", buf.String())
	}
}

func TestPrintCopyrightSection_ExtractionFailed(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{Coordinate: coord, CopyrightStatus: domain.CopyrightStatusExtractionFailed}
	var buf bytes.Buffer
	if err := printCopyrightSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "extraction failed") {
		t.Errorf("expected 'extraction failed', got: %q", buf.String())
	}
}

func TestPrintCopyrightSection_Found(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{
		Coordinate:      coord,
		CopyrightStatus: domain.CopyrightStatusFound,
		LicenseFiles: []domain.LicenseFileEntry{
			{
				Path: "LICENSE",
				CopyrightStatements: []domain.CopyrightStatement{
					{Verbatim: "Copyright 2020 Alice", Source: "LICENSE"},
					{Verbatim: "Copyright 2021 Bob", Source: "LICENSE"},
				},
			},
			{
				Path: "vendor/lib/LICENSE",
				CopyrightStatements: []domain.CopyrightStatement{
					// Duplicate of first statement — should appear only once.
					{Verbatim: "Copyright 2020 Alice", Source: "vendor/lib/LICENSE"},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := printCopyrightSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "2 statements") {
		t.Errorf("expected '2 statements' (deduped), got: %q", got)
	}
	if !strings.Contains(got, "Copyright 2020 Alice") {
		t.Errorf("expected first statement, got: %q", got)
	}
	if !strings.Contains(got, "Copyright 2021 Bob") {
		t.Errorf("expected second statement, got: %q", got)
	}
	if !strings.Contains(got, "[LICENSE]") {
		t.Errorf("expected source path in output, got: %q", got)
	}
	// Should appear exactly once (deduplication).
	if count := strings.Count(got, "Copyright 2020 Alice"); count != 1 {
		t.Errorf("expected deduped statement to appear once, got %d times", count)
	}
}

func TestPrintProvenanceSection_NotAnalysed(t *testing.T) {
	coord := makeLicenseCoord(t)
	// Zero-value Confidence is the not-analysed gate.
	r := domain.LicenseRecord{Coordinate: coord}
	var buf bytes.Buffer
	if err := printProvenanceSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "not analysed") {
		t.Errorf("expected 'not analysed', got: %q", buf.String())
	}
}

func TestPrintProvenanceSection_NoVerdictWord(t *testing.T) {
	coord := makeLicenseCoord(t)
	// Analysed with copyright-only evidence: the old output was a bare
	// "chain-of-title confidence medium". It must now render facts, not a verdict.
	r := domain.LicenseRecord{
		Coordinate: coord,
		Provenance: domain.ProvenanceSummary{Confidence: domain.ChainOfTitleMedium},
	}
	var buf bytes.Buffer
	if err := printProvenanceSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, "confidence") || strings.Contains(got, "medium") {
		t.Errorf("expected no confidence verdict word, got: %q", got)
	}
	if !strings.Contains(got, "contribution-licensing statement: none found") {
		t.Errorf("expected analysed-zero fact, got: %q", got)
	}
}

func TestPrintProvenanceSection_Facts(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{
		Coordinate: coord,
		Provenance: domain.ProvenanceSummary{
			Confidence: domain.ChainOfTitleHigh,
			Signals: []domain.ProvenanceSignal{
				domain.ProvenanceSignalInboundOutbound,
				domain.ProvenanceSignalAuthorsFile,
				domain.ProvenanceSignalPatentsFile,
			},
		},
	}
	var buf bytes.Buffer
	if err := printProvenanceSection(r, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "contribution-licensing statement: inbound=outbound") {
		t.Errorf("expected contribution statement fact, got: %q", got)
	}
	if !strings.Contains(got, "attribution files: AUTHORS, PATENTS") {
		t.Errorf("expected attribution files fact, got: %q", got)
	}
	if strings.Contains(got, "confidence") {
		t.Errorf("expected no confidence verdict word, got: %q", got)
	}
}

func TestPrintLicenseRecord_TextWithCopyrightFound(t *testing.T) {
	coord := makeLicenseCoord(t)
	r := domain.LicenseRecord{
		Coordinate:      coord,
		OverallStatus:   domain.LicenseStatusDetected,
		PrimarySPDX:     "MIT",
		CopyrightStatus: domain.CopyrightStatusFound,
		LicenseFiles: []domain.LicenseFileEntry{
			{
				Path: "LICENSE", SPDX: "MIT", Confidence: 1.0,
				CopyrightStatements: []domain.CopyrightStatement{
					{Verbatim: "Copyright 2022 Acme", Source: "LICENSE"},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := printLicenseRecord(r, false, false, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "copyright") {
		t.Errorf("expected copyright section, got: %q", got)
	}
	if !strings.Contains(got, "Copyright 2022 Acme") {
		t.Errorf("expected copyright statement, got: %q", got)
	}
}
