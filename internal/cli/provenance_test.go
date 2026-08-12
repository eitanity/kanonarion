package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
)

// noLicenceStore is the provenance query with no licence records at all: the
// copyright tier reports not_analysed, which is the point of separating it from
// "analysed, no indicators".
func noLicenceStore() *testfakes.FakeQueryLicense { return testfakes.NewFakeQueryLicense() }

func setJSONOut(t *testing.T, v bool) {
	t.Helper()
	prev := jsonOut
	jsonOut = v
	t.Cleanup(func() { jsonOut = prev })
}

func TestRunProvenance_JSONForkShapedPath(t *testing.T) {
	setJSONOut(t, true)

	var buf strings.Builder
	if err := runProvenance(context.Background(), "github.com/someuser/cobra", "v1.0.0", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}

	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	if out.Module != "github.com/someuser/cobra" || out.Version != "v1.0.0" {
		t.Errorf("module/version = %q/%q, want echo of input", out.Module, out.Version)
	}
	if out.ForkHeuristic.Status != forkStatusPathMatch {
		t.Errorf("status = %q, want %q", out.ForkHeuristic.Status, forkStatusPathMatch)
	}
	if out.ForkHeuristic.CatalogueVersion != fetchdomain.ForkCatalogueVersion {
		t.Errorf("catalogue_version = %q, want %q", out.ForkHeuristic.CatalogueVersion, fetchdomain.ForkCatalogueVersion)
	}
	if len(out.ForkHeuristic.ForkIndicators) != 1 ||
		out.ForkHeuristic.ForkIndicators[0].Canonical != "github.com/spf13/cobra" {
		t.Errorf("fork_indicators = %v, want one for github.com/spf13/cobra", out.ForkHeuristic.ForkIndicators)
	}
}

func TestRunProvenance_JSONUnrelatedPathIsAnalysedNone(t *testing.T) {
	setJSONOut(t, true)

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/some/app", "", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}

	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	if out.ForkHeuristic.Status != forkStatusNone {
		t.Errorf("status = %q, want %q (analysed, no indicators)", out.ForkHeuristic.Status, forkStatusNone)
	}
	if out.ForkHeuristic.Status == fetchdomain.ForkProvenanceNotAnalysed.String() {
		t.Error("analysed-no-fork must be distinguishable from not-analysed")
	}
	if len(out.ForkHeuristic.ForkIndicators) != 0 {
		t.Errorf("fork_indicators = %v, want none", out.ForkHeuristic.ForkIndicators)
	}
	if strings.Contains(buf.String(), `"version"`) {
		t.Errorf("version should be omitted when not supplied\ngot:\n%s", buf.String())
	}
}

func TestRunProvenance_TextForkShapedPath(t *testing.T) {
	setJSONOut(t, false)

	var buf strings.Builder
	if err := runProvenance(context.Background(), "gitlab.com/mirrors/logrus", "", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{
		"gitlab.com/mirrors/logrus",
		"Fork Heuristic:    path_match",
		"path suggests a fork of github.com/sirupsen/logrus",
		"verify",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestRunProvenance_TextUnrelatedPath(t *testing.T) {
	setJSONOut(t, false)

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/some/app", "v2.3.4", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "example.com/some/app@v2.3.4") {
		t.Errorf("text output missing module header\ngot:\n%s", got)
	}
	if !strings.Contains(got, "Fork Heuristic:    no indicators") {
		t.Errorf("text output missing analysed-no-fork line\ngot:\n%s", got)
	}
}

func TestProvenanceCmd_RejectsEmptyModulePath(t *testing.T) {
	var stdout, stderr strings.Builder
	root := newRootCmd(&stdout, &stderr)
	root.SetArgs([]string{"provenance", "@v1.0.0"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected usage error for empty module path")
	}
}

func TestProvenanceCmd_ExitsZeroOnPathMatch(t *testing.T) {
	// A fork indicator is a fact view, not a policy gate: the command must
	// succeed even when the heuristic fires.
	setJSONOut(t, false)
	var stdout, stderr strings.Builder
	root := newRootCmd(&stdout, &stderr)
	root.SetArgs([]string{"provenance", "github.com/someuser/cobra"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() = %v, want nil", err)
	}
	if !strings.Contains(stdout.String(), "path suggests a fork of github.com/spf13/cobra") {
		t.Errorf("stdout missing fork statement\ngot:\n%s", stdout.String())
	}
}

// -- copyright-attribution tier ---------------------------------------------

// jwtLicenceStore is the real shape read out of the store for
// github.com/golang-jwt/jwt/v4@v4.5.1: one MIT LICENSE carrying two copyright
// lines, the original author's and the new maintainers'.
func jwtLicenceStore(t *testing.T) *testfakes.FakeQueryLicense {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("github.com/golang-jwt/jwt/v4", "v4.5.1")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:      coord,
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{{
			Path: "LICENSE",
			SPDX: "MIT",
			CopyrightStatements: []licdomain.CopyrightStatement{
				{Verbatim: "Copyright (c) 2012 Dave Grijalva", Holders: []string{"Dave Grijalva"}, Years: "2012", Source: "LICENSE"},
				{Verbatim: "Copyright (c) 2021 golang-jwt maintainers", Holders: []string{"golang-jwt maintainers"}, Years: "2021", Source: "LICENSE"},
			},
		}},
	})
	f.SetList([]licenseports.LicenseSummary{
		{ModulePath: "github.com/golang-jwt/jwt/v4", ModuleVersion: "v4.5.1"},
		{ModulePath: "github.com/dgrijalva/jwt-go", ModuleVersion: "v3.2.0+incompatible"},
	})
	return f
}

// The republication the name-path heuristic cannot see. provenance reported no
// fork indicators for github.com/golang-jwt/jwt/v4 while the signal sat in the
// store the whole time: the licence record carries both copyright lines.
func TestRunProvenance_JWTRepublicationFromCopyrightLines(t *testing.T) {
	setJSONOut(t, true)

	var buf strings.Builder
	if err := runProvenance(context.Background(), "github.com/golang-jwt/jwt/v4", "v4.5.1", jwtLicenceStore(t), nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}

	// The name-path heuristic still finds nothing — that is the point.
	if len(out.ForkHeuristic.ForkIndicators) != 0 {
		t.Errorf("name-path heuristic unexpectedly fired: %v", out.ForkHeuristic.ForkIndicators)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalRepublication.String() {
		t.Fatalf("copyright signal = %q, want republication\ngot:\n%s", out.CopyrightSignal.Status, buf.String())
	}
	if out.CopyrightSignal.Source != "github.com/golang-jwt/jwt/v4@v4.5.1" {
		t.Errorf("source = %q, want the record the evidence came from", out.CopyrightSignal.Source)
	}

	var namesBoth bool
	var quotesBoth bool
	for _, ind := range out.CopyrightSignal.Indicators {
		holders := strings.Join(ind.Holders, "|")
		if strings.Contains(holders, "Dave Grijalva") && strings.Contains(holders, "golang-jwt maintainers") {
			namesBoth = true
		}
		ev := strings.Join(ind.Evidence, "|")
		if strings.Contains(ev, "Copyright (c) 2012 Dave Grijalva") && strings.Contains(ev, "Copyright (c) 2021 golang-jwt maintainers") {
			quotesBoth = true
		}
	}
	if !namesBoth {
		t.Errorf("no indicator names both holders: %+v", out.CopyrightSignal.Indicators)
	}
	if !quotesBoth {
		t.Errorf("no indicator quotes both copyright lines as evidence: %+v", out.CopyrightSignal.Indicators)
	}
}

// A single-holder module yields no republication indicator, and says so as a
// measured "none" rather than the undifferentiated silence that covered both
// states before.
func TestRunProvenance_SingleHolderYieldsNoneNotSilence(t *testing.T) {
	setJSONOut(t, true)
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:      coord,
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{{
			Path: "LICENSE",
			CopyrightStatements: []licdomain.CopyrightStatement{
				{Verbatim: "Copyright (c) 2019 Acme Corp", Holders: []string{"Acme Corp"}},
			},
		}},
	})

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", f, nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNone.String() {
		t.Errorf("copyright signal = %q, want none", out.CopyrightSignal.Status)
	}
	if len(out.CopyrightSignal.Indicators) != 0 {
		t.Errorf("indicators = %+v, want none", out.CopyrightSignal.Indicators)
	}
}

// A module with no licence record reports not_analysed with the reason — never
// "no indicators", which would assert a negative nothing measured.
func TestRunProvenance_NoLicenceRecordIsNotAnalysed(t *testing.T) {
	setJSONOut(t, true)
	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNotAnalysed.String() {
		t.Fatalf("copyright signal = %q, want not_analysed", out.CopyrightSignal.Status)
	}
	if !strings.Contains(out.CopyrightSignal.Detail, "kanonarion license") {
		t.Errorf("detail %q names no remedy", out.CopyrightSignal.Detail)
	}
}

// Without a version the newest record for the path answers, and the reply names
// the version the evidence came from.
func TestRunProvenance_NoVersionUsesNewestRecordForThePath(t *testing.T) {
	setJSONOut(t, true)
	older, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	newer, err := coordinate.NewModuleCoordinate("example.com/mod", "v2.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	f := testfakes.NewFakeQueryLicense()
	rec := licdomain.LicenseRecord{
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{{
			Path: "LICENSE",
			CopyrightStatements: []licdomain.CopyrightStatement{
				{Verbatim: "Copyright (c) 2019 Acme Corp", Holders: []string{"Acme Corp"}},
			},
		}},
	}
	f.AddRecord(older, licapp.PipelineVersion, rec)
	f.AddRecord(newer, licapp.PipelineVersion, rec)
	f.SetList([]licenseports.LicenseSummary{
		{ModulePath: "example.com/mod", ModuleVersion: "v1.0.0", ExtractedAt: time.Unix(100, 0)},
		{ModulePath: "example.com/mod", ModuleVersion: "v2.0.0", ExtractedAt: time.Unix(200, 0)},
		{ModulePath: "example.com/other", ModuleVersion: "v1.0.0", ExtractedAt: time.Unix(300, 0)},
	})

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "", f, nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Source != "example.com/mod@v2.0.0" {
		t.Errorf("source = %q, want the newest record for the path", out.CopyrightSignal.Source)
	}
}

// A licence record whose copyright extraction found nothing is not_analysed for
// this tier, with the extraction status named: there was nothing to compare.
func TestRunProvenance_RecordWithoutCopyrightLinesIsNotAnalysed(t *testing.T) {
	setJSONOut(t, true)
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		CopyrightStatus: licdomain.CopyrightStatusNoneFound,
		LicenseFiles:    []licdomain.LicenseFileEntry{{Path: "LICENSE"}},
	})

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", f, nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNotAnalysed.String() {
		t.Errorf("copyright signal = %q, want not_analysed", out.CopyrightSignal.Status)
	}
	if !strings.Contains(out.CopyrightSignal.Detail, "none_found") {
		t.Errorf("detail %q does not name the extraction status", out.CopyrightSignal.Detail)
	}
}

// A vendored licence file's copyright line describes a bundled dependency, not
// this module, so it must not manufacture a second holder.
func TestRunProvenance_VendoredCopyrightLinesAreExcluded(t *testing.T) {
	setJSONOut(t, true)
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", CopyrightStatements: []licdomain.CopyrightStatement{
				{Verbatim: "Copyright (c) 2019 Acme Corp", Holders: []string{"Acme Corp"}},
			}},
			{Path: "vendor/example.com/dep/LICENSE", IsVendored: true, CopyrightStatements: []licdomain.CopyrightStatement{
				{Verbatim: "Copyright (c) 2015 Someone Else", Holders: []string{"Someone Else"}},
			}},
		},
	})

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", f, nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNone.String() {
		t.Errorf("copyright signal = %q, want none: the vendored holder is not this module's", out.CopyrightSignal.Status)
	}
}

// A store that cannot be read is not evidence about the module.
func TestRunProvenance_StoreErrorIsNotAnalysed(t *testing.T) {
	setJSONOut(t, true)
	f := testfakes.NewFakeQueryLicense()
	f.Err = errors.New("store unavailable")

	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", f, nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNotAnalysed.String() {
		t.Errorf("copyright signal = %q, want not_analysed", out.CopyrightSignal.Status)
	}
	if !strings.Contains(out.CopyrightSignal.Detail, "store unavailable") {
		t.Errorf("detail %q does not carry the store failure", out.CopyrightSignal.Detail)
	}
}

// A nil use case (no licence store wired) is also not_analysed.
func TestRunProvenance_NilUseCaseIsNotAnalysed(t *testing.T) {
	setJSONOut(t, true)
	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", nil, nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNotAnalysed.String() {
		t.Errorf("copyright signal = %q, want not_analysed", out.CopyrightSignal.Status)
	}
}

// An unparseable version is a bad question, not a negative answer.
func TestRunProvenance_UnparseableVersionIsNotAnalysed(t *testing.T) {
	setJSONOut(t, true)
	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "not-a-version", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.CopyrightSignal.Status != fetchdomain.CopyrightSignalNotAnalysed.String() {
		t.Errorf("copyright signal = %q, want not_analysed", out.CopyrightSignal.Status)
	}
}

// Without a version and with no record for the path at all, the reply says so
// and names how to get one.
func TestRunProvenance_NoVersionNoRecordForPath(t *testing.T) {
	setJSONOut(t, true)
	var buf strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "", noLicenceStore(), nil, &buf); err != nil {
		t.Fatal(err)
	}
	var out provenanceOutput
	if err := json.Unmarshal([]byte(buf.String()), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !strings.Contains(out.CopyrightSignal.Detail, "at any version") {
		t.Errorf("detail %q does not say no version was found", out.CopyrightSignal.Detail)
	}
}

// The text rendering carries the same three states, with the evidence quoted
// under the statement it supports.
func TestRunProvenance_TextRendersCopyrightTier(t *testing.T) {
	setJSONOut(t, false)
	var buf strings.Builder
	if err := runProvenance(context.Background(), "github.com/golang-jwt/jwt/v4", "v4.5.1", jwtLicenceStore(t), nil, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"Copyright Signal:  republication",
		"github.com/golang-jwt/jwt/v4@v4.5.1",
		"evidence: Copyright (c) 2012 Dave Grijalva",
		"evidence: Copyright (c) 2021 golang-jwt maintainers",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text output missing %q\ngot:\n%s", want, got)
		}
	}
}

// "Ran and found nothing" and "did not run" must read differently.
func TestRunProvenance_TextDistinguishesNoneFromNotAnalysed(t *testing.T) {
	setJSONOut(t, false)
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	f := testfakes.NewFakeQueryLicense()
	f.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{{
			Path: "LICENSE",
			CopyrightStatements: []licdomain.CopyrightStatement{
				{Verbatim: "Copyright (c) 2019 Acme Corp", Holders: []string{"Acme Corp"}},
			},
		}},
	})

	var analysed strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", f, nil, &analysed); err != nil {
		t.Fatal(err)
	}
	var absent strings.Builder
	if err := runProvenance(context.Background(), "example.com/mod", "v1.0.0", noLicenceStore(), nil, &absent); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(analysed.String(), "Copyright Signal:  no indicators") {
		t.Errorf("analysed-none output:\n%s", analysed.String())
	}
	if !strings.Contains(absent.String(), "Copyright Signal:  not analysed") {
		t.Errorf("not-analysed output:\n%s", absent.String())
	}
}
