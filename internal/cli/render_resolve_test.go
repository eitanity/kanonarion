package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// -- directives table --

func TestPrintDirectivesTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printDirectivesTable(&buf, directivesSection{Project: "example.com/proj"}); err != nil {
		t.Fatalf("printDirectivesTable: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "no replace/exclude directives in example.com/proj") {
		t.Errorf("empty branch missing project-scoped notice:\n%s", got)
	}
	if strings.Contains(got, "KIND") {
		t.Errorf("empty branch should not print a table header:\n%s", got)
	}
}

func TestPrintDirectivesTable_Populated(t *testing.T) {
	s := directivesSection{
		Project: "example.com/proj",
		Directives: []directiveResult{{
			Kind:           "replace",
			Source:         "go.mod",
			Line:           5,
			OldPath:        "example.com/old",
			OldVersion:     "v1.0.0",
			NewPath:        "example.com/new",
			NewVersion:     "v1.2.0",
			Applied:        true,
			Classification: "version-replace",
			PolicyOutcome:  "warn",
		}},
	}
	var buf bytes.Buffer
	if err := printDirectivesTable(&buf, s); err != nil {
		t.Fatalf("printDirectivesTable: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"KIND", "replace", "go.mod:5",
		"example.com/old@v1.0.0",  // OLD composed from path@version
		"example.com/new@v1.2.0",  // TARGET composed from path@version
		"version-replace", "warn",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// A local-path replace renders the local path as the target, not a module path.
func TestPrintDirectivesTable_LocalPathTarget(t *testing.T) {
	s := directivesSection{
		Project: "example.com/proj",
		Directives: []directiveResult{{
			Kind:           "replace",
			Source:         "go.mod",
			Line:           7,
			OldPath:        "example.com/old",
			LocalPath:      "../local/fork",
			Applied:        true,
			Classification: "local-replace",
			PolicyOutcome:  "warn",
		}},
	}
	var buf bytes.Buffer
	if err := printDirectivesTable(&buf, s); err != nil {
		t.Fatalf("printDirectivesTable: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "../local/fork") {
		t.Errorf("local-path replace should render the local path as target:\n%s", got)
	}
}

// -- godebug table --

func TestPrintGoDebugTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printGoDebugTable(&buf, godebugSection{Project: "example.com/proj"}); err != nil {
		t.Fatalf("printGoDebugTable: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "no //go:debug settings in example.com/proj") {
		t.Errorf("empty branch missing project-scoped notice:\n%s", got)
	}
	if strings.Contains(got, "SETTING") {
		t.Errorf("empty branch should not print a table header:\n%s", got)
	}
}

func TestPrintGoDebugTable_Populated(t *testing.T) {
	s := godebugSection{
		Project: "example.com/proj",
		Settings: []godebugResult{{
			Setting:        "http2client",
			Value:          "0",
			Source:         "go.mod",
			Line:           3,
			Module:         "example.com/proj",
			Applied:        true,
			Classification: "red",
			PolicyOutcome:  "warn",
		}},
	}
	var buf bytes.Buffer
	if err := printGoDebugTable(&buf, s); err != nil {
		t.Fatalf("printGoDebugTable: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"SETTING", "http2client", "go.mod:3", "red", "warn"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// -- vendor table --

func TestPrintVendorTable_NoFindings(t *testing.T) {
	s := vendorSection{
		Project:       "example.com/proj",
		VendorDir:     "vendor",
		OverallStatus: "Reconciled",
		VendorOnly:    true,
		Modules:       []vendorModule{{}, {}},
	}
	var buf bytes.Buffer
	if err := printVendorTable(&buf, s); err != nil {
		t.Fatalf("printVendorTable: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "project: example.com/proj") || !strings.Contains(got, "status: Reconciled") {
		t.Errorf("header line missing fields:\n%s", got)
	}
	if !strings.Contains(got, "no vendor findings (2 modules reconciled)") {
		t.Errorf("no-findings branch should report the reconciled module count:\n%s", got)
	}
}

func TestPrintVendorTable_WithFindings(t *testing.T) {
	s := vendorSection{
		Project:       "example.com/proj",
		VendorDir:     "vendor",
		OverallStatus: "Drift",
		Findings: []vendorFinding{{
			Kind:          "drift",
			Module:        "example.com/x",
			Version:       "v1.0.0",
			Expected:      "h1:aaa",
			Actual:        "h1:bbb",
			PolicyOutcome: "warn",
		}},
	}
	var buf bytes.Buffer
	if err := printVendorTable(&buf, s); err != nil {
		t.Fatalf("printVendorTable: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"KIND", "drift", "example.com/x", "h1:aaa", "h1:bbb", "warn"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// -- notice document --

func TestWriteNoticeDocument_FullEntry(t *testing.T) {
	entries := []licensedomain.NoticeEntry{{
		Coordinate:   fetchdomain.ModuleCoordinate{Path: "example.com/x", Version: "v1.0.0"},
		SPDX:         "MIT",
		Copyrights:   []string{"Copyright 2026 Acme"},
		LicenseTexts: []licensedomain.NoticeLicenseFile{{Path: "LICENSE", Content: "MIT license body"}},
		EmbeddedComponents: []licensedomain.NoticeEmbeddedComponent{{
			PathPrefix:   "vendor/example.com/y",
			SPDXs:        []string{"BSD-3-Clause"},
			LicenseTexts: []licensedomain.NoticeLicenseFile{{Path: "vendor/example.com/y/LICENSE", Content: "BSD license body"}},
		}},
	}}
	var buf bytes.Buffer
	if err := writeNoticeDocument(entries, &buf); err != nil {
		t.Fatalf("writeNoticeDocument: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"THIRD-PARTY-LICENSES",
		"Module:  example.com/x@v1.0.0",
		"License: MIT",
		"Copyright 2026 Acme",
		"MIT license body",
		"Embedded component: vendor/example.com/y",
		"BSD-3-Clause",
		"BSD license body",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("notice output missing %q:\n%s", want, got)
		}
	}
}

func TestWriteNoticeDocument_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeNoticeDocument(nil, &buf); err != nil {
		t.Fatalf("writeNoticeDocument: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "THIRD-PARTY-LICENSES") {
		t.Errorf("header missing for empty document:\n%s", got)
	}
	// No entries => no divider lines after the preamble.
	if strings.Contains(got, noticeDiv) {
		t.Errorf("empty document should not emit entry dividers:\n%s", got)
	}
}

// -- walk-id resolution --

func walkSummary(id string, coord fetchdomain.ModuleCoordinate, scope walkdomain.WalkScope) walkports.WalkSummary {
	return walkports.WalkSummary{ID: id, Target: coord, Scope: scope}
}

func TestLatestWalkIDForCoord_Found(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	fake := testfakes.NewFakeQueryWalks()
	fake.SetSummaries([]walkports.WalkSummary{
		walkSummary("WALK-1", coord, walkdomain.WalkScopeCode),
	})

	id, err := latestWalkIDForCoord(context.Background(), fake, coord)
	if err != nil {
		t.Fatalf("latestWalkIDForCoord: %v", err)
	}
	if id != "WALK-1" {
		t.Errorf("want WALK-1, got %q", id)
	}
}

func TestLatestWalkIDForCoord_NotFound(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	fake := testfakes.NewFakeQueryWalks() // no summaries => empty result

	if _, err := latestWalkIDForCoord(context.Background(), fake, coord); err == nil {
		t.Fatal("expected error when no walk exists for the coordinate")
	} else if !strings.Contains(err.Error(), "no walk found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLatestWalkIDForCoord_ListError(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	fake := testfakes.NewFakeQueryWalks()
	fake.ListErr = context.DeadlineExceeded

	if _, err := latestWalkIDForCoord(context.Background(), fake, coord); err == nil {
		t.Fatal("expected the store list error to propagate")
	}
}

// Scope-aware resolution must ignore walks of a different scope even when their
// coordinate matches.
func TestLatestWalkIDForCoordScope_FiltersByScope(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	fake := testfakes.NewFakeQueryWalks()
	fake.SetSummaries([]walkports.WalkSummary{
		walkSummary("TOOL-WALK", coord, walkdomain.WalkScopeTool),
		walkSummary("PROD-WALK", coord, walkdomain.WalkScopeCode),
	})

	id, err := latestWalkIDForCoordScope(context.Background(), fake, coord, walkdomain.WalkScopeCode)
	if err != nil {
		t.Fatalf("latestWalkIDForCoordScope: %v", err)
	}
	if id != "PROD-WALK" {
		t.Errorf("want PROD-WALK (production scope), got %q", id)
	}
}

// A coordinate that exists only under a different scope resolves to not-found,
// not to the wrong-scope walk.
func TestLatestWalkIDForCoordScope_NotFoundForScope(t *testing.T) {
	coord := fetchdomain.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}
	fake := testfakes.NewFakeQueryWalks()
	fake.SetSummaries([]walkports.WalkSummary{
		walkSummary("TOOL-WALK", coord, walkdomain.WalkScopeTool),
	})

	if _, err := latestWalkIDForCoordScope(context.Background(), fake, coord, walkdomain.WalkScopeCode); err == nil {
		t.Fatal("expected not-found when no walk matches the requested scope")
	} else if !strings.Contains(err.Error(), "no walk found") {
		t.Errorf("unexpected error: %v", err)
	}
}
