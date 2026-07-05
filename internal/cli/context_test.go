package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licapp "github.com/eitanity/kanonarion/internal/license/application"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
)

func TestPrintContextFullEntryPointsByPackage(t *testing.T) {
	out := contextOutput{
		Module:          contextModuleInfo{Path: "example.com/app", Version: "v1.0.0"},
		Verification:    contextVerification{Status: sectionStatusNotFetched},
		License:         contextLicense{Status: sectionStatusNotRun},
		Interface:       contextInterface{Status: sectionStatusNotRun},
		Examples:        contextExamples{Status: sectionStatusNotRun},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusNotRun},
		CallGraph: contextCallGraph{
			Status:    "Extracted",
			Algorithm: "cha",
			NodeCount: 10,
			EdgeCount: 8,
			EntryPointsByPackage: map[string]int{
				"example.com/app/b": 3,
				"example.com/app/a": 5,
			},
		},
	}
	var buf strings.Builder
	if err := printContextFull(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{
		"Entry Points by Package:",
		"example.com/app/a: 5",
		"example.com/app/b: 3",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}

	// Flat list must be absent when EntryPoints is empty.
	if strings.Contains(got, "Entry Points:\n") {
		t.Errorf("unexpected flat entry points section\ngot:\n%s", got)
	}
	// Packages must appear in sorted order.
	aIdx := strings.Index(got, "example.com/app/a")
	bIdx := strings.Index(got, "example.com/app/b")
	if aIdx > bIdx {
		t.Errorf("packages not sorted: a at %d, b at %d", aIdx, bIdx)
	}
}

func TestPrintContextFullEntryPointsFull(t *testing.T) {
	out := contextOutput{
		Module:          contextModuleInfo{Path: "example.com/app", Version: "v1.0.0"},
		Verification:    contextVerification{Status: sectionStatusNotFetched},
		License:         contextLicense{Status: sectionStatusNotRun},
		Interface:       contextInterface{Status: sectionStatusNotRun},
		Examples:        contextExamples{Status: sectionStatusNotRun},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusNotRun},
		CallGraph: contextCallGraph{
			Status:               "Extracted",
			EntryPointsByPackage: map[string]int{"example.com/app": 1},
			EntryPoints:          []string{"example.com/app.Main"},
		},
	}
	var buf strings.Builder
	if err := printContextFull(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{
		"Entry Points by Package:",
		"example.com/app: 1",
		"Entry Points:",
		"example.com/app.Main",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}

func makeNotRunOutput(commands contextCommands) contextOutput {
	return contextOutput{
		Module:          contextModuleInfo{Path: "example.com/app", Version: "v1.0.0"},
		Commands:        commands,
		Verification:    contextVerification{Status: sectionStatusNotFetched},
		Dependencies:    contextDependencies{Status: sectionStatusNotRun},
		License:         contextLicense{Status: sectionStatusNotRun},
		Interface:       contextInterface{Status: sectionStatusNotRun},
		CallGraph:       contextCallGraph{Status: sectionStatusNotRun},
		Examples:        contextExamples{Status: sectionStatusNotRun},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusNotRun},
	}
}

func TestContextNotRunHints_Compact(t *testing.T) {
	cmds := contextCommands{
		License:         "kanonarion license example.com/app@v1.0.0",
		Interface:       "kanonarion interface-show example.com/app@v1.0.0",
		CallGraph:       "kanonarion callgraph-show example.com/app@v1.0.0",
		Examples:        "kanonarion examples-find <symbol>",
		Vulnerabilities: "kanonarion vuln-show example.com/app@v1.0.0",
	}
	out := makeNotRunOutput(cmds)

	var buf strings.Builder
	if err := printContextText(out, true, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	wantHints := []string{
		"Dependencies:    (not run — run: kanonarion walk example.com/app@v1.0.0)",
		"License:         (not run — run: kanonarion license example.com/app@v1.0.0)",
		"Interface:       (not run — run: kanonarion interface-show example.com/app@v1.0.0)",
		"Call Graph:      (not run — run: kanonarion callgraph-show example.com/app@v1.0.0)",
		"Examples:        (not run — run: kanonarion examples-find <symbol>)",
		"Vulnerabilities: (not run — run: kanonarion vuln-show example.com/app@v1.0.0)",
	}
	for _, want := range wantHints {
		if !strings.Contains(got, want) {
			t.Errorf("missing hint %q\ngot:\n%s", want, got)
		}
	}
}

func TestContextNotRunHints_NoCommandFallback(t *testing.T) {
	out := makeNotRunOutput(contextCommands{})
	var buf strings.Builder
	if err := printContextText(out, true, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// Dependencies always has a hint via module path, others fall back to plain (not run)
	if !strings.Contains(got, "Dependencies:    (not run — run: kanonarion walk") {
		t.Errorf("Dependencies hint missing\ngot:\n%s", got)
	}
	for _, section := range []string{"License:", "Interface:", "Call Graph:", "Examples:", "Vulnerabilities:"} {
		wantHint := section + " (not run — run:"
		if strings.Contains(got, wantHint) {
			t.Errorf("unexpected hint for %s when no command set\ngot:\n%s", section, got)
		}
		if !strings.Contains(got, section) {
			t.Errorf("section %q missing from output\ngot:\n%s", section, got)
		}
		// Confirm (not run) appears without a run-hint for this section — verified above via wantHint check.
	}
}

func TestContextNotRunHints_Full(t *testing.T) {
	cmds := contextCommands{
		License:         "kanonarion license example.com/app@v1.0.0",
		Interface:       "kanonarion interface-show example.com/app@v1.0.0",
		CallGraph:       "kanonarion callgraph-show example.com/app@v1.0.0",
		Examples:        "kanonarion examples-find <symbol>",
		Vulnerabilities: "kanonarion vuln-show example.com/app@v1.0.0",
	}
	out := makeNotRunOutput(cmds)

	var buf strings.Builder
	if err := printContextFull(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	wantHints := []string{
		"(not run — run: kanonarion walk example.com/app@v1.0.0)",
		"(not run — run: kanonarion license example.com/app@v1.0.0)",
		"(not run — run: kanonarion interface-show example.com/app@v1.0.0)",
		"(not run — run: kanonarion callgraph-show example.com/app@v1.0.0)",
		"(not run — run: kanonarion examples-find <symbol>)",
	}
	for _, want := range wantHints {
		if !strings.Contains(got, want) {
			t.Errorf("missing full-view hint %q\ngot:\n%s", want, got)
		}
	}
}

func TestPrintContextSummary_Populated(t *testing.T) {
	out := contextOutput{
		Module:   contextModuleInfo{Path: "example.com/app", Version: "v1.0.0"},
		Commands: contextCommands{License: "kanonarion license example.com/app@v1.0.0"},
		Verification: contextVerification{
			Status: "Verified",
			GitURL: "https://github.com/example/app",
		},
		Dependencies: contextDependencies{
			Status: "Resolved",
			Count:  3,
		},
		License: contextLicense{
			Status: "Extracted",
			SPDX:   "MIT",
		},
		Interface: contextInterface{
			Status:   "Extracted",
			Packages: []contextPackage{{ImportPath: "example.com/app", Funcs: []string{"Foo()"}}},
		},
		CallGraph: contextCallGraph{
			Status:    "Extracted",
			NodeCount: 42,
			EdgeCount: 100,
		},
		Examples: contextExamples{
			Status: "Extracted",
			Count:  5,
		},
		Vulnerabilities: contextVulnerabilities{
			Status:     "Affected",
			WalkStatus: "Partial",
			Findings:   []contextCVE{{ID: "GO-2024-0001"}},
		},
	}

	var buf strings.Builder
	if err := printContextSummary(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{
		"Verified",
		"https://github.com/example/app",
		"3 direct",
		"MIT",
		"1 package(s)",
		"42 nodes",
		"5 (",
		"Affected (1 finding(s))",
		"[walk coverage: Partial — other modules unscanned]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in summary output:\n%s", want, got)
		}
	}
}

func TestPrintContextSummary_ErrorBranches(t *testing.T) {
	out := contextOutput{
		Module: contextModuleInfo{Path: "example.com/app", Version: "v1.0.0"},
		Verification: contextVerification{
			Status: sectionStatusReadError,
			Error:  "db locked",
		},
		Dependencies: contextDependencies{
			Status: sectionStatusReadError,
			Error:  "walk missing",
		},
		License:         contextLicense{Status: sectionStatusReadError, Error: "no record"},
		Interface:       contextInterface{Status: sectionStatusReadError, Error: "corrupt"},
		CallGraph:       contextCallGraph{Status: sectionStatusReadError, Error: "bad graph"},
		Examples:        contextExamples{Status: sectionStatusReadError, Error: "store err"},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusReadError, Error: "vuln err"},
	}

	var buf strings.Builder
	if err := printContextSummary(out, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	for _, want := range []string{"db locked", "walk missing", "no record", "corrupt", "bad graph", "store err", "vuln err"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing error %q in output:\n%s", want, got)
		}
	}
}

func TestPrintFullVerification_Populated(t *testing.T) {
	tests := []struct {
		name  string
		v     contextVerification
		wants []string
	}{
		{
			name:  "read error",
			v:     contextVerification{Status: sectionStatusReadError, Error: "db locked"},
			wants: []string{"failed: db locked"},
		},
		{
			name:  "verified with git url and retracted",
			v:     contextVerification{Status: "Verified", GitURL: "https://github.com/foo/bar", Retracted: true, ExtractedAt: "2024-01-01T00:00:00Z"},
			wants: []string{"Verified", "https://github.com/foo/bar", "RETRACTED", "2024-01-01"},
		},
		{
			name:  "verified minimal",
			v:     contextVerification{Status: "Verified"},
			wants: []string{"Verified"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			w := &errWriter{w: &buf}
			printFullVerification(w, tc.v)
			got := buf.String()
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

// TestLicenseSummaryLine_NeverBlank guards the absence-as-answer defect: an
// Unclassified root (a licence file present but unmatched) must never render
// as an empty summary line that reads like "no licence found". The
// low-confidence case additionally surfaces the recognised fragment.
func TestLicenseSummaryLine_NeverBlank(t *testing.T) {
	tests := []struct {
		name string
		l    contextLicense
		want string
	}{
		{
			name: "classified shows SPDX",
			l:    contextLicense{Status: "Detected", SPDX: "MIT"},
			want: "MIT",
		},
		{
			name: "unclassified with low-confidence fragment",
			l: contextLicense{
				Status:                "Unclassified",
				LowConfidenceSPDX:     "AGPL-3.0-or-later",
				LowConfidenceCoverage: 0.0279,
			},
			want: "Unclassified — license file present; low-confidence AGPL-3.0-or-later match (~3% coverage)",
		},
		{
			name: "unclassified without fragment still names the status",
			l:    contextLicense{Status: "Unclassified"},
			want: "Unclassified (license file present, could not classify)",
		},
		{
			name: "none names the absence explicitly",
			l:    contextLicense{Status: "None"},
			want: "None (no license file found)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := licenseSummaryLine(tc.l)
			if got == "" {
				t.Fatal("summary line must never be blank")
			}
			if got != tc.want {
				t.Errorf("licenseSummaryLine = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrintFullLicense_Populated(t *testing.T) {
	tests := []struct {
		name  string
		l     contextLicense
		wants []string
	}{
		{
			name:  "read error",
			l:     contextLicense{Status: sectionStatusReadError, Error: "no record"},
			wants: []string{"failed: no record"},
		},
		{
			name:  "extracted",
			l:     contextLicense{Status: "Detected", SPDX: "Apache-2.0", ExtractedAt: "2024-06-01T00:00:00Z"},
			wants: []string{"Apache-2.0", "Detected", "2024-06-01"},
		},
		{
			name: "unclassified surfaces low-confidence fragment",
			l: contextLicense{
				Status:                "Unclassified",
				LowConfidenceSPDX:     "AGPL-3.0-or-later",
				LowConfidenceCoverage: 0.0279,
			},
			wants: []string{"Unclassified", "Low-confidence match: AGPL-3.0-or-later", "~3% coverage"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			w := &errWriter{w: &buf}
			printFullLicense(w, tc.l, "")
			got := buf.String()
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestPrintFullInterface_Populated(t *testing.T) {
	tests := []struct {
		name  string
		ifc   contextInterface
		wants []string
	}{
		{
			name:  "read error",
			ifc:   contextInterface{Status: sectionStatusReadError, Error: "corrupt"},
			wants: []string{"failed: corrupt"},
		},
		{
			name: "extracted with packages",
			ifc: contextInterface{
				Status: "Extracted",
				Packages: []contextPackage{
					{
						ImportPath: "example.com/app",
						Types:      []string{"type Foo struct"},
						Funcs:      []string{"func Bar() error"},
						Consts:     []string{"MaxRetries"},
						Vars:       []string{"DefaultTimeout"},
					},
				},
			},
			wants: []string{"example.com/app", "type Foo struct", "func Bar() error", "const MaxRetries", "var DefaultTimeout"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			w := &errWriter{w: &buf}
			printFullInterface(w, tc.ifc, "")
			got := buf.String()
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestPrintFullExamples_Populated(t *testing.T) {
	tests := []struct {
		name  string
		ex    contextExamples
		wants []string
	}{
		{
			name:  "read error",
			ex:    contextExamples{Status: sectionStatusReadError, Error: "store err"},
			wants: []string{"failed: store err"},
		},
		{
			name: "extracted with example",
			ex: contextExamples{
				Status: "Extracted",
				Examples: []contextExample{
					{
						Name:   "ExampleFoo",
						Symbol: "Foo",
						Doc:    "Foo shows usage.",
						Body:   "fmt.Println(Foo())",
						Output: "hello\n",
					},
				},
			},
			wants: []string{"ExampleFoo", "(Foo)", "Foo shows usage.", "fmt.Println", "// Output:", "// hello"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			w := &errWriter{w: &buf}
			printFullExamples(w, tc.ex, "")
			got := buf.String()
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestPrintFullVulnerabilities_Populated(t *testing.T) {
	reachable := true
	tests := []struct {
		name  string
		v     contextVulnerabilities
		wants []string
	}{
		{
			name:  "read error",
			v:     contextVulnerabilities{Status: sectionStatusReadError, Error: "vuln err"},
			wants: []string{"failed: vuln err"},
		},
		{
			name: "affected with cve",
			v: contextVulnerabilities{
				Status:          "Affected",
				WalkStatus:      "Complete",
				Reason:          "binary missing",
				ExtractedAt:     "2024-01-01T00:00:00Z",
				WalkID:          "01JWALK000000000000001",
				SnapshotVersion: "v2024.01",
				Findings: []contextCVE{
					{
						ID:        "GO-2024-0001",
						Aliases:   []string{"CVE-2024-1234"},
						Summary:   "heap overflow",
						FixedIn:   "v1.2.3",
						Score:     9.8,
						Reachable: &reachable,
					},
				},
			},
			wants: []string{
				"Affected", "Complete", "binary missing", "2024-01-01",
				"01JWALK000000000000001", "v2024.01",
				"GO-2024-0001", "CVE-2024-1234", "heap overflow", "v1.2.3", "9.8", "true",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			w := &errWriter{w: &buf}
			printFullVulnerabilities(w, tc.v, contextCommands{})
			got := buf.String()
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestPrintFullDependencies_Populated(t *testing.T) {
	tests := []struct {
		name  string
		d     contextDependencies
		wants []string
	}{
		{
			name:  "read error",
			d:     contextDependencies{Status: sectionStatusReadError, Error: "walk missing"},
			wants: []string{"failed: walk missing"},
		},
		{
			name: "resolved with deps",
			d: contextDependencies{
				Status:  "Resolved",
				WalkID:  "01JWALK000000000000001",
				Partial: true,
				Dependencies: []contextDependency{
					{Path: "github.com/foo/bar", Version: "v1.0.0"},
				},
			},
			wants: []string{"Resolved", "01JWALK000000000000001", "Partial: true", "github.com/foo/bar@v1.0.0"},
		},
		{
			name:  "no direct deps",
			d:     contextDependencies{Status: "Resolved"},
			wants: []string{"no direct dependencies"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			w := &errWriter{w: &buf}
			printFullDependencies(w, tc.d, "example.com/app@v1.0.0")
			got := buf.String()
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestBuildCallGraphGroupsByPackage(t *testing.T) {
	// Verify that EntryPointsByPackage counts are aggregated per package and
	// EntryPoints remains nil when entryPointsFull is false.
	cg := contextCallGraph{
		Status:    "Extracted",
		NodeCount: 3,
		EdgeCount: 2,
		EntryPointsByPackage: map[string]int{
			"example.com/app": 1,
		},
	}

	if cg.EntryPoints != nil {
		t.Errorf("EntryPoints should be nil without --entry-points-full, got %v", cg.EntryPoints)
	}
	if got := cg.EntryPointsByPackage["example.com/app"]; got != 1 {
		t.Errorf("EntryPointsByPackage[example.com/app] = %d, want 1", got)
	}
}

func mustContextCoord(t *testing.T) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuildLicense_CopyrightFound(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:      coord,
		OverallStatus:   licdomain.LicenseStatusDetected,
		PrimarySPDX:     "MIT",
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{
				Path: "LICENSE",
				CopyrightStatements: []licdomain.CopyrightStatement{
					{Verbatim: "Copyright 2020 Alice", Holders: []string{"Alice"}, Years: "2020", Source: "LICENSE"},
					{Verbatim: "Copyright 2021 Bob", Holders: []string{"Bob"}, Years: "2021", Source: "LICENSE"},
				},
			},
		},
	})

	l := buildLicense(context.Background(), coord, uc)

	if l.CopyrightStatus != "found" {
		t.Errorf("CopyrightStatus = %q, want %q", l.CopyrightStatus, "found")
	}
	if len(l.CopyrightStatements) != 2 {
		t.Fatalf("CopyrightStatements len = %d, want 2", len(l.CopyrightStatements))
	}
	if l.CopyrightStatements[0].Verbatim != "Copyright 2020 Alice" {
		t.Errorf("first statement verbatim = %q", l.CopyrightStatements[0].Verbatim)
	}
	if l.CopyrightStatements[0].Years != "2020" {
		t.Errorf("first statement years = %q", l.CopyrightStatements[0].Years)
	}
}

// TestBuildLicense_LowConfidenceFromUnclassifiedRoot verifies the partial
// fragment is lifted from the root licence file onto the context output only
// when the module is Unclassified, picking the highest-coverage root match and
// ignoring vendored files.
func TestBuildLicense_LowConfidenceFromUnclassifiedRoot(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: licdomain.LicenseStatusUnclassified,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", LowConfidenceSPDX: "AGPL-3.0-or-later", LowConfidenceCoverage: 0.0279},
			{Path: "vendor/x/LICENSE", IsVendored: true, LowConfidenceSPDX: "GPL-3.0", LowConfidenceCoverage: 0.9},
		},
	})

	l := buildLicense(context.Background(), coord, uc)

	if l.Status != "Unclassified" {
		t.Errorf("Status = %q, want Unclassified", l.Status)
	}
	if l.LowConfidenceSPDX != "AGPL-3.0-or-later" {
		t.Errorf("LowConfidenceSPDX = %q, want AGPL-3.0-or-later (vendored match must be ignored)", l.LowConfidenceSPDX)
	}
	if l.LowConfidenceCoverage != 0.0279 {
		t.Errorf("LowConfidenceCoverage = %f, want 0.0279", l.LowConfidenceCoverage)
	}
}

// TestBuildLicense_NoLowConfidenceWhenClassified ensures a confidently
// classified module never carries a low-confidence fallback, even if a stray
// fragment lingers on a file entry.
func TestBuildLicense_NoLowConfidenceWhenClassified(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:    coord,
		OverallStatus: licdomain.LicenseStatusDetected,
		PrimarySPDX:   "MIT",
		LicenseFiles: []licdomain.LicenseFileEntry{
			{Path: "LICENSE", SPDX: "MIT", LowConfidenceSPDX: "AGPL-3.0-or-later", LowConfidenceCoverage: 0.0279},
		},
	})

	l := buildLicense(context.Background(), coord, uc)

	if l.LowConfidenceSPDX != "" {
		t.Errorf("classified module must not carry a low-confidence fallback, got %q", l.LowConfidenceSPDX)
	}
}

func TestBuildLicense_CopyrightDeduplication(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:      coord,
		OverallStatus:   licdomain.LicenseStatusDetected,
		CopyrightStatus: licdomain.CopyrightStatusFound,
		LicenseFiles: []licdomain.LicenseFileEntry{
			{
				Path: "LICENSE",
				CopyrightStatements: []licdomain.CopyrightStatement{
					{Verbatim: "Copyright 2020 Alice", Source: "LICENSE"},
				},
			},
			{
				Path: "vendor/lib/LICENSE",
				CopyrightStatements: []licdomain.CopyrightStatement{
					{Verbatim: "Copyright 2020 Alice", Source: "vendor/lib/LICENSE"},
				},
			},
		},
	})

	l := buildLicense(context.Background(), coord, uc)

	if len(l.CopyrightStatements) != 1 {
		t.Errorf("expected 1 deduplicated statement, got %d", len(l.CopyrightStatements))
	}
}

func TestBuildLicense_CopyrightNotAnalysed(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{
		Coordinate:      coord,
		OverallStatus:   licdomain.LicenseStatusDetected,
		CopyrightStatus: licdomain.CopyrightStatusNotAnalysed,
	})

	l := buildLicense(context.Background(), coord, uc)

	if l.CopyrightStatus != "not_analysed" {
		t.Errorf("CopyrightStatus = %q, want not_analysed", l.CopyrightStatus)
	}
	if len(l.CopyrightStatements) != 0 {
		t.Errorf("expected no statements for not_analysed, got %d", len(l.CopyrightStatements))
	}
}

func TestPrintFullLicense_CopyrightFound(t *testing.T) {
	l := contextLicense{
		Status:          "Detected",
		SPDX:            "MIT",
		CopyrightStatus: "found",
		CopyrightStatements: []contextCopyrightStatement{
			{Verbatim: "Copyright 2020 Alice", Source: "LICENSE"},
		},
	}
	var buf strings.Builder
	w := &errWriter{w: &buf}
	printFullLicense(w, l, "")
	got := buf.String()

	if !strings.Contains(got, "Copyright (1 statements)") {
		t.Errorf("expected copyright header, got: %q", got)
	}
	if !strings.Contains(got, "Copyright 2020 Alice") {
		t.Errorf("expected statement verbatim, got: %q", got)
	}
	if !strings.Contains(got, "[LICENSE]") {
		t.Errorf("expected source path, got: %q", got)
	}
}

func TestPrintFullLicense_CopyrightNotAnalysed(t *testing.T) {
	l := contextLicense{
		Status:          "Detected",
		CopyrightStatus: "not_analysed",
	}
	var buf strings.Builder
	w := &errWriter{w: &buf}
	printFullLicense(w, l, "")
	got := buf.String()

	if !strings.Contains(got, "not analysed") {
		t.Errorf("expected 'not analysed', got: %q", got)
	}
}

func TestPrintFullLicense_CopyrightNoneFound(t *testing.T) {
	l := contextLicense{
		Status:          "Detected",
		CopyrightStatus: "none_found",
	}
	var buf strings.Builder
	w := &errWriter{w: &buf}
	printFullLicense(w, l, "")
	got := buf.String()

	if !strings.Contains(got, "none found") {
		t.Errorf("expected 'none found', got: %q", got)
	}
}
