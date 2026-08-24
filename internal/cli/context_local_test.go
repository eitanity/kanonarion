package cli

import (
	"bytes"
	"strings"
	"testing"
)

func sampleLocalContext() localContextOutput {
	return localContextOutput{
		Workspace: localWorkspaceInfo{
			Root:          "/home/dev/proj",
			Module:        "example.com/proj",
			VersionID:     "local-abc123",
			AnalysisLevel: "import",
		},
		Dependencies: []localImportedModule{
			{
				Path:             "github.com/spf13/cobra",
				Version:          "v1.10.2",
				ImportedPackages: []string{"github.com/spf13/cobra"},
			},
			{
				Path:             "golang.org/x/mod",
				Version:          "v0.36.0",
				ImportedPackages: []string{"golang.org/x/mod/modfile", "golang.org/x/mod/module"},
				UsedSymbols:      []string{"golang.org/x/mod/modfile.Parse"},
			},
		},
	}
}

// When --json is off, the working-tree context must render the human-readable
// summary, not JSON. This is the flag-honouring guarantee the other context
// paths already provide; the working-tree path previously emitted JSON
// unconditionally.
func TestPrintLocalContextText_RendersTextNotJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := printLocalContextText(sampleLocalContext(), &buf); err != nil {
		t.Fatalf("printLocalContextText: %v", err)
	}
	got := buf.String()

	if strings.HasPrefix(strings.TrimSpace(got), "{") {
		t.Fatalf("expected human-readable text, got JSON:\n%s", got)
	}
	for _, want := range []string{
		"example.com/proj",
		"Analysis level:  import",
		"Dependencies:    2 module(s) imported",
		"github.com/spf13/cobra@v1.10.2",
		"golang.org/x/mod@v0.36.0",
		"2 package(s), 1 symbol(s)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

// A reachability notice (no stored findings for the analysed closure) must be
// surfaced verbatim so the caller learns which command populates findings —
// absence of analysis is never rendered as a confident "no findings".
func TestPrintLocalContextText_SurfacesReachabilityNotice(t *testing.T) {
	out := sampleLocalContext()
	out.Reachability = &reachabilityOutput{
		Root:       "/home/dev/proj",
		ModulePath: "example.com/proj",
		Notice:     "no stored vulnerability findings for the 2 analysed dependency module(s); run 'kanonarion walk' then 'kanonarion vuln-scan' for these coordinates to populate findings",
		Modules:    []reachabilityModule{},
	}

	var buf bytes.Buffer
	if err := printLocalContextText(out, &buf); err != nil {
		t.Fatalf("printLocalContextText: %v", err)
	}
	got := buf.String()

	if !strings.Contains(got, "Reachability:") {
		t.Errorf("output missing Reachability section:\n%s", got)
	}
	if !strings.Contains(got, out.Reachability.Notice) {
		t.Errorf("reachability notice not surfaced verbatim:\n%s", got)
	}
}

// The seed restriction prints on the text surface, and on the "no stored
// findings" path as well: that is where a narrowing the reader does not know
// about is most easily read as "the store holds nothing".
func TestPrintLocalContextText_StatesTheSeedRestriction(t *testing.T) {
	out := sampleLocalContext()
	out.Reachability = &reachabilityOutput{
		Root:            "/home/dev/proj",
		ModulePath:      "example.com/proj",
		SeedRestriction: "seed restricted to stored records measured in this tree's own frame (rooted at example.com/proj) or in the isolated frame; records measured in another consumer's build were not read",
		Notice:          "no stored vulnerability findings for the 2 module(s) of this build the store holds a record for",
		Modules:         []reachabilityModule{},
	}

	var buf bytes.Buffer
	if err := printLocalContextText(out, &buf); err != nil {
		t.Fatalf("printLocalContextText: %v", err)
	}
	got := buf.String()

	if !strings.Contains(got, out.Reachability.SeedRestriction) {
		t.Errorf("seed restriction not stated:\n%s", got)
	}
	if !strings.Contains(got, out.Reachability.Notice) {
		t.Errorf("notice dropped when a restriction is stated:\n%s", got)
	}
}

// An analysed reachability result with affected modules renders each finding's
// CVE id and verdict rather than collapsing to an empty/clean summary.
func TestPrintLocalContextText_RendersReachabilityFindings(t *testing.T) {
	out := sampleLocalContext()
	out.Reachability = &reachabilityOutput{
		Modules: []reachabilityModule{
			{
				Path:    "golang.org/x/mod",
				Version: "v0.36.0",
				Findings: []reachabilityFinding{
					{CVEID: "GO-2024-0001", Verdict: "reachable"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := printLocalContextText(out, &buf); err != nil {
		t.Fatalf("printLocalContextText: %v", err)
	}
	got := buf.String()

	for _, want := range []string{"GO-2024-0001", "reachable"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, got)
		}
	}
}

// -- test scope on the working-tree answer --

// localScopeSample is a working-tree answer with one production-only
// dependency and one reached only from _test.go files.
func localScopeSample(level string, testsExcluded bool) localContextOutput {
	out := localContextOutput{
		Workspace: localWorkspaceInfo{
			Root:          "/home/dev/proj",
			Module:        "example.com/proj",
			VersionID:     "local-abc123",
			AnalysisLevel: level,
			TestsExcluded: testsExcluded,
		},
		Dependencies: []localImportedModule{
			{
				Path:             "example.com/prod",
				Version:          "v1.0.0",
				ImportedPackages: []string{"example.com/prod"},
				UsedSymbols:      []string{"example.com/prod.Run"},
			},
			{
				Path:             "example.com/testonly",
				Version:          "v2.0.0",
				ImportedPackages: []string{"example.com/testonly"},
				UsedSymbols:      []string{"example.com/testonly.Helper"},
				TestOnly:         true,
			},
		},
	}
	if testsExcluded {
		out.Dependencies = out.Dependencies[:1]
	}
	return out
}

func renderLocal(t *testing.T, out localContextOutput) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printLocalContextText(out, &buf); err != nil {
		t.Fatalf("printLocalContextText: %v", err)
	}
	return buf.String()
}

// The scope is stated on every answer, narrowed or not. A reader cannot tell a
// tree with no test-scope users from one whose test-scope users were dropped,
// which is the whole reason the line exists.
func TestPrintLocalContextText_StatesTestScopeBothWays(t *testing.T) {
	wide := renderLocal(t, localScopeSample("symbol", false))
	if !strings.Contains(wide, "Test scope:      included") {
		t.Errorf("an unnarrowed answer does not state its scope:\n%s", wide)
	}
	if !strings.Contains(wide, "example.com/testonly@v2.0.0") || !strings.Contains(wide, "[test]") {
		t.Errorf("the test-scope user is not present and tagged:\n%s", wide)
	}
	if strings.Contains(wide, "example.com/prod@v1.0.0  (1 package(s), 1 symbol(s))  [test]") {
		t.Errorf("a production dependency was tagged [test]:\n%s", wide)
	}

	narrow := renderLocal(t, localScopeSample("symbol", true))
	if !strings.Contains(narrow, "Test scope:      excluded") ||
		!strings.Contains(narrow, "--exclude-tests was given") {
		t.Errorf("a narrowed answer does not state the narrowing:\n%s", narrow)
	}
	if strings.Contains(narrow, "example.com/testonly") {
		t.Errorf("a test-scope user survived the narrowing:\n%s", narrow)
	}
}

// The narrowing is stated even when the tree had no test-scope user to drop:
// that answer is otherwise byte-identical to the unnarrowed one.
func TestPrintLocalContextText_StatesTheNarrowingWhenNothingWasDropped(t *testing.T) {
	out := localScopeSample("import", true)
	got := renderLocal(t, out)
	if !strings.Contains(got, "Test scope:      excluded") {
		t.Errorf("the narrowing is unstated when nothing was dropped:\n%s", got)
	}
	if !strings.Contains(got, "Dependencies:    1 module(s) imported") {
		t.Errorf("unexpected dependency line:\n%s", got)
	}
}

// The count line names what was counted. Symbol level counts references, and a
// blank import is imported while referencing nothing — the word "imported"
// there describes a set the answer deliberately excludes.
func TestPrintLocalContextText_CountVerbMatchesTheAnalysisLevel(t *testing.T) {
	symbol := renderLocal(t, localScopeSample("symbol", false))
	if !strings.Contains(symbol, "Dependencies:    2 module(s) referenced") {
		t.Errorf("symbol level does not count references:\n%s", symbol)
	}
	if strings.Contains(symbol, "module(s) imported") {
		t.Errorf("symbol level still claims \"imported\":\n%s", symbol)
	}
	imports := renderLocal(t, localScopeSample("import", false))
	if !strings.Contains(imports, "Dependencies:    2 module(s) imported") {
		t.Errorf("import level does not count imports:\n%s", imports)
	}
}

// Both derived scope fields are emitted at their zero. An absent key reads as
// "not measured", which is a different fact from "tests were included" and
// "production code reaches this module".
func TestLocalContextJSON_ScopeFieldsAreEmittedAtFalse(t *testing.T) {
	out := localScopeSample("symbol", false)
	ws := sectionKeys(t, out.Workspace)
	if v := requireKey(t, ws, "tests_excluded",
		"an absent scope leaves the reader unable to tell a wide answer from a narrowed one"); v != false {
		t.Errorf("tests_excluded = %v, want false", v)
	}
	dep := sectionKeys(t, out.Dependencies[0])
	if v := requireKey(t, dep, "test_only",
		"an absent tag reads as unmeasured, not as reached by production code"); v != false {
		t.Errorf("test_only = %v, want false", v)
	}
	tagged := sectionKeys(t, out.Dependencies[1])
	if v := requireKey(t, tagged, "test_only", "the tag is the machine-readable half of [test]"); v != true {
		t.Errorf("test_only = %v, want true", v)
	}
}
