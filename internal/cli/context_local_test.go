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
