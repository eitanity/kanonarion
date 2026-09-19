package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// remedyTestCoordinate is a published coordinate, so ForcedReanalysisInstruction
// renders the `callgraph ... --force` form the fields that keep a re-analysis
// line print.
func remedyTestCoordinate(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return coord
}

// TestToolchainRemedy_OffersNoReAnalysis is the ticket's defect.
//
// Re-analysing under toolchain A appends another A record. The B record stays,
// the set of toolchains present is unchanged, and the gate fires on exactly that
// set — so the line could never resolve what it was printed against. One store
// answered 28 forced re-analyses across 13.5 hours and refused after every one.
//
// The assertion is on the LINES rather than on the rendered string, because the
// lines are the contract: they are what a reader copies, and what the CLI
// contract test pushes back through the argument parser.
func TestToolchainRemedy_OffersNoReAnalysis(t *testing.T) {
	t.Parallel()
	coord := remedyTestCoordinate(t)
	conflict := domain.CallGraphConflict{
		Coordinate:      coord,
		PipelineVersion: "0.7.0",
		Field:           domain.ConflictFieldToolchain,
		Values:          []string{"go1.26.5", "go1.27.1"},
	}
	got := conflict.Remedy().Lines
	want := []string{
		"kanonarion callgraph-show example.com/mod@v1.0.0 --history",
		"kanonarion callgraph-show example.com/mod@v1.0.0 --toolchain go1.26.5",
	}
	if len(got) != len(want) {
		t.Fatalf("toolchain remedy prints %d line(s), want %d:\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("toolchain remedy line %d = %q, want %q", i, got[i], want[i])
		}
	}
	// Named explicitly as well as counted, so a future line that happens to keep
	// the count at two cannot reintroduce the one measurement that cannot help.
	for _, line := range got {
		if strings.Contains(line, "--force") {
			t.Errorf("toolchain remedy still offers a re-analysis: %q", line)
		}
	}
	if strings.Contains(conflict.Error(), domain.ForcedReanalysisInstruction(coord, "")) {
		t.Errorf("the rendered toolchain refusal still names a forced re-analysis:\n%s", conflict.Error())
	}
}

// TestToolchainRemedy_NamesWhereThePreferenceLives.
//
// Dropping the re-analysis line leaves --toolchain as the only route through,
// and --toolchain is per invocation: a reader who follows it on one command
// meets the same refusal on the next. The lead is where the reader is told the
// choice can be recorded once, so the route out of "forever" has to be named
// there or it is not named at all.
//
// It names a REAL toolchain, and the same one the --toolchain line names. A
// template is not a remedy: the values that disagreed are in hand, printing
// "<version>" where one of them belongs makes the sentence something the reader
// has to translate before running, and two renderings of the same choice are two
// things that can drift.
func TestToolchainRemedy_NamesWhereThePreferenceLives(t *testing.T) {
	t.Parallel()
	conflict := domain.CallGraphConflict{
		Coordinate:      remedyTestCoordinate(t),
		PipelineVersion: "0.7.0",
		Field:           domain.ConflictFieldToolchain,
		Values:          []string{"go1.26.5", "go1.27.1"},
	}
	remedy := conflict.Remedy()
	const want = "kanonarion config set callgraph.toolchain go1.26.5"
	if !strings.Contains(remedy.Lead, want) {
		t.Errorf("the toolchain remedy's lead does not name %q:\n%s", want, remedy.Lead)
	}
	if strings.Contains(remedy.Lead, "<") {
		t.Errorf("the toolchain remedy's lead still prints a template:\n%s", remedy.Lead)
	}
	// The selector in the prose and the selector on the line are the same value,
	// read from the same place, so a reader told to record one toolchain is not
	// then shown another.
	selectorLine := ""
	for _, l := range remedy.Lines {
		if strings.Contains(l, "--toolchain ") {
			selectorLine = l
		}
	}
	if selectorLine == "" {
		t.Fatalf("no --toolchain line to agree with:\n%v", remedy.Lines)
	}
	sel := selectorLine[strings.LastIndex(selectorLine, " ")+1:]
	if !strings.Contains(remedy.Lead, "callgraph.toolchain "+sel) {
		t.Errorf("the lead records a different toolchain from the one --toolchain names (%q):\n%s", sel, remedy.Lead)
	}
}

// TestToolchainRemedy_SaysNothingAboutRecordingWhatCannotBeNamed.
//
// A "GOROOT ..." identity is a directory whose toolchain was never recorded, so
// there is no version to pass to --toolchain and no version to record. The
// selector line is already omitted in that case; the sentence about recording it
// goes with it rather than falling back to a placeholder, which is the same rule
// read the other way.
func TestToolchainRemedy_SaysNothingAboutRecordingWhatCannotBeNamed(t *testing.T) {
	t.Parallel()
	conflict := domain.CallGraphConflict{
		Coordinate:      remedyTestCoordinate(t),
		PipelineVersion: "0.7.0",
		Field:           domain.ConflictFieldToolchain,
		Values:          []string{"GOROOT /usr/local/go", "GOROOT /opt/go"},
	}
	remedy := conflict.Remedy()
	for _, line := range remedy.Lines {
		if strings.Contains(line, "--toolchain") {
			t.Fatalf("a remedy offered --toolchain with no selectable version: %q", line)
		}
	}
	if strings.Contains(remedy.Lead, "callgraph.toolchain") {
		t.Errorf("the lead offers to record a toolchain none of the records names:\n%s", remedy.Lead)
	}
	if remedy.Lead == "" || len(remedy.Lines) == 0 {
		t.Errorf("the refusal was left with no remedy at all: %+v", remedy)
	}
}

// TestOtherConflictFields_KeepTheirRemedies is the control on the change above.
//
// The toolchain is the ONE field where no further measurement exists to take.
// Every other field either has one or says plainly that it has none, and
// removing the toolchain's line must not quietly remove theirs: an artefact
// identity is settled by fetching the bytes again, and two graphs at a
// completeness with a rung above it are settled by reaching that rung.
func TestOtherConflictFields_KeepTheirRemedies(t *testing.T) {
	t.Parallel()
	coord := remedyTestCoordinate(t)
	forced := domain.ForcedReanalysisInstruction(coord, "")

	tests := []struct {
		name           string
		conflict       domain.CallGraphConflict
		wantLines      []string
		wantReanalysis bool
	}{
		{
			name: "an unreadable source names the sources this build can read",
			conflict: domain.CallGraphConflict{
				Coordinate: coord, PipelineVersion: "0.7.0",
				Field: domain.ConflictFieldAnalysisSource,
			},
			wantLines: []string{
				"kanonarion callgraph-show example.com/mod@v1.0.0 --history",
				"kanonarion callgraph-show example.com/mod@v1.0.0 --source zip",
			},
			wantReanalysis: false,
		},
		{
			name: "two artefact identities for one pinned version are settled by fetching again",
			conflict: domain.CallGraphConflict{
				Coordinate: coord, PipelineVersion: "0.7.0",
				Field: domain.ConflictFieldArtefactIdentity,
			},
			wantLines: []string{
				"kanonarion callgraph-show example.com/mod@v1.0.0 --history",
				"kanonarion fetch example.com/mod@v1.0.0",
				forced,
			},
			wantReanalysis: true,
		},
		{
			name: "two graphs at a completeness with a rung above it are settled by reaching it",
			conflict: domain.CallGraphConflict{
				Coordinate: coord, PipelineVersion: "0.7.0",
				Field:        domain.ConflictFieldCallGraph,
				Completeness: domain.CompletenessMetadataOnly,
			},
			wantLines: []string{
				"kanonarion callgraph-show example.com/mod@v1.0.0 --diff",
				"kanonarion callgraph-show example.com/mod@v1.0.0 --history",
				forced,
			},
			wantReanalysis: true,
		},
		{
			name: "two graphs at the top rung say plainly that nothing clears them",
			conflict: domain.CallGraphConflict{
				Coordinate: coord, PipelineVersion: "0.7.0",
				Field:        domain.ConflictFieldCallGraph,
				Completeness: domain.CompletenessBuiltWithBodies,
			},
			wantLines: []string{
				"kanonarion callgraph-show example.com/mod@v1.0.0 --diff",
				"kanonarion callgraph-show example.com/mod@v1.0.0 --history",
			},
			wantReanalysis: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.conflict.Remedy().Lines
			if len(got) != len(tc.wantLines) {
				t.Fatalf("%s prints %d line(s), want %d:\n%v",
					tc.conflict.Field, len(got), len(tc.wantLines), got)
			}
			for i := range tc.wantLines {
				if got[i] != tc.wantLines[i] {
					t.Errorf("%s remedy line %d = %q, want %q",
						tc.conflict.Field, i, got[i], tc.wantLines[i])
				}
			}
			named := false
			for _, line := range got {
				if line == forced {
					named = true
				}
			}
			if named != tc.wantReanalysis {
				t.Errorf("%s names a forced re-analysis = %v, want %v:\n%v",
					tc.conflict.Field, named, tc.wantReanalysis, got)
			}
		})
	}
}
