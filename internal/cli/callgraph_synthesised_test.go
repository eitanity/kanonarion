package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

func synthesisedCGRecord(t *testing.T) cgdomain.CallGraphRecord {
	t.Helper()
	rec := makeCGRecord(t)
	rec.AnalysisSource = cgdomain.AnalysisSourceModuleZip
	rec.ArtefactIdentity = "zip:h1:abc="
	rec.SynthesisedGoMod = cgdomain.SynthesisedGoMod{
		ModulePath:  "example.com/cg",
		GoDirective: "1.16",
	}
	return rec
}

// TestRunCallGraphShow_ReportsSynthesisedGoMod: the analysis read the published
// bytes PLUS a file kanonarion invented, and a provenance line that did not say
// so would claim the graph describes the artefact it was sealed against.
func TestRunCallGraphShow_ReportsSynthesisedGoMod(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := makeCGCoord(t)
	uc.AddRecord(coord, cgapp.PipelineVersion, synthesisedCGRecord(t))

	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 50, limitEdges: 100}, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"synthesised go.mod", "example.com/cg", "1.16"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
}

// TestRunCallGraphShow_OmitsSynthesisWhenTreeWasPublished: the note must not
// appear on a record analysed as published, or it would stop meaning anything.
func TestRunCallGraphShow_OmitsSynthesisWhenTreeWasPublished(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := makeCGCoord(t)
	rec := makeCGRecord(t)
	rec.AnalysisSource = cgdomain.AnalysisSourceModuleZip
	uc.AddRecord(coord, cgapp.PipelineVersion, rec)

	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 50, limitEdges: 100}, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "synthesised") {
		t.Errorf("a record analysed as published claims a synthesised go.mod:\n%s", buf.String())
	}
}

// TestCallGraphShowJSON_CarriesSynthesisedGoMod: a machine consumer has to be
// able to see that the analysed tree was not the published tree, and the field
// is absent rather than empty when it was.
func TestCallGraphShowJSON_CarriesSynthesisedGoMod(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := makeCGCoord(t)
	uc.AddRecord(coord, cgapp.PipelineVersion, synthesisedCGRecord(t))

	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 50, limitEdges: 100}, true, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{`"synthesised_go_mod"`, `"go_directive": "1.16"`, `"module_path": "example.com/cg"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("JSON does not carry %s:\n%s", want, buf.String())
		}
	}

	uc2 := testfakes.NewFakeQueryCallGraph()
	uc2.AddRecord(coord, cgapp.PipelineVersion, makeCGRecord(t))
	var plain bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 50, limitEdges: 100}, true, uc2, &plain); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(plain.String(), "synthesised_go_mod") {
		t.Errorf("a record analysed as published emits the field:\n%s", plain.String())
	}
}

// TestHistoryOrigin_NamesTheInventedFile: the history view reports what a
// generation was computed from, and the artefact alone is not it.
func TestHistoryOrigin_NamesTheInventedFile(t *testing.T) {
	got := historyOrigin(synthesisedCGRecord(t))
	if !strings.Contains(got, "zip:h1:abc=") {
		t.Errorf("origin %q dropped the artefact identity", got)
	}
	if !strings.Contains(got, "synthesised go.mod") {
		t.Errorf("origin %q does not say the tree was not the published tree", got)
	}
}

// TestRunCallGraphHistory_SaysWhyEachGenerationExists: the history view is where
// an operator lands holding N generations of one analysis, and until the record
// stated it the only thing left to read intent out of was the directory the run
// happened to stand in.
func TestRunCallGraphHistory_SaysWhyEachGenerationExists(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := makeCGCoord(t)

	forced := makeCGRecord(t)
	forced.DerivedBy = cgdomain.DerivationFor(cgdomain.ReuseGateWorktree, true)
	forced.ContentHash = "sha256:forced"
	uc.AddGeneration(coord, cgapp.PipelineVersion, forced)

	// A generation written before the field says nothing, and must not be given a
	// reason it never stated.
	preField := makeCGRecord(t)
	preField.ContentHash = "sha256:prefield"
	uc.AddGeneration(coord, cgapp.PipelineVersion, preField)

	var buf bytes.Buffer
	if err := runCallGraphHistory(context.Background(), coord, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "worktree reuse gate bypassed (--force)") {
		t.Errorf("history does not say the forced generation was forced:\n%s", out)
	}
	if got := strings.Count(out, "derived:"); got != 1 {
		t.Errorf("history printed %d derivation lines for one stated derivation:\n%s", got, out)
	}
}
