package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// analyserShowRecord is a minimal served record stating one analyser identity.
func analyserShowRecord(t *testing.T, id cgdomain.AnalyserIdentity) cgdomain.CallGraphRecord {
	t.Helper()
	return cgdomain.CallGraphRecord{
		Coordinate:    makeCGCoord(t),
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Completeness:  cgdomain.CompletenessBuiltWithBodies,
		Nodes:         []cgdomain.CallNode{{ID: "example.com/cg.Main", Module: "example.com/cg", Package: "example.com/cg", Symbol: "Main"}},
		NodeCount:     1,
		Analyser:      id,
	}
}

func showText(t *testing.T, uc QueryCallGraphUseCase) string {
	t.Helper()
	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 0, limitEdges: 0}, false, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow: %v", err)
	}
	return buf.String()
}

func showJSON(t *testing.T, uc QueryCallGraphUseCase) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 0, limitEdges: 0}, true, uc, &buf); err != nil {
		t.Fatalf("runCallGraphShow --json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding the document: %v\n%s", err, buf.String())
	}
	return doc
}

// TestCallGraphShow_NamesTheAnalyserOnEveryRecord pins that the library that
// parsed a module is printed beside the algorithm that walked the result — on
// every record, including the ones that name none. A reader who sees no line
// reads it as "the usual one", which is exactly the reading the axis exists to
// prevent.
func TestCallGraphShow_NamesTheAnalyserOnEveryRecord(t *testing.T) {
	for _, tc := range []struct {
		name  string
		id    cgdomain.AnalyserIdentity
		wants []string
	}{
		{
			name:  "observed",
			id:    cgdomain.ObservedAnalyser("v0.49.0"),
			wants: []string{"analyser: golang.org/x/tools v0.49.0"},
		},
		{
			name:  "inferred",
			id:    cgdomain.InferredAnalyser("v0.47.0"),
			wants: []string{"analyser: golang.org/x/tools v0.47.0", "INFERRED"},
		},
		{
			name:  "unrecorded",
			id:    cgdomain.AnalyserIdentity{},
			wants: []string{"analyser: not recorded"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc := testfakes.NewFakeQueryCallGraph()
			uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, analyserShowRecord(t, tc.id))
			out := showText(t, uc)
			for _, want := range tc.wants {
				if !strings.Contains(out, want) {
					t.Errorf("output does not contain %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestCallGraphShow_InferredNeverPrintsAsObserved is the same never-identical
// rule, measured at the surface a person actually reads.
func TestCallGraphShow_InferredNeverPrintsAsObserved(t *testing.T) {
	lineFor := func(id cgdomain.AnalyserIdentity) string {
		uc := testfakes.NewFakeQueryCallGraph()
		uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, analyserShowRecord(t, id))
		for _, line := range strings.Split(showText(t, uc), "\n") {
			if strings.Contains(line, "analyser:") {
				return line
			}
		}
		t.Fatal("no analyser line in the output")
		return ""
	}
	observed := lineFor(cgdomain.ObservedAnalyser("v0.49.0"))
	inferred := lineFor(cgdomain.InferredAnalyser("v0.49.0"))
	if observed == inferred {
		t.Errorf("an observed and an inferred v0.49.0 print the same line: %q", observed)
	}
}

// TestCallGraphShow_ReportsAnAnalyserDisagreement is decision 4 at the surface.
// It never changes which generation answers — the served record is the same one
// either way — it states that the generations behind it were not parsed alike.
func TestCallGraphShow_ReportsAnAnalyserDisagreement(t *testing.T) {
	coord := makeCGCoord(t)
	uc := testfakes.NewFakeQueryCallGraph()
	served := analyserShowRecord(t, cgdomain.ObservedAnalyser("v0.49.0"))
	uc.AddRecord(coord, cgapp.PipelineVersion, served)
	uc.AddGeneration(coord, cgapp.PipelineVersion, analyserShowRecord(t, cgdomain.InferredAnalyser("v0.47.0")))
	uc.AddGeneration(coord, cgapp.PipelineVersion, served)

	out := showText(t, uc)
	if !strings.Contains(out, "notice:") || !strings.Contains(out, "not all parsed by the same golang.org/x/tools") {
		t.Errorf("no disagreement notice in:\n%s", out)
	}
	if !strings.Contains(out, "v0.47.0") || !strings.Contains(out, "v0.49.0") {
		t.Errorf("the notice does not name both analysers:\n%s", out)
	}

	// Everything the person is told, the document carries — as fields, not as the
	// sentence.
	doc := showJSON(t, uc)
	raw, ok := doc["analyser_disagreement"]
	if !ok {
		t.Fatalf("the document carries no analyser_disagreement: %v", doc)
	}
	disagreement, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("analyser_disagreement is %T, want an object", raw)
	}
	analysers, ok := disagreement["analysers"].([]any)
	if !ok || len(analysers) != 2 {
		t.Fatalf("analysers = %v, want two entries", disagreement["analysers"])
	}
	first, ok := analysers[0].(map[string]any)
	if !ok {
		t.Fatalf("the first analyser is %T, want an object", analysers[0])
	}
	if first["version"] != "v0.47.0" || first["provenance"] != "inferred" || first["inferred"] != true {
		t.Errorf("the inferred entry is %v, want v0.47.0 marked inferred", first)
	}
}

// TestCallGraphShow_SaysNothingWhenTheAnalysersAgree is the other half, and the
// one that keeps the statement worth reading. A store written by a single binary
// gains no line anywhere.
func TestCallGraphShow_SaysNothingWhenTheAnalysersAgree(t *testing.T) {
	for _, tc := range []struct {
		name        string
		generations []cgdomain.AnalyserIdentity
	}{
		{"one generation", []cgdomain.AnalyserIdentity{cgdomain.ObservedAnalyser("v0.49.0")}},
		{"two at one version", []cgdomain.AnalyserIdentity{
			cgdomain.ObservedAnalyser("v0.49.0"), cgdomain.ObservedAnalyser("v0.49.0")}},
		{"one version, two strengths", []cgdomain.AnalyserIdentity{
			cgdomain.ObservedAnalyser("v0.49.0"), cgdomain.InferredAnalyser("v0.49.0")}},
		{"nothing recorded anywhere", []cgdomain.AnalyserIdentity{{}, {}}},
		{"one names a version, the rest say nothing", []cgdomain.AnalyserIdentity{
			cgdomain.ObservedAnalyser("v0.49.0"), {}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coord := makeCGCoord(t)
			uc := testfakes.NewFakeQueryCallGraph()
			uc.AddRecord(coord, cgapp.PipelineVersion, analyserShowRecord(t, tc.generations[0]))
			for _, id := range tc.generations {
				uc.AddGeneration(coord, cgapp.PipelineVersion, analyserShowRecord(t, id))
			}
			if out := showText(t, uc); strings.Contains(out, "not all parsed by the same golang.org/x/tools") {
				t.Errorf("a disagreement was reported where there is none:\n%s", out)
			}
			if doc := showJSON(t, uc); doc["analyser_disagreement"] != nil {
				t.Errorf("the document carries a disagreement where there is none: %v", doc["analyser_disagreement"])
			}
		})
	}
}

// TestCallGraphShow_JSONFieldsTheAnalyser pins that the document states the
// version and the strength as separate values, so a consumer branches on a
// field rather than parsing a sentence.
func TestCallGraphShow_JSONFieldsTheAnalyser(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion,
		analyserShowRecord(t, cgdomain.InferredAnalyser("v0.47.0")))

	doc := showJSON(t, uc)
	analyser, ok := doc["analyser"].(map[string]any)
	if !ok {
		t.Fatalf("analyser = %v, want an object present on every record", doc["analyser"])
	}
	if analyser["module"] != cgdomain.AnalyserModulePath {
		t.Errorf("module = %v, want %q", analyser["module"], cgdomain.AnalyserModulePath)
	}
	if analyser["version"] != "v0.47.0" {
		t.Errorf("version = %v, want v0.47.0", analyser["version"])
	}
	if analyser["provenance"] != "inferred" || analyser["inferred"] != true {
		t.Errorf("provenance = %v / inferred = %v, want inferred", analyser["provenance"], analyser["inferred"])
	}
}
