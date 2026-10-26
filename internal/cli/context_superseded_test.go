package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	"code.eitanity.com/kanonarion/internal/coordinate"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	exapp "code.eitanity.com/kanonarion/internal/example/application"
	exdomain "code.eitanity.com/kanonarion/internal/example/domain"
	licapp "code.eitanity.com/kanonarion/internal/license/application"
	licdomain "code.eitanity.com/kanonarion/internal/license/domain"
)

// renderedSections is a document's compact text, full text and JSON.
func renderedSections(t *testing.T, out contextOutput) (summary, full, doc string) {
	t.Helper()
	var s, f bytes.Buffer
	if err := printContextSummary(out, &s); err != nil {
		t.Fatal(err)
	}
	if err := printContextFull(out, &f); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return s.String(), f.String(), string(raw)
}

// requireSuperseded checks a superseded section names the served pipeline, the
// held ones and the remedy, in text and in JSON.
func requireSuperseded(t *testing.T, status, line string, out contextOutput, label string, want ...string) {
	t.Helper()
	if status != sectionStatusSuperseded {
		t.Fatalf("status = %q, want superseded", status)
	}
	for _, w := range want {
		if !strings.Contains(line, w) {
			t.Errorf("statement lacks %q:\n%s", w, line)
		}
	}
	summary, full, doc := renderedSections(t, out)
	if !strings.Contains(summary, label+"(superseded — "+line+")") {
		t.Errorf("summary does not print the statement:\n%s", summary)
	}
	if !strings.Contains(full, "(superseded — "+line+")") {
		t.Errorf("full text does not print the statement:\n%s", full)
	}
	escaped, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, `"status":"superseded"`) || !strings.Contains(doc, `"error":`+string(escaped)) {
		t.Errorf("JSON does not carry superseded with the statement:\n%s", doc)
	}
}

func TestContextLicence_SupersededPipelineReadsSuperseded(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.1.0")
	uc := testfakes.NewFakeQueryLicense()
	uc.AddRecord(coord, "1.2.0", licdomain.LicenseRecord{})
	uc.AddRecord(coord, "1.3.0", licdomain.LicenseRecord{})

	got := buildLicense(ctx, coord, uc, nil)
	requireSuperseded(t, got.Status, got.Error, contextOutput{License: got}, "  License:         ",
		"serves pipeline "+licapp.PipelineVersion, "at pipeline 1.2.0, 1.3.0", "Re-extract it:\n  kanonarion license example.com/mod@v1.1.0")

	// Nothing held at any pipeline still reads not_run.
	if got := buildLicense(ctx, mustCoord(t, "example.com/absent", "v1.0.0"), uc, nil); got.Status != sectionStatusNotRun || got.Error != "" {
		t.Errorf("absent coordinate = %+v, want not_run", got)
	}
	// A served record answers as it did, whatever else is held.
	uc.AddRecord(coord, licapp.PipelineVersion, licdomain.LicenseRecord{PrimarySPDX: "MIT", OverallStatus: licdomain.LicenseStatusDetected})
	if got := buildLicense(ctx, coord, uc, nil); got.Status != licdomain.LicenseStatusDetected.String() || got.SPDX != "MIT" {
		t.Errorf("current record = %+v", got)
	}
}

// A listing that fails leaves not_run: less precise, never a fault of its own.
func TestContextLicence_UnreadablePipelinesLeaveNotRun(t *testing.T) {
	coord := mustCoord(t, "example.com/mod", "v1.1.0")
	if got, ok := supersededPipelines(context.Background(), failingPipelines{}, coord, "1.4.0"); ok || got != nil {
		t.Errorf("supersededPipelines over a failed read = %v, %v", got, ok)
	}
}

type failingPipelines struct{}

func (failingPipelines) PipelinesHeld(context.Context, coordinate.ModuleCoordinate) ([]string, error) {
	return nil, context.Canceled
}

// The examples section can meet a superseded record: its reads key on the
// pipeline, as the licence's do.
func TestContextExamples_SupersededPipelineReadsSuperseded(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.1.0")
	uc := testfakes.NewFakeQueryExamples()
	uc.AddRecord(coord, "0.2.0", exdomain.ExampleRecord{})

	got := buildExamples(ctx, coord, uc, true, "")
	requireSuperseded(t, got.Status, got.Error, contextOutput{Examples: got}, "  Examples:        ",
		"serves pipeline "+exapp.PipelineVersion, "at pipeline 0.2.0", "Re-extract it:\n  kanonarion examples example.com/mod@v1.1.0")

	if got := buildExamples(ctx, mustCoord(t, "example.com/absent", "v1.0.0"), uc, true, ""); got.Status != sectionStatusNotRun {
		t.Errorf("absent coordinate = %+v, want not_run", got)
	}
	uc.AddRecord(coord, exapp.PipelineVersion, exdomain.ExampleRecord{OverallStatus: exdomain.ExampleStatusFound})
	if got := buildExamples(ctx, coord, uc, true, ""); got.Status != "Found" {
		t.Errorf("current record = %+v", got)
	}
}

// The dependencies section cannot meet a superseded record: no walk read keys on
// a pipeline, so a walk taken at any pipeline answers.
func TestContextDependencies_WalkAtAnyPipelineAnswers(t *testing.T) {
	ctx := context.Background()
	library := libraryWalk(t)
	library.Graph.PipelineVersion = "0.0.1"
	store := frameStore(library)

	got := buildDependencies(ctx, libCoord(t), store, basisWalk{})
	if got.Status != "succeeded" || got.Count != 2 || got.WalkID != library.ID {
		t.Errorf("a walk at an old pipeline = %+v, want it to answer", got)
	}
}

// callGraphMissFake holds coord as UnservedCoordinates states it.
func callGraphMissFake(u ...cgports.UnservedCoordinate) *testfakes.FakeQueryCallGraph {
	f := testfakes.NewFakeQueryCallGraph()
	f.Unserved = u
	return f
}

func TestContextCallGraph_SupersededPipelineReadsSuperseded(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "golang.org/x/mod", "v0.37.0")
	uc := callGraphMissFake(cgports.UnservedCoordinate{Coordinate: coord, Pipelines: []string{"0.5.0", "0.6.0"}})

	cg, capab := buildCallGraph(ctx, coord, uc, false, "")
	out := contextOutput{CallGraph: cg, Capability: capab}
	want := []string{"serves pipeline " + cgapp.PipelineVersion, "at pipeline 0.5.0, 0.6.0",
		"Re-analyse it:\n  kanonarion fetch golang.org/x/mod@v0.37.0 && kanonarion callgraph golang.org/x/mod@v0.37.0"}
	requireSuperseded(t, cg.Status, cg.Error, out, "  Call Graph:      ", want...)
	requireCapabilityPointsAtCallGraph(t, capab, out, "superseded")
}

// requireCapabilityPointsAtCallGraph checks a capability section with no answer
// names its status and leaves the statement to call_graph, in text and JSON.
func requireCapabilityPointsAtCallGraph(t *testing.T, capab contextCapability, out contextOutput, words string) {
	t.Helper()
	if capab.Error != "" || capab.contextCapabilityAnswer != nil {
		t.Errorf("capability = %+v; want a status and no statement or answer", capab)
	}
	raw, err := json.Marshal(capab)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"error"`) {
		t.Errorf("capability JSON repeats the statement: %s", raw)
	}
	summary, full, _ := renderedSections(t, out)
	if want := "(" + words + " — see Call Graph)"; !strings.Contains(summary, "  Capability:      "+want+"\n") ||
		!strings.Contains(full, "=== Capability ===\n"+want+"\n") {
		t.Errorf("capability text lacks %q:\n%s\n%s", want, summary, full)
	}
}

// A working tree's remedy is the tree's own re-ingestion.
func TestContextCallGraph_SupersededWorkingTreeNamesLocal(t *testing.T) {
	coord, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	uc := callGraphMissFake(cgports.UnservedCoordinate{Coordinate: coord, Pipelines: []string{"0.10.0"}, AnalysisRoot: "/src/app"})
	cg, _ := buildCallGraph(context.Background(), coord, uc, false, "")
	if cg.Status != sectionStatusSuperseded || !strings.HasSuffix(cg.Error, "Re-analyse it:\n  kanonarion local /src/app") {
		t.Errorf("working tree = %+v", cg)
	}
}

// Held at the served pipeline under another frame stays other_frame; held
// nowhere stays not_run. The capability section follows both.
func TestContextCallGraph_OtherFrameAndNotRunAreUnchanged(t *testing.T) {
	ctx := context.Background()
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	uc := callGraphMissFake(cgports.UnservedCoordinate{
		Coordinate: coord, Pipelines: []string{"0.5.0", cgapp.PipelineVersion},
		Frames: []cgdomain.BuildFrame{frameMissWasm},
	})
	cg, capab := buildCallGraph(ctx, coord, uc, false, "")
	if cg.Status != sectionStatusOtherFrame || capab.Status != sectionStatusOtherFrame ||
		strings.Join(capab.HeldFrames, ",") != "wasip1/wasm" || strings.Join(capab.ReadWith, ",") != "--target wasip1/wasm" {
		t.Errorf("other frame = %+v / %+v", cg, capab)
	}
	requireCapabilityPointsAtCallGraph(t, capab, contextOutput{CallGraph: cg, Capability: capab}, "held under wasip1/wasm")

	for _, u := range [][]cgports.UnservedCoordinate{nil, {{Coordinate: coord}}} {
		cg, capab = buildCallGraph(ctx, coord, callGraphMissFake(u...), false, "")
		if cg.Status != sectionStatusNotRun || capab.Status != sectionStatusNotRun || capab.Error != "" {
			t.Errorf("held nowhere = %+v / %+v", cg, capab)
		}
	}
	requireCapabilityPointsAtCallGraph(t, capab, contextOutput{CallGraph: cg, Capability: capab}, "not run")
}

// A read error is carried to the capability section as its status.
func TestContextCapability_FollowsReadError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.Err = context.DeadlineExceeded
	cg, capab := buildCallGraph(context.Background(), mustCoord(t, "example.com/mod", "v1.0.0"), uc, false, "")
	if cg.Status != sectionStatusReadError || cg.Error == "" || capab.Status != sectionStatusReadError {
		t.Errorf("read error = %+v / %+v", cg, capab)
	}
	requireCapabilityPointsAtCallGraph(t, capab, contextOutput{CallGraph: cg, Capability: capab}, "failed")
}

// Every --full section that can be superseded prints its statement: a status
// word alone tells the reader neither the pipelines nor the remedy.
func TestContextFull_EverySupersededSectionPrintsItsStatement(t *testing.T) {
	out := contextOutput{
		Interface:       contextInterface{Status: sectionStatusSuperseded, Error: "interface statement\n  kanonarion interface m@v1"},
		License:         contextLicense{Status: sectionStatusSuperseded, Error: "licence statement"},
		CallGraph:       contextCallGraph{Status: sectionStatusSuperseded, Error: "call graph statement"},
		Capability:      contextCapability{Status: sectionStatusSuperseded},
		Examples:        contextExamples{Status: sectionStatusSuperseded, Error: "examples statement"},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusSuperseded, Error: "vulnerability statement\n  kanonarion vuln-scan w"},
	}
	_, full, _ := renderedSections(t, out)
	for heading, statement := range map[string]string{
		"=== Interface ===":       out.Interface.Error,
		"=== License ===":         out.License.Error,
		"=== Call Graph ===":      out.CallGraph.Error,
		"=== Capability ===":      "(superseded — see Call Graph)",
		"=== Examples ===":        out.Examples.Error,
		"=== Vulnerabilities ===": out.Vulnerabilities.Error,
	} {
		_, section, _ := strings.Cut(full, heading+"\n")
		section, _, _ = strings.Cut(section, "\n=== ")
		if !strings.Contains(section, statement) {
			t.Errorf("%s does not print its statement %q:\n%s", heading, statement, section)
		}
	}
}

// Every non-answer status of every --full section prints the statement or
// remedy the compact line carries for it; the set-aside generations a
// vulnerability section carries are named under it.
func TestContextFull_EveryNonAnswerStatusPrintsItsStatement(t *testing.T) {
	cmds := contextCommands{
		Interface: "kanonarion interface-show m@v1", CallGraph: "kanonarion callgraph-show m@v1",
		Examples: "kanonarion examples-show m@v1 <name>", Vulnerabilities: "kanonarion vuln-show m@v1",
		License: "kanonarion license m@v1",
	}
	aside := []setAsideJSON{{Kind: "vulnerability", Coordinate: "m@v1", ContentHash: "sha256:aside", Reason: "unreproducible"}}
	for _, tc := range []struct {
		name, heading string
		set           func(*contextOutput)
		want          []string
	}{
		{"verification not_fetched", "Verification", func(o *contextOutput) { o.Verification = contextVerification{Status: sectionStatusNotFetched} }, []string{"(not fetched)"}},
		{"verification read_error", "Verification", func(o *contextOutput) {
			o.Verification = contextVerification{Status: sectionStatusReadError, Error: "verify fault"}
		}, []string{"verify fault"}},
		{"verification set_aside", "Verification", func(o *contextOutput) {
			o.Verification = contextVerification{Status: sectionStatusSetAside, Error: "verify aside"}
		}, []string{"verify aside"}},
		{"verification divergent", "Verification", func(o *contextOutput) {
			o.Verification = contextVerification{Status: sectionStatusDivergent, Error: "divergent fetch records"}
		}, []string{"divergent fetch records"}},
		{"dependencies not_run", "Dependencies", func(o *contextOutput) { o.Dependencies = contextDependencies{Status: sectionStatusNotRun} }, []string{"kanonarion walk m@v1"}},
		{"dependencies not_in_basis_walk", "Dependencies", func(o *contextOutput) {
			o.Dependencies = contextDependencies{Status: sectionStatusNotInWalk, WalkID: "01W"}
		}, []string{"walk 01W does not hold m@v1"}},
		{"dependencies read_error", "Dependencies", func(o *contextOutput) {
			o.Dependencies = contextDependencies{Status: sectionStatusReadError, Error: "walk fault"}
		}, []string{"walk fault"}},
		{"license not_run", "License", func(o *contextOutput) { o.License = contextLicense{Status: sectionStatusNotRun} }, []string{cmds.License}},
		{"license read_error", "License", func(o *contextOutput) { o.License = contextLicense{Status: sectionStatusReadError, Error: "lic fault"} }, []string{"lic fault"}},
		{"license set_aside", "License", func(o *contextOutput) { o.License = contextLicense{Status: sectionStatusSetAside, Error: "lic aside"} }, []string{"lic aside"}},
		{"license superseded", "License", func(o *contextOutput) {
			o.License = contextLicense{Status: sectionStatusSuperseded, Error: "lic superseded"}
		}, []string{"lic superseded"}},
		{"interface not_run", "Interface", func(o *contextOutput) { o.Interface = contextInterface{Status: sectionStatusNotRun} }, []string{cmds.Interface}},
		{"interface read_error", "Interface", func(o *contextOutput) {
			o.Interface = contextInterface{Status: sectionStatusReadError, Error: "iface fault"}
		}, []string{"iface fault"}},
		{"interface superseded", "Interface", func(o *contextOutput) {
			o.Interface = contextInterface{Status: sectionStatusSuperseded, Error: "iface superseded"}
		}, []string{"iface superseded"}},
		{"call graph not_run", "Call Graph", func(o *contextOutput) { o.CallGraph = contextCallGraph{Status: sectionStatusNotRun} }, []string{cmds.CallGraph}},
		{"call graph read_error", "Call Graph", func(o *contextOutput) {
			o.CallGraph = contextCallGraph{Status: sectionStatusReadError, Error: "cg fault"}
		}, []string{"cg fault"}},
		{"call graph other_frame", "Call Graph", func(o *contextOutput) {
			o.CallGraph = contextCallGraph{Status: sectionStatusOtherFrame, HeldFrames: []string{"wasip1/wasm"}, ReadWith: []string{"--target wasip1/wasm"}}
		}, []string{"held under wasip1/wasm — read with --target wasip1/wasm"}},
		{"call graph superseded", "Call Graph", func(o *contextOutput) {
			o.CallGraph = contextCallGraph{Status: sectionStatusSuperseded, Error: "cg superseded"}
		}, []string{"cg superseded"}},
		{"capability not_run", "Capability", func(o *contextOutput) { o.Capability = contextCapability{Status: sectionStatusNotRun} }, []string{"(not run — see Call Graph)"}},
		{"capability read_error", "Capability", func(o *contextOutput) {
			o.Capability = contextCapability{Status: sectionStatusReadError}
		}, []string{"(failed — see Call Graph)"}},
		{"capability other_frame", "Capability", func(o *contextOutput) {
			o.Capability = contextCapability{Status: sectionStatusOtherFrame, HeldFrames: []string{"wasip1/wasm"}, ReadWith: []string{"--target wasip1/wasm"}}
		}, []string{"(held under wasip1/wasm — see Call Graph)"}},
		{"capability superseded", "Capability", func(o *contextOutput) {
			o.Capability = contextCapability{Status: sectionStatusSuperseded}
		}, []string{"(superseded — see Call Graph)"}},
		{"examples not_run", "Examples", func(o *contextOutput) { o.Examples = contextExamples{Status: sectionStatusNotRun} }, []string{cmds.Examples}},
		{"examples read_error", "Examples", func(o *contextOutput) {
			o.Examples = contextExamples{Status: sectionStatusReadError, Error: "ex fault"}
		}, []string{"ex fault"}},
		{"examples set_aside", "Examples", func(o *contextOutput) { o.Examples = contextExamples{Status: sectionStatusSetAside, Error: "ex aside"} }, []string{"ex aside"}},
		{"examples superseded", "Examples", func(o *contextOutput) {
			o.Examples = contextExamples{Status: sectionStatusSuperseded, Error: "ex superseded"}
		}, []string{"ex superseded"}},
		{"vulnerabilities not_run", "Vulnerabilities", func(o *contextOutput) { o.Vulnerabilities = contextVulnerabilities{Status: sectionStatusNotRun} }, []string{cmds.Vulnerabilities}},
		{"vulnerabilities read_error", "Vulnerabilities", func(o *contextOutput) {
			o.Vulnerabilities = contextVulnerabilities{Status: sectionStatusReadError, Error: "vuln fault"}
		}, []string{"vuln fault"}},
		{"vulnerabilities superseded", "Vulnerabilities", func(o *contextOutput) {
			o.Vulnerabilities = contextVulnerabilities{Status: sectionStatusSuperseded, Error: "vuln superseded", SetAside: aside}
		}, []string{"vuln superseded", "m@v1 content_hash sha256:aside — unreproducible"}},
		{"vulnerabilities set_aside", "Vulnerabilities", func(o *contextOutput) {
			o.Vulnerabilities = contextVulnerabilities{Status: sectionStatusSetAside, Error: "vuln aside", SetAside: aside}
		}, []string{"(no record this build can serve — vuln aside)", "m@v1 content_hash sha256:aside — unreproducible"}},
		{"vulnerabilities answered with rows set aside", "Vulnerabilities", func(o *contextOutput) {
			o.Vulnerabilities = contextVulnerabilities{Status: "Clean", SetAside: aside}
		}, []string{"m@v1 content_hash sha256:aside — unreproducible"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := contextOutput{Module: contextModuleInfo{Path: "m", Version: "v1"}, Commands: cmds}
			tc.set(&out)
			_, full, _ := renderedSections(t, out)
			_, section, _ := strings.Cut(full, "=== "+tc.heading+" ===\n")
			section, _, _ = strings.Cut(section, "\n=== ")
			for _, w := range tc.want {
				if !strings.Contains(section, w) {
					t.Errorf("--full %s lacks %q:\n%s", tc.heading, w, section)
				}
			}
		})
	}
}

// Every section the summary prints has a --full heading carrying the same
// statement: the native coverage and the standard library's licence basis
// were summary-only.
func TestContextFull_CarriesEverySectionTheSummaryCarries(t *testing.T) {
	out := contextOutput{
		Module:          contextModuleInfo{Path: "std", Version: "v1.27.2"},
		License:         contextLicense{Status: "Known", SPDX: "BSD-3-Clause", Custody: &contextLicenseCustody{Statement: "the published BSD-3-Clause"}},
		CallGraph:       contextCallGraph{Status: sectionStatusNotRun},
		Capability:      contextCapability{Status: sectionStatusNotRun},
		Vulnerabilities: contextVulnerabilities{Status: sectionStatusNotRun},
		Native: &nativeCoverage{
			State: nativeStateNotExamined, Statement: "not examined — run: kanonarion native std@v1.27.2",
			Components: []nativeCoverageComponent{}, LinkedLibraries: []string{"libz"},
		},
	}
	summary, full, _ := renderedSections(t, out)
	for label, heading := range map[string]string{
		"  Verification:": "=== Verification ===", "  Provenance:": "=== Provenance ===",
		"  Dependencies:": "=== Dependencies ===", "  License:": "=== License ===",
		"  Interface:": "=== Interface ===", "  Call Graph:": "=== Call Graph ===",
		"  Capability:": "=== Capability ===", "  Examples:": "=== Examples ===",
		"  Vulnerabilities:": "=== Vulnerabilities ===", "  Native code:": "=== Native Code ===",
	} {
		if strings.Contains(summary, label) != strings.Contains(full, heading) {
			t.Errorf("summary has %q = %v, full has %q = %v", label, strings.Contains(summary, label),
				heading, strings.Contains(full, heading))
		}
	}
	for _, want := range []string{
		"=== Native Code ===\nState:        not_examined\nnot examined — run: kanonarion native std@v1.27.2\n",
		"also links, from outside this module: libz\n",
		"Basis:        the published BSD-3-Clause\n",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("--full lacks %q:\n%s", want, full)
		}
	}

	out.Native = nil
	if summary, full, _ = renderedSections(t, out); strings.Contains(summary, "Native code") || strings.Contains(full, "Native Code") {
		t.Errorf("a document with no native statement printed one:\n%s\n%s", summary, full)
	}
}
