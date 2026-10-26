package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/cli/testfakes"
	"code.eitanity.com/kanonarion/internal/coordinate"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	capapp "code.eitanity.com/kanonarion/internal/capability/application"
)

// sensitiveRecord is a module whose exported function reads the environment and
// dials, whose initialiser does both, and whose test alone executes a process:
// sensitive calls, both co-location facts, and a test-only sink the default
// roots must not count.
func sensitiveRecord(coord coordinate.ModuleCoordinate) cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		Coordinate:    coord,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			{ID: "m.Fetch", Package: "m", Symbol: "Fetch", IsExportedAPI: true},
			{ID: "m.init", Package: "m", Symbol: "init"},
			{ID: "m.TestRun", Package: "m", Symbol: "TestRun", IsTest: true},
			{ID: "os.Getenv", Package: "os", Symbol: "Getenv", IsExternal: true},
			{ID: "net.Dial", Package: "net", Symbol: "Dial", IsExternal: true},
			{ID: "os/exec.Command", Package: "os/exec", Symbol: "Command", IsExternal: true},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "m.Fetch", ToID: "os.Getenv", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "m.Fetch", ToID: "net.Dial", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "m.init", ToID: "os.Getenv", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "m.init", ToID: "net.Dial", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "m.TestRun", ToID: "os/exec.Command", Confidence: cgdomain.ConfidenceDirect},
		},
	}
}

// quietRecord is a module that calls nothing outside itself.
func quietRecord(coord coordinate.ModuleCoordinate) cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		Coordinate:    coord,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes:         []cgdomain.CallNode{{ID: "m.Add", Package: "m", Symbol: "Add", IsExportedAPI: true}},
	}
}

// capabilityJSONOf runs `capability --json` over uc.
func capabilityJSONOf(t *testing.T, coord coordinate.ModuleCoordinate, uc *testfakes.FakeQueryCallGraph) capabilityReportJSON {
	t.Helper()
	var buf bytes.Buffer
	scope := capabilityRootScope(false)
	if err := runCapability(context.Background(), coord.String(), capapp.NewAnalyseCapabilitiesUseCase(uc), uc, scope,
		capabilityOutput{json: true}, &buf); err != nil {
		t.Fatal(err)
	}
	var doc capabilityReportJSON
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// contextCapabilityOf builds the section over uc and reads it back from JSON.
func contextCapabilityOf(t *testing.T, coord coordinate.ModuleCoordinate, uc *testfakes.FakeQueryCallGraph) (contextCapabilityAnswer, string) {
	t.Helper()
	_, capab := buildCallGraph(context.Background(), coord, uc, false, "")
	raw, err := json.Marshal(capab)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Status string `json:"status"`
		contextCapabilityAnswer
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "Extracted" || got.Command != "kanonarion capability "+coord.String() {
		t.Errorf("status/command = %q / %q", got.Status, got.Command)
	}
	return got.contextCapabilityAnswer, string(raw)
}

// The section agrees with `capability --json` on the same record: the label
// set, the counts and the flags.
func TestContextCapability_AgreesWithCapabilityJSON(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	for name, rec := range map[string]cgdomain.CallGraphRecord{
		"sensitive": sensitiveRecord(coord),
		"none":      quietRecord(coord),
	} {
		t.Run(name, func(t *testing.T) {
			uc := testfakes.NewFakeQueryCallGraph()
			uc.AddRecord(coord, cgapp.PipelineVersion, rec)
			full := capabilityJSONOf(t, coord, uc)
			got, raw := contextCapabilityOf(t, coord, uc)

			want := contextCapabilityAnswer{
				TestRoots: full.TestRoots, Partial: full.Partial, Caveat: full.Caveat,
				Capabilities: full.Capabilities, RowsByCapability: got.RowsByCapability, RowCount: full.RowCount,
				SensitiveCallsCount: len(full.SensitiveCalls), CollectsAndEgressesCount: len(full.CollectsAndEgresses),
				InitReachesBothCount: len(full.InitReachesBoth), UnanalyzedCallees: full.UnanalyzedCallees, Command: got.Command,
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("section = %+v\ncapability --json gives %+v", got, want)
			}
			sum := 0
			for _, n := range got.RowsByCapability {
				sum += n
			}
			if sum != full.RowCount || len(got.RowsByCapability) != len(full.Capabilities) {
				t.Errorf("rows_by_capability %v does not partition row_count %d over %v", got.RowsByCapability, full.RowCount, full.Capabilities)
			}
			if sensitive := name == "sensitive"; (got.SensitiveCallsCount > 0) != sensitive ||
				sensitive && (got.CollectsAndEgressesCount == 0 || got.InitReachesBothCount == 0) {
				t.Fatalf("fixture %s no longer has the facts it exists for: %s", name, raw)
			}
			if strings.Contains(raw, "EXEC_PROCESS") {
				t.Errorf("a test-only sink was counted under the default roots: %s", raw)
			}
		})
	}
}

// The graph is read once per coordinate: the capability section analyses the
// record the call-graph section already holds.
func TestContextCapability_LoadsTheGraphOnce(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(coord, cgapp.PipelineVersion, sensitiveRecord(coord))
	cg, capab := buildCallGraph(context.Background(), coord, uc, false, "")
	if cg.Status != "Extracted" || capab.contextCapabilityAnswer == nil {
		t.Fatalf("sections = %+v / %+v", cg, capab)
	}
	if uc.RecordReads != 1 || uc.HistoryCalls != 0 {
		t.Errorf("record reads = %d, history reads = %d; want one read of the graph", uc.RecordReads, uc.HistoryCalls)
	}
}

// A graph that did not extract was never searched: its status, a statement, and
// no counts, never an empty set. A partial graph is answered and marked.
func TestContextCapability_FailedGraphGivesNoAnswer(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	for _, status := range []cgdomain.CallGraphStatus{
		cgdomain.CallGraphStatusLoadFailed, cgdomain.CallGraphStatusExtractionFailed,
		cgdomain.CallGraphStatusExcludedByConfig, cgdomain.CallGraphStatusUnknown,
	} {
		rec := quietRecord(coord)
		rec.OverallStatus = status
		got := buildCapability(coord, rec)
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != status.String() || got.contextCapabilityAnswer != nil || strings.Contains(string(raw), "capabilities") {
			t.Errorf("%s = %s", status, raw)
		}
		if line := capabilityLine(got); line != "(the call graph is "+status.String()+", so no capability was searched for)" {
			t.Errorf("%s text = %q", status, line)
		}
	}
	rec := sensitiveRecord(coord)
	rec.OverallStatus = cgdomain.CallGraphStatusPartial
	got := buildCapability(coord, rec)
	if got.contextCapabilityAnswer == nil || !got.Partial || got.Caveat == "" || got.Status != "Partial" {
		t.Errorf("partial graph = %+v", got)
	}
}

// The text forms state the counts, the per-label rows and the full-record
// command; the full renderer gives the section its own heading.
func TestContextCapability_Text(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	rec := sensitiveRecord(coord)
	rec.OverallStatus = cgdomain.CallGraphStatusPartial
	out := contextOutput{CallGraph: contextCallGraph{Status: "Partial"}, Capability: buildCapability(coord, rec)}
	summary, full, _ := renderedSections(t, out)
	for _, want := range []string{
		"  Capability:      2 label(s), 2 sensitive call(s), 2 collect-and-egress, 1 init-reaches-both, 0 unanalysed callee(s) (Partial; test roots excluded)\n",
		"    caveat:        call graph did not fully resolve",
		"    rows:          ENV_READ 2, NET_DIAL 2\n",
		"    full record:   kanonarion capability example.com/m@v1.0.0\n",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
	if !strings.Contains(full, "=== Capability ===\n2 label(s)") || !strings.Contains(full, "\nfull record:   kanonarion capability") {
		t.Errorf("full text:\n%s", full)
	}

	quiet := contextOutput{Capability: buildCapability(coord, quietRecord(coord))}
	if summary, _, _ = renderedSections(t, quiet); strings.Contains(summary, "rows:") || strings.Contains(summary, "caveat:") {
		t.Errorf("a module with no rows printed a rows or caveat line:\n%s", summary)
	}
}

// Every route that builds a call-graph section builds the capability section
// beside it, from the same read: the coordinate, --gomod and --walk-id, in JSON
// and in text.
func TestContextCapability_EveryRoute(t *testing.T) {
	fx := newJSONStdoutFixture(t)
	chdirWithGoMod(t, "")
	for name, args := range map[string][]string{
		"coordinate": {"context", jsonDocDepCoord},
		"gomod":      {"context", "--gomod", fx.populatedGoMod()},
		"walk-id":    {"context", "--walk-id", jsonDocWalkID},
	} {
		t.Run(name, func(t *testing.T) {
			args = append(args, "--store-root", fx.storeRoot)
			var stdout, stderr bytes.Buffer
			if err := Run(append(args, "--json"), &stdout, &stderr); err != nil {
				t.Fatalf("%v\n%s", err, stderr.String())
			}
			_, rows := decodeEnvelope(t, name, stdout.Bytes())
			answered := 0
			for _, row := range rows {
				var doc struct {
					CallGraph  map[string]any `json:"call_graph"`
					Capability map[string]any `json:"capability"`
				}
				if err := json.Unmarshal(row, &doc); err != nil {
					t.Fatal(err)
				}
				if doc.Capability == nil || doc.Capability["status"] != doc.CallGraph["status"] {
					t.Errorf("capability %v does not follow call_graph %v", doc.Capability, doc.CallGraph["status"])
				}
				if doc.Capability["command"] != nil {
					answered++
				}
			}
			if answered == 0 {
				t.Errorf("no module answered the capability section; the route is not exercised:\n%s", stdout.String())
			}
			stdout.Reset()
			if err := Run(args, &stdout, &stderr); err != nil {
				t.Fatalf("%v\n%s", err, stderr.String())
			}
			if n, m := strings.Count(stdout.String(), "  Call Graph:"), strings.Count(stdout.String(), "  Capability:"); n == 0 || n != m {
				t.Errorf("text has %d call-graph and %d capability lines:\n%s", n, m, stdout.String())
			}
		})
	}
}

// context --walk-id states the provenance section in JSON as it does in text:
// one document per module, the same heuristic answer in both.
func TestContextWalk_ProvenanceInJSONAndText(t *testing.T) {
	fx := newJSONStdoutFixture(t)
	chdirWithGoMod(t, "")
	args := []string{"context", "--walk-id", jsonDocWalkID, "--store-root", fx.storeRoot}
	var stdout, stderr bytes.Buffer
	if err := Run(append(args, "--json"), &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	_, rows := decodeEnvelope(t, "context --walk-id", stdout.Bytes())
	for _, row := range rows {
		var doc struct {
			Module     contextModuleInfo `json:"module"`
			Provenance contextProvenance `json:"provenance"`
		}
		if err := json.Unmarshal(row, &doc); err != nil {
			t.Fatal(err)
		}
		coord := mustCoord(t, doc.Module.Path, doc.Module.Version)
		if want := buildProvenance(coord); !reflect.DeepEqual(doc.Provenance, want) {
			t.Errorf("%s provenance = %+v, want %+v", coord, doc.Provenance, want)
		}
	}
	stdout.Reset()
	if err := Run(args, &stdout, &stderr); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if n := strings.Count(stdout.String(), "  Provenance:      no fork indicators"); len(rows) == 0 || n != len(rows) {
		t.Errorf("JSON has %d documents, text %d provenance lines:\n%s", len(rows), n, stdout.String())
	}
}

// The text form hides the labels capability's text hides by default, names
// them, and keeps them out of the label count; JSON carries every label.
func TestContextCapability_TextHidesSuppressedLabels(t *testing.T) {
	coord := mustCoord(t, "example.com/m", "v1.0.0")
	c := buildCapability(coord, sensitiveRecord(coord))
	c.Capabilities = append(c.Capabilities, "RUNTIME_INTERNAL")
	c.RowsByCapability["RUNTIME_INTERNAL"] = 9
	summary, full, doc := renderedSections(t, contextOutput{Capability: c})
	for _, text := range []string{summary, full} {
		if !strings.Contains(text, "2 label(s), 2 sensitive call(s)") ||
			!strings.Contains(text, "rows:          ENV_READ 2, NET_DIAL 2\n") ||
			!strings.Contains(text, "hidden:        1 label(s): RUNTIME_INTERNAL (suppressed by default; --json carries them)\n") {
			t.Errorf("text does not hide the suppressed label as capability does:\n%s", text)
		}
	}
	if !strings.Contains(doc, `"RUNTIME_INTERNAL":9`) || !strings.Contains(doc, `"RUNTIME_INTERNAL"]`) {
		t.Errorf("JSON dropped the suppressed label: %s", doc)
	}
	if shown, hidden := splitSuppressed([]string{"ENV_READ", "RUNTIME_INTERNAL"}); len(shown) != 1 || len(hidden) != 1 {
		t.Errorf("split = %v / %v", shown, hidden)
	}
}
