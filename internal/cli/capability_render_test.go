package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	capapp "code.eitanity.com/kanonarion/internal/capability/application"
	capdomain "code.eitanity.com/kanonarion/internal/capability/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

func renderNode(id, pkg, recv, sym string, external, exported bool) cgdomain.CallNode {
	return cgdomain.CallNode{ID: id, Package: pkg, Receiver: recv, Symbol: sym, IsExternal: external, IsExportedAPI: exported}
}

// capabilityRenderGraph exercises every section the report prints: an Act and a Context
// finding, a suppressed RUNTIME_INTERNAL, a plumbing-only CGO_CALL, a sensitive
// call, both co-location facts, an owned asm body and a package default.
func capabilityRenderGraph() cgdomain.CallGraphRecord {
	asm := renderNode("m.asmLoop", "m", "", "asmLoop", false, false)
	asm.IsAssemblyOrLinkname = true
	unsafeFn := renderNode("m.cast", "m", "", "cast", false, false)
	unsafeFn.UsesUnsafePointer = true
	edge := func(from, to string, c cgdomain.EdgeConfidence) cgdomain.CallEdge {
		return cgdomain.CallEdge{FromID: from, ToID: to, Confidence: c}
	}
	return cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			renderNode("m.init", "m", "", "init", false, false),
			renderNode("m.Send", "m", "", "Send", false, true),
			renderNode("m.helper", "m", "", "helper", false, false),
			renderNode("m.other", "m", "", "other", false, false),
			asm, unsafeFn,
			renderNode("os.Getenv", "os", "", "Getenv", true, false),
			renderNode("net.Dial", "net", "", "Dial", true, false),
			renderNode("reflect.TypeOf", "reflect", "", "TypeOf", true, false),
			renderNode("runtime.GC", "runtime", "", "GC", true, false),
			renderNode("runtime/cgo._Cgo_use", "runtime/cgo", "", "_Cgo_use", true, false),
		},
		Edges: []cgdomain.CallEdge{
			edge("m.init", "m.Send", cgdomain.ConfidenceDirect),
			edge("m.Send", "os.Getenv", cgdomain.ConfidenceDirect),
			edge("m.Send", "net.Dial", cgdomain.ConfidenceDirect),
			edge("m.helper", "os.Getenv", cgdomain.ConfidenceDirect),
			edge("m.other", "os.Getenv", cgdomain.ConfidenceCHAOverapprox),
			edge("m.helper", "reflect.TypeOf", cgdomain.ConfidenceDirect),
			edge("m.helper", "runtime.GC", cgdomain.ConfidenceDirect),
			edge("m.helper", "runtime/cgo._Cgo_use", cgdomain.ConfidenceDirect),
		},
	}
}

func renderReport() capdomain.CapabilityReport {
	rec := capabilityRenderGraph()
	return capdomain.Analyse(rec, capdomain.SelectRoots(rec, cgdomain.RootScopeProduction), cgdomain.RootScopeProduction)
}

func TestCapabilityReportText_PrintsEverySectionAndHidesSuppressed(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{report: renderReport()}
	if err := runCapability(context.Background(), "m@v1.0.0", uc, noGenerations{}, cgdomain.RootScopeProduction, capabilityOutput{}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"  ENV_READ         [Direct]  [EXPORTED_API]  DIRECT_CALL  via os.Getenv",
		"CGO_CALL         [Direct]  [INTERNAL]  RUNTIME_PLUMBING  via runtime/cgo._Cgo_use  plumbing-only",
		"REFLECT_INSPECT  [Direct]  [INTERNAL]  DIRECT_CALL  via reflect.TypeOf  (package default)",
		"1 finding hidden: RUNTIME_INTERNAL is suppressed by default (--show-suppressed shows it)",
		"sensitive calls (2): exported sensitive functions called over at least one Direct edge",
		"    ENV_READ       os.Getenv  from EXPORTED_API, INTERNAL (3 callers)",
		"    NET_DIAL       net.Dial  from EXPORTED_API (1 caller)",
		"  co-location (2):",
		"collects and egresses: m.Send [EXPORTED_API]  collects os.Getenv; egresses net.Dial",
		"init reaches both: m.init [INIT] at depth 2  (os.Getenv at 2, net.Dial at 2, over Direct edges)",
		"unanalysed bodies (1): this module's own assembly or //go:linkname functions",
		"    m.asmLoop",
		"package defaults: reflect 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\n  RUNTIME_INTERNAL ") {
		t.Errorf("RUNTIME_INTERNAL must be hidden without --show-suppressed:\n%s", out)
	}
	// Act before Context: ENV_READ precedes REFLECT_INSPECT.
	if strings.Index(out, "  ENV_READ  ") > strings.Index(out, "  REFLECT_INSPECT") {
		t.Errorf("Act findings print before Context:\n%s", out)
	}

	buf.Reset()
	if err := runCapability(context.Background(), "m@v1.0.0", uc, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{showSuppressed: true}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\n  RUNTIME_INTERNAL ") || strings.Contains(buf.String(), "hidden") {
		t.Errorf("--show-suppressed prints the finding and no hidden count:\n%s", buf.String())
	}
}

func TestCapabilityReportText_NamesAnEmptyRollUp(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{}, noGenerations{}, cgdomain.RootScopeProduction, capabilityOutput{}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"sensitive calls: none",
		"co-location: no function collects and egresses, and no initialiser reaches both",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("empty report lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestCapabilityReportJSON_CarriesTheAxesAndTheRollUp(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{report: renderReport()}, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{json: true}, &buf); err != nil {
		t.Fatal(err)
	}
	var got capabilityReportJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	assertFindingAxes(t, got.Findings)
	if len(got.SensitiveCalls) != 2 || len(got.CollectsAndEgresses) != 1 || len(got.InitReachesBoth) != 1 ||
		len(got.Unanalyzed) != 1 || len(got.PackageDefaults) != 1 || got.RowCount != len(renderReport().Rows) {
		t.Errorf("roll-up = %+v", got)
	}
	assertEmptyListsArePresent(t)
}

// assertFindingAxes checks the three axes and the suppression marks on the
// findings of the render fixture.
func assertFindingAxes(t *testing.T, findings []capabilityFindingJSON) {
	t.Helper()
	byCap := map[string]capabilityFindingJSON{}
	for _, f := range findings {
		byCap[f.Capability] = f
	}
	env := byCap["ENV_READ"]
	if env.Reach != "DIRECT_CALL" || env.CallerKind != "EXPORTED_API" || env.CapslockCategory != "READ_SYSTEM_STATE" ||
		env.ClassifiedBy != "rule" || env.Suppressed {
		t.Errorf("ENV_READ = %+v", env)
	}
	if rt := byCap["RUNTIME_INTERNAL"]; !rt.Suppressed || rt.CapslockCategory != "RUNTIME" {
		t.Errorf("JSON carries the suppressed finding, marked: %+v", rt)
	}
	if !byCap["CGO_CALL"].PlumbingOnly {
		t.Errorf("CGO_CALL = %+v, want plumbing_only", byCap["CGO_CALL"])
	}
}

// assertEmptyListsArePresent: every list is an array even when empty.
func assertEmptyListsArePresent(t *testing.T) {
	t.Helper()
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{}, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{json: true}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"sensitive_calls": []`, `"collects_and_egresses": []`, `"init_reaches_both": []`,
		`"unanalyzed": []`, `"package_defaults": []`, `"partial": false`} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("empty report JSON lacks %s:\n%s", key, buf.String())
		}
	}
}

// The diff prints the roll-up first, keeps added and removed apart, collapses
// INTERNAL rows to a count, and hides suppressed rows behind a count.
func TestCapabilityDiffText_RollUpFirstThenRankedRows(t *testing.T) {
	to := renderReport()
	diff := capdomain.DiffCapabilities(capdomain.CapabilityReport{Unanalyzed: []string{"m.oldAsm"}}, to)
	uc := fakeCapAnalyser{toReport: to, diff: diff}
	var buf bytes.Buffer
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction, capabilityOutput{}, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	order := []string{
		"  sensitive calls: 2 added, 0 removed",
		"    + ENV_READ       os.Getenv  from EXPORTED_API, INTERNAL (3 callers)",
		"    + NET_DIAL       net.Dial  from EXPORTED_API (1 caller)",
		"  co-location: 2 added, 0 removed",
		"    + collects and egresses: m.Send",
		"    + init reaches both: m.init",
		"  unanalysed bodies: 1 added, 1 removed",
		"    + m.asmLoop",
		"    - m.oldAsm",
		"  capabilities: 6 (CGO_CALL, ENV_READ, NET_DIAL, REFLECT_INSPECT, RUNTIME_INTERNAL, UNSAFE_POINTER) added, 0 removed",
		"  rows added: 8 (1 suppressed: runtime internals and unexported plumbing; --show-suppressed shows them)",
		"    + [EXPORTED_API] ENV_READ DIRECT_CALL os.Getenv  [Direct]  m.Send",
		"    + [EXPORTED_API] NET_DIAL DIRECT_CALL net.Dial  [Direct]  m.Send",
		"    + [INTERNAL] CGO_CALL RUNTIME_PLUMBING runtime/cgo._Cgo_use  [Direct]  1 caller  plumbing-only",
		"    + [INTERNAL] ENV_READ DIRECT_CALL os.Getenv  [Direct]  2 callers",
		"    + [INTERNAL] UNSAFE_POINTER DIRECT_CALL m.cast (own body)  [Direct]  itself",
		"    + [INTERNAL] REFLECT_INSPECT DIRECT_CALL reflect.TypeOf  [Direct]  1 caller",
		"  rows removed: 0",
	}
	at := 0
	for _, want := range order {
		i := strings.Index(out[at:], want)
		if i < 0 {
			t.Fatalf("diff lacks %q after offset %d:\n%s", want, at, out)
		}
		at += i + len(want)
	}
	if strings.Contains(out, "runtime.GC") {
		t.Errorf("the suppressed row is hidden without --show-suppressed:\n%s", out)
	}
	buf.Reset()
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{showSuppressed: true}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[INTERNAL] RUNTIME_INTERNAL DIRECT_CALL runtime.GC") ||
		strings.Contains(buf.String(), "suppressed:") {
		t.Errorf("--show-suppressed prints the row and no hidden count:\n%s", buf.String())
	}
}

// countSuppressedRows counts the suppressed rows, failing any row that lacks a
// field.
func countSuppressedRows(t *testing.T, rows []capabilityRowJSON) int {
	t.Helper()
	suppressed := 0
	for _, r := range rows {
		if r.Suppressed {
			suppressed++
		}
		if r.CapslockCategory == "" || r.Caller == "" || r.Callee == "" || r.Confidence == "" || r.ClassifiedBy == "" {
			t.Errorf("row lacks a field: %+v", r)
		}
	}
	return suppressed
}

// JSON carries every row per caller, with the same rows text groups.
func TestCapabilityDiffJSON_CarriesEveryRow(t *testing.T) {
	to := renderReport()
	diff := capdomain.DiffCapabilities(capdomain.CapabilityReport{}, to)
	var buf bytes.Buffer
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", fakeCapAnalyser{toReport: to, diff: diff},
		noGenerations{}, cgdomain.RootScopeProduction, capabilityOutput{json: true}, &buf); err != nil {
		t.Fatal(err)
	}
	var got capabilityDiffJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(got.RowsAdded) != len(to.Rows) || got.ToRows != len(to.Rows) || got.FromRows != 0 {
		t.Fatalf("rows_added %d to_rows %d from_rows %d, want %d", len(got.RowsAdded), got.ToRows, got.FromRows, len(to.Rows))
	}
	if suppressed := countSuppressedRows(t, got.RowsAdded); suppressed != 1 || len(got.SensitiveCallsAdded) != 2 || len(got.CollectsAndEgressesAdded) != 1 ||
		len(got.InitReachesBothAdded) != 1 || len(got.UnanalyzedAdded) != 1 || got.RowsRemoved == nil {
		t.Errorf("diff JSON = %+v", got)
	}
}

// A depth move is printed as one change of depth, in text and JSON.
func TestCapabilityDiff_InitDepthMoveIsAChange(t *testing.T) {
	ir := func(depth int) capdomain.CapabilityReport {
		return capdomain.CapabilityReport{InitReachesBoth: []capdomain.InitReach{{
			Init: "m.init", CallerKind: capdomain.CallerInit, Depth: depth, Collection: "os.Getenv", Egress: "net.Dial",
		}}}
	}
	diff := capdomain.DiffCapabilities(ir(6), ir(7))
	uc := fakeCapAnalyser{fromReport: ir(6), toReport: ir(7), diff: diff}
	var buf bytes.Buffer
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction, capabilityOutput{}, &buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  co-location: 0 added, 0 removed, 1 changed depth",
		"    ~ init reaches both: m.init [INIT] depth 6 → 7  (os.Getenv, net.Dial)",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("diff lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction, capabilityOutput{json: true}, &buf); err != nil {
		t.Fatal(err)
	}
	var got capabilityDiffJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []initReachDepthChangeJSON{{Init: "m.init", Collection: "os.Getenv", Egress: "net.Dial", FromDepth: 6, ToDepth: 7}}
	if len(got.InitReachesBothAdded) != 0 || len(got.InitReachesBothRemoved) != 0 ||
		len(got.InitReachesBothDepthChanged) != 1 || got.InitReachesBothDepthChanged[0] != want[0] {
		t.Errorf("JSON = +%v -%v ~%v", got.InitReachesBothAdded, got.InitReachesBothRemoved, got.InitReachesBothDepthChanged)
	}
}

// A diff states the frame its records were read under once, and each side's
// where the two state it differently; the JSON carries each side's.
func TestCapabilityDiff_FrameLines(t *testing.T) {
	from, to := coordinatetest.MustNew("m", "v1.0.0"), coordinatetest.MustNew("m", "v1.1.0")
	host := cgdomain.CallGraphRecord{Coordinate: from, Frame: hostFrame()}
	served := &servedCallGraphs{source: fakeCallGraphSource{from.String(): host, to.String(): host}}
	uc := capapp.NewAnalyseCapabilitiesUseCase(served)
	var buf bytes.Buffer
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{served: served}, &buf); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(buf.String(), "  frame: "+hostFrame().String()+"\n"); got != 1 {
		t.Errorf("one frame stated %d times:\n%s", got, buf.String())
	}

	served.source = fakeCallGraphSource{from.String(): host, to.String(): {Coordinate: to, Frame: framePico}}
	buf.Reset()
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{served: served}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "  frame: "+hostFrame().String()+"\n  frame: tinygo/pico (linux/arm)") {
		t.Errorf("two frames not both stated:\n%s", buf.String())
	}
	buf.Reset()
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, noGenerations{}, cgdomain.RootScopeProduction,
		capabilityOutput{json: true, served: served}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"tinygo_target": "pico"`) || !strings.Contains(buf.String(), `"text": "`+hostFrame().String()+`"`) {
		t.Errorf("the JSON sides lack their frames:\n%s", buf.String())
	}
}

// fakeCallGraphSource serves the record stored under a coordinate's string.
type fakeCallGraphSource map[string]cgdomain.CallGraphRecord

func (f fakeCallGraphSource) GetCallGraphRecord(_ context.Context, coord coordinate.ModuleCoordinate, _ string) (cgdomain.CallGraphRecord, bool, error) {
	r, ok := f[coord.String()]
	return r, ok, nil
}
