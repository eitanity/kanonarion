package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	capdomain "github.com/eitanity/kanonarion/internal/capability/domain"
)

type fakeCapAnalyser struct {
	report     capdomain.CapabilityReport
	fromReport capdomain.CapabilityReport
	toReport   capdomain.CapabilityReport
	diff       capdomain.CapabilityDiff
	err        error
}

func (f fakeCapAnalyser) Analyse(context.Context, coordinate.ModuleCoordinate, string, cgdomain.RootScope) (capdomain.CapabilityReport, error) {
	return f.report, f.err
}

func (f fakeCapAnalyser) Diff(context.Context, coordinate.ModuleCoordinate, coordinate.ModuleCoordinate, string, cgdomain.RootScope) (capdomain.CapabilityReport, capdomain.CapabilityReport, capdomain.CapabilityDiff, error) {
	return f.fromReport, f.toReport, f.diff, f.err
}

func sampleReport() capdomain.CapabilityReport {
	return capdomain.CapabilityReport{
		Findings: []capdomain.CapabilityFinding{
			{
				Capability:        capdomain.CapabilityNetwork,
				Path:              []string{"m.Root", "net/http.Get"},
				SinkPackage:       "net/http",
				SinkSymbol:        "Get",
				WeakestConfidence: "Direct",
				Basis:             capdomain.BasisUse,
			},
		},
	}
}

// observedReport is a report whose only EXEC and UNSAFE_POINTER paths establish
// something weaker than a capability of the module.
func observedReport() capdomain.CapabilityReport {
	r := sampleReport()
	r.Observations = []capdomain.CapabilityFinding{
		{
			Capability:        capdomain.CapabilityExec,
			Path:              []string{"m.init", "os/exec.init"},
			SinkPackage:       "os/exec",
			SinkSymbol:        "init",
			WeakestConfidence: "Direct",
			Basis:             capdomain.BasisLinkageOnly,
		},
		{
			Capability:        capdomain.CapabilityUnsafePointer,
			Path:              []string{"m.Root", "sync.(*RWMutex).Lock"},
			SinkPackage:       "sync",
			SinkSymbol:        "Lock",
			WeakestConfidence: "Direct",
			Basis:             capdomain.BasisCalleeBodyFact,
		},
	}
	return r
}

// TestRunCapabilityObservationsAreStatedNotDropped: an observation is out of the
// capability set but on the page, under a heading that says what it is.
func TestRunCapabilityObservationsAreStatedNotDropped(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{report: observedReport()}
	if err := runCapability(context.Background(), "m@v1.0.0", uc, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "not capabilities of this module") {
		t.Errorf("observations heading missing: %q", out)
	}
	for _, want := range []string{
		"EXEC", "os/exec.init", "linkage only",
		"UNSAFE_POINTER", "sync.Lock", "callee body fact",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("observation detail %q missing: %q", want, out)
		}
	}
	// A capability line is indented two spaces; an observation four. Matching the
	// bare label would match both, so anchor on the line start.
	if strings.Contains(out, "\n  EXEC") {
		t.Errorf("EXEC must not be rendered as a capability: %q", out)
	}
}

// TestRunCapabilityObservationsWithNoCapability: a report with nothing witnessed
// still says so AND still shows what it did find.
func TestRunCapabilityObservationsWithNoCapability(t *testing.T) {
	var buf bytes.Buffer
	rep := observedReport()
	rep.Findings = nil
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{report: rep}, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "no sensitive capabilities") {
		t.Errorf("empty message missing: %q", out)
	}
	if !strings.Contains(out, "os/exec.init") {
		t.Errorf("observations still belong on an otherwise empty report: %q", out)
	}
}

func TestRunCapabilityJSONCarriesObservationsAndBasis(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{report: observedReport()}, cgdomain.RootScopeProduction, true, &buf); err != nil {
		t.Fatal(err)
	}
	var got capabilityReportJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "NETWORK" {
		t.Errorf("an observation must not enter the capability set: %v", got.Capabilities)
	}
	if len(got.Findings) != 1 || got.Findings[0].Basis != "use" {
		t.Errorf("findings = %+v", got.Findings)
	}
	if got.Findings[0].BasisNote != "" {
		t.Errorf("a used capability needs no qualification, got %q", got.Findings[0].BasisNote)
	}
	if len(got.Observations) != 2 {
		t.Fatalf("observations = %+v", got.Observations)
	}
	wantBasis := []string{"linkage_only", "callee_body_fact"}
	for i, o := range got.Observations {
		if o.Basis != wantBasis[i] {
			t.Errorf("observation %d basis = %q, want %q", i, o.Basis, wantBasis[i])
		}
		if o.BasisNote == "" {
			t.Errorf("observation %d carries no note", i)
		}
	}
}

// TestRunCapabilityJSONAlwaysCarriesObservations: the key is present even when
// empty, so its absence can never be read as "none found".
func TestRunCapabilityJSONAlwaysCarriesObservations(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{report: sampleReport()}, cgdomain.RootScopeProduction, true, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\"observations\": []") {
		t.Errorf("observations key missing from JSON: %s", buf.String())
	}
}

func TestRunCapabilityText(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{report: sampleReport()}
	if err := runCapability(context.Background(), "m@v1.0.0", uc, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "m@v1.0.0 capabilities") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, "NETWORK") || !strings.Contains(out, "net/http.Get") {
		t.Errorf("missing finding: %q", out)
	}
	if !strings.Contains(out, "m.Root → net/http.Get") {
		t.Errorf("missing path: %q", out)
	}
}

func TestRunCapabilityPartialCaveat(t *testing.T) {
	var buf bytes.Buffer
	rep := sampleReport()
	rep.Partial = true
	rep.Caveat = "graph did not resolve"
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{report: rep}, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "graph did not resolve") {
		t.Errorf("caveat not printed: %q", buf.String())
	}
}

func TestRunCapabilityEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{}, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no sensitive capabilities") {
		t.Errorf("expected empty message: %q", buf.String())
	}
}

func TestRunCapabilityJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{report: sampleReport()}, cgdomain.RootScopeProduction, true, &buf); err != nil {
		t.Fatal(err)
	}
	var got capabilityReportJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if got.Module != "m" || got.Version != "v1.0.0" {
		t.Errorf("coord = %s@%s", got.Module, got.Version)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "NETWORK" {
		t.Errorf("capabilities = %v", got.Capabilities)
	}
	if len(got.Findings) != 1 || got.Findings[0].SinkSymbol != "Get" {
		t.Errorf("findings = %+v", got.Findings)
	}
}

func TestRunCapabilityInvalidCoordinate(t *testing.T) {
	var buf bytes.Buffer
	err := runCapability(context.Background(), "not-a-coordinate", fakeCapAnalyser{}, cgdomain.RootScopeProduction, false, &buf)
	if err == nil {
		t.Fatal("expected error for bad coordinate")
	}
}

func TestRunCapabilityAnalyseError(t *testing.T) {
	var buf bytes.Buffer
	err := runCapability(context.Background(), "m@v1.0.0", fakeCapAnalyser{err: errors.New("boom")}, cgdomain.RootScopeProduction, false, &buf)
	if err == nil {
		t.Fatal("expected propagated error")
	}
}

func TestRunCapabilityDiffText(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{
		diff: capdomain.CapabilityDiff{
			ParityOK: true,
			Added:    []capdomain.Capability{capdomain.CapabilityExec},
			Removed:  []capdomain.Capability{capdomain.CapabilityNetwork},
		},
	}
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "+ EXEC") || !strings.Contains(out, "- NETWORK") {
		t.Errorf("diff output missing add/remove: %q", out)
	}
}

func TestRunCapabilityDiffNoChangeAndCaveat(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{
		diff: capdomain.CapabilityDiff{ParityOK: false, Caveat: "not valid"},
	}
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "not valid") {
		t.Errorf("caveat missing: %q", out)
	}
	// Two empty sets and two identical non-empty sets are different findings; the
	// no-change line says which one it is.
	for _, want := range []string{"no capability change", "neither version witnesses any capability"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the no-change output: %q", want, out)
		}
	}
}

// TestRunCapabilityDiffNoChangeNamesTheCommonSet asserts an unchanged non-empty
// capability set is stated rather than collapsed into the same line an empty one
// prints.
func TestRunCapabilityDiffNoChangeNamesTheCommonSet(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{
		diff: capdomain.CapabilityDiff{
			ParityOK: true,
			Common:   []capdomain.Capability{capdomain.CapabilityNetwork, capdomain.CapabilityExec},
		},
	}
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"no capability change", "both versions witness the same 2 capabilities", "NETWORK", "EXEC"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the no-change output: %q", want, out)
		}
	}
}

func TestRunCapabilityDiffJSON(t *testing.T) {
	var buf bytes.Buffer
	uc := fakeCapAnalyser{
		fromReport: sampleReport(),
		toReport:   sampleReport(),
		diff: capdomain.CapabilityDiff{
			ParityOK: true,
			Common:   []capdomain.Capability{capdomain.CapabilityNetwork},
		},
	}
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, cgdomain.RootScopeProduction, true, &buf); err != nil {
		t.Fatal(err)
	}
	var got capabilityDiffJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !got.ParityOK || len(got.Common) != 1 {
		t.Errorf("diff json = %+v", got)
	}
	if got.From.Module != "m" || got.To.Version != "v1.1.0" {
		t.Errorf("coords = %+v / %+v", got.From, got.To)
	}
}

func TestRunCapabilityDiffInvalidCoordinates(t *testing.T) {
	var buf bytes.Buffer
	if err := runCapabilityDiff(context.Background(), "bad", "m@v1.1.0", fakeCapAnalyser{}, cgdomain.RootScopeProduction, false, &buf); err == nil {
		t.Error("expected error for bad 'from'")
	}
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "bad", fakeCapAnalyser{}, cgdomain.RootScopeProduction, false, &buf); err == nil {
		t.Error("expected error for bad 'to'")
	}
}

func TestRunCapabilityDiffError(t *testing.T) {
	var buf bytes.Buffer
	err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", fakeCapAnalyser{err: errors.New("boom")}, cgdomain.RootScopeProduction, false, &buf)
	if err == nil {
		t.Fatal("expected propagated error")
	}
}

// TestCapabilityRootScopeIsStatedOnEveryReport pins the disclosure. The default
// root set here is the narrow one, so an unstated axis would leave a reader
// assuming the whole test surface was searched.
func TestCapabilityRootScopeIsStatedOnEveryReport(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope cgdomain.RootScope
		want  string
	}{
		{"production", cgdomain.RootScopeProduction, "test functions excluded"},
		{"with tests", cgdomain.RootScopeWithTests, "--include-tests was given"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			uc := fakeCapAnalyser{report: sampleReport()}
			if err := runCapability(context.Background(), "m@v1.0.0", uc, tc.scope, false, &buf); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("root scope not stated: %q", buf.String())
			}
			buf.Reset()
			if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, tc.scope, false, &buf); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("root scope not stated on the diff: %q", buf.String())
			}
		})
	}
}

func TestCapabilityJSONCarriesTheRootScope(t *testing.T) {
	for scope, want := range map[cgdomain.RootScope]string{
		cgdomain.RootScopeProduction: "excluded",
		cgdomain.RootScopeWithTests:  "included",
	} {
		var buf bytes.Buffer
		uc := fakeCapAnalyser{report: sampleReport()}
		if err := runCapability(context.Background(), "m@v1.0.0", uc, scope, true, &buf); err != nil {
			t.Fatal(err)
		}
		var got capabilityReportJSON
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
		}
		if got.TestRoots != want {
			t.Errorf("test_roots = %q, want %q", got.TestRoots, want)
		}
	}
}

func TestCapabilityRootScopeFromFlag(t *testing.T) {
	if got := capabilityRootScope(false); got != cgdomain.RootScopeProduction {
		t.Errorf("default scope = %v, want production", got)
	}
	if got := capabilityRootScope(true); got != cgdomain.RootScopeWithTests {
		t.Errorf("--include-tests scope = %v, want with-tests", got)
	}
}

// unexportedSinkRecord is a module whose only path to a sink starts at an
// unexported, non-init function — the shape entered through a registered
// handler or a callback, which the exported-API rule would never root. The
// record is classified a library, so it also pins that the kind decides
// nothing.
func unexportedSinkRecord() cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		ArtifactKind:  cgdomain.ArtifactLibrary,
		Nodes: []cgdomain.CallNode{
			{ID: "m.Exported", Package: "m", Symbol: "Exported", IsExportedAPI: true},
			{ID: "m.loadData", Package: "m", Symbol: "loadData"},
			{ID: "os.ReadFile", Package: "os", Symbol: "ReadFile", IsExternal: true},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "m.loadData", ToID: "os.ReadFile", Confidence: cgdomain.ConfidenceDirect},
		},
	}
}

// TestCapabilityRootsLineMatchesTheRootsUsed drives a record through the real
// selector and analysis, then checks the disclosure against the roots that were
// actually used: the line must not describe a narrower set than the traversal
// ran on.
func TestCapabilityRootsLineMatchesTheRootsUsed(t *testing.T) {
	rec := unexportedSinkRecord()
	for _, tc := range []struct {
		name  string
		scope cgdomain.RootScope
		want  []string
	}{
		{"production", cgdomain.RootScopeProduction, []string{"all of this module's own code", "test functions excluded"}},
		{"with tests", cgdomain.RootScopeWithTests, []string{"all of this module's own code", "--include-tests was given"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := capdomain.SelectRoots(rec, tc.scope)
			exported := map[string]bool{}
			for _, n := range rec.Nodes {
				exported[n.ID] = n.IsExportedAPI || cgdomain.IsInitSymbol(n.Symbol)
			}
			widerThanExportedAPI := false
			for _, r := range roots {
				if !exported[r] {
					widerThanExportedAPI = true
				}
			}
			if !widerThanExportedAPI {
				t.Fatalf("fixture no longer roots a non-exported node: roots = %v", roots)
			}

			var buf bytes.Buffer
			uc := fakeCapAnalyser{report: capdomain.Analyse(rec, roots)}
			if err := runCapability(context.Background(), "m@v1.0.0", uc, tc.scope, false, &buf); err != nil {
				t.Fatal(err)
			}
			got := buf.String()
			if strings.Contains(got, "exported API") {
				t.Errorf("roots line claims exported-API rooting, but %v rooted the traversal:\n%s", roots, got)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("roots line does not state %q:\n%s", want, got)
				}
			}
		})
	}
}

// TestCapabilityJSONOmitsTheArtifactKind pins the removal: the report does not
// consult the record's kind, so publishing it would invite a machine reader to
// rely on a fact this answer never used.
func TestCapabilityJSONOmitsTheArtifactKind(t *testing.T) {
	rec := unexportedSinkRecord()
	var buf bytes.Buffer
	uc := fakeCapAnalyser{report: capdomain.Analyse(rec, capdomain.SelectRoots(rec, cgdomain.RootScopeProduction))}
	if err := runCapability(context.Background(), "m@v1.0.0", uc, cgdomain.RootScopeProduction, true, &buf); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if _, present := got["artifact_kind"]; present {
		t.Errorf("artifact_kind is published but no longer governs the answer:\n%s", buf.String())
	}
}

// TestCapabilityDiffDisclosesOneSharedRootSet pins that both sides of --against
// are rooted by one rule: a version that gains a command is no longer rooted
// differently from the one it is diffed against, so the sets are comparable and
// one line describes both.
func TestCapabilityDiffDisclosesOneSharedRootSet(t *testing.T) {
	uc := fakeCapAnalyser{
		fromReport: capdomain.CapabilityReport{},
		toReport:   capdomain.CapabilityReport{},
		diff:       capdomain.CapabilityDiff{ParityOK: true},
	}
	var buf bytes.Buffer
	if err := runCapabilityDiff(context.Background(), "m@v1.0.0", "m@v1.1.0", uc, cgdomain.RootScopeProduction, false, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if n := strings.Count(got, "roots: "); n != 1 {
		t.Errorf("diff printed %d roots lines, want one shared line:\n%s", n, got)
	}
	if !strings.Contains(got, capabilityRootScopeLine(cgdomain.RootScopeProduction)) {
		t.Errorf("diff does not disclose the shared root set:\n%s", got)
	}
}

// TestCapabilityRootsLineWording pins both lines byte for byte, so a reword
// that drifts from what SelectRoots does has to be deliberate.
func TestCapabilityRootsLineWording(t *testing.T) {
	for scope, want := range map[cgdomain.RootScope]string{
		cgdomain.RootScopeProduction: "roots: all of this module's own code; test functions excluded (widen with --include-tests)",
		cgdomain.RootScopeWithTests:  "roots: all of this module's own code, test functions included (--include-tests was given)",
	} {
		if got := capabilityRootScopeLine(scope); got != want {
			t.Errorf("roots line = %q, want %q", got, want)
		}
	}
}
