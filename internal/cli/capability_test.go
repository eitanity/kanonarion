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
			},
		},
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
