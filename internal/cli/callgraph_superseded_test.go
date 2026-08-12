package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// supersededStore is the state every store lands in the moment the extraction
// pipeline version moves: the records are all there, healthy and readable, and
// not one of them is served. The record deliberately makes no claim about
// function-value references, which is the cause an empty answer used to reach
// for here — it is a true statement about that record and the wrong answer to
// "why is this empty".
func supersededStore(t *testing.T) *testfakes.FakeQueryCallGraph {
	t.Helper()
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: "0.4.1"},
	})
	uc.AddRecord(coord, "0.4.1", cgdomain.CallGraphRecord{
		Coordinate:     coord,
		Nodes:          []cgdomain.CallNode{{ID: "example.com/app.Root"}},
		ReferenceScope: cgdomain.ReferenceScopeUnknown,
	})
	return uc
}

func assertSupersededDiagnostic(t *testing.T, err error, out string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected the superseded-pipeline diagnostic, got output: %q", out)
	}
	msg := err.Error()
	for _, want := range []string{
		"superseded extraction logic",
		"pipeline " + cgapp.PipelineVersion,
		"0.4.1",
		"kanonarion callgraph example.com/app@v1.0.0",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("diagnostic does not mention %q: %v", want, msg)
		}
	}
	// The reference axis is a real and separate cause. Naming it here sends a
	// reader to investigate extraction scope when the store simply holds nothing
	// this build serves.
	if strings.Contains(msg, "reference-scope") || strings.Contains(out, "reference-scope") {
		t.Errorf("the empty answer blamed reference scope: %v / %q", msg, out)
	}
}

func TestRunCallers_SupersededPipelineNamesItself(t *testing.T) {
	uc := supersededStore(t)
	var buf bytes.Buffer
	err := runCallers(context.Background(), "example.com/app.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	assertSupersededDiagnostic(t, err, buf.String())
}

func TestRunCallees_SupersededPipelineNamesItself(t *testing.T) {
	uc := supersededStore(t)
	var buf bytes.Buffer
	err := runCallees(context.Background(), "example.com/app.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	assertSupersededDiagnostic(t, err, buf.String())
}

func TestRunCallersTransitive_SupersededPipelineNamesItself(t *testing.T) {
	uc := supersededStore(t)
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "example.com/app.Root", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	assertSupersededDiagnostic(t, err, buf.String())
}

func TestRunCalleesTransitive_SupersededPipelineNamesItself(t *testing.T) {
	uc := supersededStore(t)
	var buf bytes.Buffer
	err := runCalleesTransitive(context.Background(), "example.com/app.Root", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	assertSupersededDiagnostic(t, err, buf.String())
}

// TestRunImplementers_SupersededPipelineNamesItself: an implementers query over
// a superseded store answered "no implementers", which is a claim about the
// code. It must say the same thing the edge queries say.
func TestRunImplementers_SupersededPipelineNamesItself(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: "0.4.1"},
	})
	uc.AddRecord(coord, "0.4.1", cgdomain.CallGraphRecord{
		Coordinate: coord,
		Interfaces: []cgdomain.InterfaceType{
			{ID: "example.com/app.Store", Package: "example.com/app", Name: "Store", Methods: []string{"Put"}},
		},
		Implementations: []cgdomain.InterfaceImplementation{
			{InterfaceID: "example.com/app.Store", TypeID: "example.com/app.(*S)", Package: "example.com/app"},
		},
	})
	var buf bytes.Buffer
	err := runImplementers(context.Background(), "example.com/app.Store", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	assertSupersededDiagnostic(t, err, buf.String())
}

// TestRunCallers_ServedRecordIsUnaffected: the diagnostic is about the serving
// version and nothing else. A module served at this version keeps every answer
// it had, including the reference-scope verdict where that is the real cause.
func TestRunCallers_ServedRecordIsUnaffected(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Coordinate:     coord,
		Nodes:          []cgdomain.CallNode{{ID: "example.com/app.Root"}},
		ReferenceScope: cgdomain.ReferenceScopeUnknown,
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No callers found for example.com/app.Root") {
		t.Errorf("expected the genuine-zero message, got: %q", out)
	}
	if !strings.Contains(out, "reference-scope-unmeasured") {
		t.Errorf("expected the reference-scope cause to survive where it applies, got: %q", out)
	}
}

// TestRunCallers_MixedGenerationsStillAnswer: a module the store holds at both a
// superseded and the serving version is served, not refused.
func TestRunCallers_MixedGenerationsStillAnswer(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: "0.4.1"},
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Coordinate:     coord,
		Nodes:          []cgdomain.CallNode{{ID: "example.com/app.Root"}},
		ReferenceScope: cgdomain.ReferenceScopeAnalysed,
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No callers found for example.com/app.Root") {
		t.Errorf("expected the genuine-zero message, got: %q", buf.String())
	}
}

// TestCallGraphShow_SupersededPipelineNamesTheGenerations: show is where the
// remedy sends an operator, so it must not answer "run kanonarion callgraph
// first" about a coordinate it is holding several generations of.
func TestCallGraphShow_SupersededPipelineNamesTheGenerations(t *testing.T) {
	uc := supersededStore(t)
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/app@v1.0.0", callGraphShowFlags{}, false, uc, &buf)
	if err == nil {
		t.Fatalf("expected a not-found error, got: %q", buf.String())
	}
	if !strings.Contains(err.Error(), "superseded pipeline 0.4.1") {
		t.Errorf("show does not name the superseded generations: %v", err)
	}
	if !strings.Contains(err.Error(), "kanonarion callgraph example.com/app@v1.0.0") {
		t.Errorf("show does not name the remedy: %v", err)
	}
}
