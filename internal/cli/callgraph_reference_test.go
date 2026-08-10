package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// TestRunCallers_ReferenceEdgeReportsTheRegistrationSite is the end-to-end shape
// of the defect: a handler registered as a method value has no call edge, and
// used to answer "no callers". It now answers with the registrar, labelled a
// reference so nobody reads the registration as an invocation.
func TestRunCallers_ReferenceEdgeReportsTheRegistrationSite(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.(*H).confirmEmail", Symbol: "confirmEmail", Receiver: "*H"}}, nil))
	uc.SetCallers([]cgports.CallEdgeRef{{
		ModulePath:    "example.com/m",
		ModuleVersion: "v1.0.0",
		FromID:        "example.com/m.(*H).MountRoutes",
		ToID:          "example.com/m.(*H).confirmEmail",
		Confidence:    cgdomain.ConfidenceDirect,
		Kind:          cgdomain.EdgeKindReference,
	}})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.(*H).confirmEmail", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/m.(*H).MountRoutes") {
		t.Errorf("the registration site is not in the answer: %q", out)
	}
	if !strings.Contains(out, "reference") {
		t.Errorf("the answer does not say the edge is a reference rather than a call: %q", out)
	}
}

// TestRunCallers_UnmeasuredReferenceScopeIsUnresolved pairs the two halves the
// verdict contract needs. A record whose analysis never looked for function
// values cannot claim an absence — but the control beside it, a record that DID
// look, still reports a confident RESOLVED-ABSENT. Without the control this test
// would pass just as well if the verdict had simply been switched off.
func TestRunCallers_UnmeasuredReferenceScopeIsUnresolved(t *testing.T) {
	unmeasured := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	unmeasured.ReferenceScope = cgdomain.ReferenceScopeUnknown
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, unmeasured)

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "UNRESOLVED") {
		t.Fatalf("an unmeasured reference axis must not claim absence, got: %q", out)
	}
	if !strings.Contains(out, string(cgdomain.SinkReferenceScopeUnmeasured)) {
		t.Errorf("the verdict does not name the unmeasured axis: %q", out)
	}

	// The control. Same symbol, same empty answer, a record that measured both
	// axes — still a confident negative.
	measured := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil))
	var ctrl bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Root", false, measured, &ctrl, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error on the control: %v", err)
	}
	if !strings.Contains(ctrl.String(), "RESOLVED-ABSENT") {
		t.Errorf("the control lost its confident negative, so the verdict was disabled rather than corrected: %q", ctrl.String())
	}
}

// TestRunCallers_TestHarnessEntryIsUnresolved covers the same false measurement
// at a second surface. A test function is invoked on every `go test` run, by a
// main package the analysis deliberately does not read; reporting "no callers,
// proven" for it is as wrong as it was for the registered handler.
func TestRunCallers_TestHarnessEntryIsUnresolved(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{
		{ID: "example.com/m.TestThing", Symbol: "TestThing", IsTest: true},
		{ID: "example.com/m.(*fake).TestHook", Symbol: "TestHook", Receiver: "*fake", IsTest: true},
	}, nil)
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, rec)

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.TestThing", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "UNRESOLVED") || !strings.Contains(out, string(cgdomain.SinkTestHarnessEntry)) {
		t.Fatalf("a test entry point must not be reported as a proven absence, got: %q", out)
	}

	// The control: a method on a test fake is NOT a harness entry point. It is
	// reached by dispatch or not at all, so its absence is still a measurement.
	var ctrl bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.(*fake).TestHook", false, uc, &ctrl, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error on the control: %v", err)
	}
	if !strings.Contains(ctrl.String(), "RESOLVED-ABSENT") {
		t.Errorf("the control lost its confident negative: %q", ctrl.String())
	}
}
