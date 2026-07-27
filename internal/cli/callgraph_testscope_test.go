package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// TestRunCallers_UnmeasuredTestScopeIsNotAnAbsence is the query-side
// rule: over a record that never analysed _test.go declarations, "no callers"
// is an unmeasured axis, not a measurement. Reporting RESOLVED-ABSENT there is
// how "can I delete this" turns into a broken build.
func TestRunCallers_UnmeasuredTestScopeIsNotAnAbsence(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.TestScope = cgdomain.TestScopeUnknown
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0", rec)

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "UNRESOLVED") {
		t.Fatalf("expected UNRESOLVED over an unmeasured test axis, got: %q", out)
	}
	if !strings.Contains(out, string(cgdomain.SinkTestScopeUnmeasured)) {
		t.Errorf("verdict does not name the unmeasured axis: %q", out)
	}
}

// TestRunCallers_ExcludeTestsStatesTheNarrowing: a caller who asks for
// production-only results gets a confident absent, but the verdict line has to
// say what "none" covered — otherwise the answer reads wider than it is.
func TestRunCallers_ExcludeTestsStatesTheNarrowing(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.TestScope = cgdomain.TestScopeUnknown
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0", rec)

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Root", false, uc, &buf, buildScope{},
		cgports.EdgeQueryOptions{ExcludeTests: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "RESOLVED-ABSENT") {
		t.Fatalf("a requested scope is not a soundness sink, got: %q", out)
	}
	if !strings.Contains(out, "production only") || !strings.Contains(out, "--"+testScopeFlagName) {
		t.Errorf("verdict line does not state the requested scope: %q", out)
	}
}

// TestPrintEdgeRefs_TagsTestEdges keeps the two surfaces separable by eye: a
// caller that is test code is labelled, so a reader scanning a mixed answer can
// tell the production blast radius from the test one without a second query.
func TestPrintEdgeRefs_TagsTestEdges(t *testing.T) {
	refs := []cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Prod", ToID: "example.com/m.Target", Confidence: cgdomain.ConfidenceDirect},
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m_test.TestX", ToID: "example.com/m.Target", Confidence: cgdomain.ConfidenceDirect, IsTest: true},
	}
	var buf bytes.Buffer
	if err := printEdgeRefs("callers", "example.com/m.Target", refs, false, &buf); err != nil {
		t.Fatalf("printEdgeRefs: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		switch {
		case strings.Contains(line, "m.Prod"):
			if strings.Contains(line, "[test]") {
				t.Errorf("production caller tagged as test: %q", line)
			}
		case strings.Contains(line, "TestX"):
			if !strings.Contains(line, "[test]") {
				t.Errorf("test caller not tagged: %q", line)
			}
		}
	}
}

// TestPrintEdgeRefs_JSONCarriesTestRole: the machine-readable shape has to
// carry the same distinction, or a consumer filtering on it silently cannot.
func TestPrintEdgeRefs_JSONCarriesTestRole(t *testing.T) {
	refs := []cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m_test.TestX", ToID: "example.com/m.Target", IsTest: true},
	}
	var buf bytes.Buffer
	if err := printEdgeRefs("callers", "example.com/m.Target", refs, true, &buf); err != nil {
		t.Fatalf("printEdgeRefs: %v", err)
	}
	if !strings.Contains(buf.String(), `"is_test": true`) {
		t.Errorf("JSON does not carry the test role: %s", buf.String())
	}
}

// TestCallGraphShow_ReportsTestScope: every record dump states the axis,
// including when it was not measured. Silence there reads as "there was no test
// code", which is the confusion the axis exists to remove.
func TestCallGraphShow_ReportsTestScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope cgdomain.TestScope
		want  string
	}{
		{"analysed", cgdomain.TestScopeAnalysed, "test scope: analysed"},
		{"excluded", cgdomain.TestScopeExcluded, "test scope: EXCLUDED"},
		{"not recorded", cgdomain.TestScopeUnknown, "test scope: not recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
			rec.TestScope = tc.scope
			rec.NodeCount = len(rec.Nodes)

			var buf bytes.Buffer
			if err := printCallGraphRecord(rec, 10, 10, &buf); err != nil {
				t.Fatalf("printCallGraphRecord: %v", err)
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("output missing %q:\n%s", tc.want, buf.String())
			}
		})
	}
}
