package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"

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
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, rec)

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
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, rec)

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
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
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

// TestRunCallers_NonEmptyAnswerStatesTheNarrowing is the case the empty-result
// path already covered and the populated one did not: a list of one production
// caller is indistinguishable from an unnarrowed query that found one caller,
// so a narrowed answer has to name its own scope. The second half is the
// non-zero control — an unnarrowed answer must claim no narrowing.
func TestRunCallers_NonEmptyAnswerStatesTheNarrowing(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Target", Symbol: "Target"}}, nil))
	uc.SetCallers([]cgports.CallEdgeRef{{
		ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
		FromID: "example.com/m.Prod", ToID: "example.com/m.Target",
		Confidence: cgdomain.ConfidenceDirect,
	}})

	var narrowed bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Target", false, uc, &narrowed, buildScope{},
		cgports.EdgeQueryOptions{ExcludeTests: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(narrowed.String(), "test callers omitted (--"+testScopeFlagName+" was given)") {
		t.Errorf("a narrowed non-empty answer does not state its scope: %q", narrowed.String())
	}

	var wide bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Target", false, uc, &wide, buildScope{},
		cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(wide.String(), "omitted") {
		t.Errorf("an unnarrowed answer claims a narrowing: %q", wide.String())
	}
}

// TestRunCallees_NonEmptyAnswerStatesTheNarrowing: the callees direction is not
// the callers one with the arrow reversed as far as output goes, so it is
// asserted separately rather than assumed.
func TestRunCallees_NonEmptyAnswerStatesTheNarrowing(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil))
	uc.SetCallees([]cgports.CallEdgeRef{{
		ModulePath: "example.com/m", ModuleVersion: "v1.0.0",
		FromID: "example.com/m.Root", ToID: "example.com/m.Leaf",
		Confidence: cgdomain.ConfidenceDirect,
	}})

	var narrowed bytes.Buffer
	if err := runCallees(context.Background(), "example.com/m.Root", false, uc, &narrowed, buildScope{},
		cgports.EdgeQueryOptions{ExcludeTests: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(narrowed.String(), "test callees omitted (--"+testScopeFlagName+" was given)") {
		t.Errorf("a narrowed non-empty answer does not state its scope: %q", narrowed.String())
	}

	var wide bytes.Buffer
	if err := runCallees(context.Background(), "example.com/m.Root", false, uc, &wide, buildScope{},
		cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(wide.String(), "omitted") {
		t.Errorf("an unnarrowed answer claims a narrowing: %q", wide.String())
	}
}

// TestRunCallers_NarrowedAnswerStatesItOnceOnly: the empty path carries the
// narrowing on its verdict line already. The scope line must not double it up,
// or the same fact is stated twice in two phrasings.
func TestRunCallers_NarrowedAnswerStatesItOnceOnly(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Target", Symbol: "Target"}}, nil))

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Target", false, uc, &buf, buildScope{},
		cgports.EdgeQueryOptions{ExcludeTests: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "production only") {
		t.Fatalf("the empty path lost its verdict-line narrowing: %q", out)
	}
	if strings.Contains(out, "test callers omitted") {
		t.Errorf("the narrowing is stated twice on an empty answer: %q", out)
	}
}

// TestTransitiveResultJSON_CarriesTheScope: the transitive surface already
// returns an envelope, so the narrowing has somewhere machine-readable to live.
// The field is always present — a consumer must never read an absent field as
// "nothing was excluded".
func TestTransitiveResultJSON_CarriesTheScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts cgports.EdgeQueryOptions
		want string
	}{
		{"narrowed", cgports.EdgeQueryOptions{ExcludeTests: true},
			"test callers omitted (--" + testScopeFlagName + " was given)"},
		{"wide", cgports.EdgeQueryOptions{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := printTransitiveResult("callers", "example.com/m.Target", 0,
				[]string{"example.com/m.Prod"}, nil, true, &buf, tc.opts); err != nil {
				t.Fatalf("printTransitiveResult: %v", err)
			}
			var got struct {
				Scope *string `json:"scope"`
			}
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if got.Scope == nil {
				t.Fatalf("scope absent from the envelope: %q", buf.String())
			}
			if tc.want == "" {
				if *got.Scope != "" {
					t.Errorf("an unnarrowed traversal claims a narrowing: %q", *got.Scope)
				}
				return
			}
			if !strings.Contains(*got.Scope, tc.want) {
				t.Errorf("scope %q does not state %q", *got.Scope, tc.want)
			}
		})
	}
}
