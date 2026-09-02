package cli

import (
	"bytes"
	"context"
	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

const (
	implPortID  = "example.com/m/ports.Store"
	implAdapter = "example.com/m/adapter.(*Store)"
	implFake    = "example.com/m/app_test.(*fakeStore)"
	implModule  = "example.com/m"
	// The fixtures describe records this build serves: a query answers from the
	// serving pipeline version, so a fixture pinned to a literal would stop
	// exercising the path it was written for the next time that version moves.
	implPipeline = cgapp.PipelineVersion
)

// implRecord is an analysed record declaring one port with a production
// adapter and a test fake implementing it.
func implRecord() cgdomain.CallGraphRecord {
	rec := builtRecord([]cgdomain.CallNode{
		{ID: implAdapter + ".Put", Symbol: "Put"},
		{ID: implFake + ".Put", Symbol: "Put", IsTest: true},
	}, nil)
	rec.Interfaces = []cgdomain.InterfaceType{
		{ID: implPortID, Package: "example.com/m/ports", Name: "Store", Methods: []string{"Put"}},
	}
	rec.Implementations = []cgdomain.InterfaceImplementation{
		{
			InterfaceID: implPortID,
			TypeID:      implAdapter,
			Package:     "example.com/m/adapter",
			Methods:     []cgdomain.ImplementedMethod{{Method: "Put", NodeID: implAdapter + ".Put"}},
		},
		{
			InterfaceID: implPortID,
			TypeID:      implFake,
			Package:     "example.com/m/app_test",
			IsTest:      true,
			Methods:     []cgdomain.ImplementedMethod{{Method: "Put", NodeID: implFake + ".Put"}},
		},
	}
	return rec
}

func runImpl(t *testing.T, queryID string, jsonOut bool, rec cgdomain.CallGraphRecord, opts cgports.EdgeQueryOptions) string {
	t.Helper()
	uc := fakeWithRecord(implModule, "v1.0.0", implPipeline, rec)
	var buf bytes.Buffer
	if err := runImplementers(context.Background(), queryID, jsonOut, uc, &buf, buildScope{}, opts); err != nil {
		t.Fatalf("runImplementers(%q): %v", queryID, err)
	}
	return buf.String()
}

// TestRunImplementers_ListsProductionAndTestTypes is the headline: the answer to
// "what must change with this port" includes the test fakes, which is where the
// bulk of a signature change's edit surface lives.
func TestRunImplementers_ListsProductionAndTestTypes(t *testing.T) {
	out := runImpl(t, implPortID, false, implRecord(), cgports.EdgeQueryOptions{})
	for _, want := range []string{implAdapter, implFake, "[test]", "RESOLVED-PRESENT"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRunImplementers_ExcludeTests keeps the production-only view available and
// says on the scope line that it was asked for.
func TestRunImplementers_ExcludeTests(t *testing.T) {
	out := runImpl(t, implPortID, false, implRecord(), cgports.EdgeQueryOptions{ExcludeTests: true})
	if strings.Contains(out, implFake) {
		t.Errorf("test implementer survived --exclude-tests:\n%s", out)
	}
	if !strings.Contains(out, implAdapter) {
		t.Errorf("production implementer missing:\n%s", out)
	}
	if !strings.Contains(out, "--"+testScopeFlagName+" was given") {
		t.Errorf("scope line does not state the exclusion:\n%s", out)
	}
	if !strings.Contains(out, "1 implementer of") {
		t.Errorf("count not rendered in the singular:\n%s", out)
	}
}

// TestRunImplementers_PerMethodForm resolves each implementer to the concrete
// node supplying the method, which is what the caller then feeds to callers or
// callees.
func TestRunImplementers_PerMethodForm(t *testing.T) {
	out := runImpl(t, "example.com/m/ports.(Store).Put", false, implRecord(), cgports.EdgeQueryOptions{})
	if !strings.Contains(out, implAdapter+".Put") {
		t.Errorf("per-method form did not name the concrete node:\n%s", out)
	}
}

// TestRunImplementers_ScopeIsAlwaysStated: the relation covers the declaring
// module's own types, and a reader who assumes otherwise reads a complete
// answer to a narrow question as an incomplete answer to a wide one.
func TestRunImplementers_ScopeIsAlwaysStated(t *testing.T) {
	out := runImpl(t, implPortID, false, implRecord(), cgports.EdgeQueryOptions{})
	if !strings.Contains(out, "types in other modules that satisfy this interface are not measured") {
		t.Errorf("scope not stated:\n%s", out)
	}
}

// TestRunImplementers_DeclaredButUnimplementedIsAbsent: a declared interface
// with no implementers over a fully-measured module is a measurement, and says
// which set it measured rather than claiming a universal absence.
func TestRunImplementers_DeclaredButUnimplementedIsAbsent(t *testing.T) {
	rec := implRecord()
	rec.Implementations = nil
	out := runImpl(t, implPortID, false, rec, cgports.EdgeQueryOptions{})
	if !strings.Contains(out, "RESOLVED-ABSENT") {
		t.Errorf("expected RESOLVED-ABSENT:\n%s", out)
	}
	if !strings.Contains(out, "no type in "+implModule+" satisfies") {
		t.Errorf("absent verdict does not name the measured set:\n%s", out)
	}
}

// TestRunImplementers_UnmeasuredTestScopeDowngrades: over a record that never
// looked at test files, an empty implementer set cannot be reported as a
// measurement — test fakes are exactly what would have been found.
func TestRunImplementers_UnmeasuredTestScopeDowngrades(t *testing.T) {
	rec := implRecord()
	rec.Implementations = nil
	rec.TestScope = cgdomain.TestScopeUnknown
	out := runImpl(t, implPortID, false, rec, cgports.EdgeQueryOptions{})
	if !strings.Contains(out, "UNRESOLVED") {
		t.Errorf("expected UNRESOLVED over an unmeasured test axis:\n%s", out)
	}
	if !strings.Contains(out, string(cgdomain.SinkTestScopeUnmeasured)) {
		t.Errorf("verdict does not name the unmeasured axis:\n%s", out)
	}
}

// TestRunImplementers_UnknownInterfaceIsAnError distinguishes "not an interface
// this module declares" from "an interface with no implementers"; returning an
// empty list for the first would be an absence-as-answer.
func TestRunImplementers_UnknownInterfaceIsAnError(t *testing.T) {
	uc := fakeWithRecord(implModule, "v1.0.0", implPipeline, implRecord())
	var buf bytes.Buffer
	err := runImplementers(context.Background(), "example.com/m/ports.NoSuchInterface", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatalf("expected an error, got output: %q", buf.String())
	}
	if !strings.Contains(err.Error(), "is not an interface declared by the analysed module") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRunImplementers_UnknownMethodNamesTheRealOnes fails usefully rather than
// answering a question about a method the interface does not have.
func TestRunImplementers_UnknownMethodNamesTheRealOnes(t *testing.T) {
	uc := fakeWithRecord(implModule, "v1.0.0", implPipeline, implRecord())
	var buf bytes.Buffer
	err := runImplementers(context.Background(), "example.com/m/ports.(Store).Nope", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatal("expected an error for a method the interface does not declare")
	}
	if !strings.Contains(err.Error(), "its methods are Put") {
		t.Errorf("error does not name the real methods: %v", err)
	}
}

// TestRunImplementers_JSONCarriesVerdictAndScope keeps the machine-readable
// shape as honest as the text one.
func TestRunImplementers_JSONCarriesVerdictAndScope(t *testing.T) {
	out := runImpl(t, implPortID, true, implRecord(), cgports.EdgeQueryOptions{})
	for _, want := range []string{`"answer"`, `"scope"`, `"is_test"`, `"count": 2`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON missing %q:\n%s", want, out)
		}
	}
}
