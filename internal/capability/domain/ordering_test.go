package domain

import (
	"reflect"
	"slices"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself. Together over
// every field the element carries, that is what "total order" means: no two
// DISTINCT elements compare equal, so the sort has no tie to resolve.
func assertOrders[T any](t *testing.T, key string, less func(a, b T) bool, lower, upper T) {
	t.Helper()
	if !less(lower, upper) {
		t.Errorf("%s: the comparator does not order two elements differing only in this field", key)
	}
	if less(upper, lower) {
		t.Errorf("%s: the comparator is not antisymmetric", key)
	}
	if less(lower, lower) {
		t.Errorf("%s: the comparator reports an element less than itself", key)
	}
}

// TestCapabilityFindingLess_IsKeyedOnEveryField exercises the finding
// comparator against every field a CapabilityFinding carries. It was keyed on
// the capability alone, which is an identity only for as long as the report
// carries one witness per capability.
func TestCapabilityFindingLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "capability", CapabilityFindingLess,
		CapabilityFinding{Capability: "a"}, CapabilityFinding{Capability: "b"})
	assertOrders(t, "sink_package", CapabilityFindingLess,
		CapabilityFinding{SinkPackage: "a"}, CapabilityFinding{SinkPackage: "b"})
	assertOrders(t, "sink_symbol", CapabilityFindingLess,
		CapabilityFinding{SinkSymbol: "a"}, CapabilityFinding{SinkSymbol: "b"})
	assertOrders(t, "weakest_confidence", CapabilityFindingLess,
		CapabilityFinding{WeakestConfidence: cgdomain.EdgeConfidence("a")},
		CapabilityFinding{WeakestConfidence: cgdomain.EdgeConfidence("b")})
	assertOrders(t, "path length", CapabilityFindingLess,
		CapabilityFinding{Path: []string{"a"}}, CapabilityFinding{Path: []string{"a", "b"}})
	assertOrders(t, "path element", CapabilityFindingLess,
		CapabilityFinding{Path: []string{"a"}}, CapabilityFinding{Path: []string{"b"}})
	assertOrders(t, "tier", CapabilityFindingLess,
		CapabilityFinding{Capability: CapabilityNetDial}, CapabilityFinding{Capability: CapabilityCgoCall + "_"})
	assertOrders(t, "reach", CapabilityFindingLess,
		CapabilityFinding{Reach: "a"}, CapabilityFinding{Reach: "b"})
	assertOrders(t, "caller_kind", CapabilityFindingLess,
		CapabilityFinding{CallerKind: "a"}, CapabilityFinding{CallerKind: "b"})
	assertOrders(t, "classified_by", CapabilityFindingLess,
		CapabilityFinding{ClassifiedBy: "a"}, CapabilityFinding{ClassifiedBy: "b"})
	assertOrders(t, "plumbing_only", CapabilityFindingLess,
		CapabilityFinding{}, CapabilityFinding{PlumbingOnly: true})
	assertOrders(t, "basis", CapabilityFindingLess,
		CapabilityFinding{Basis: "a"}, CapabilityFinding{Basis: "b"})
}

// TestRowLess_IsKeyedOnEveryRankingField walks the diff's ranking one field at
// a time: caller kind, tier, confidence, capability, callee, caller, reach.
func TestRowLess_IsKeyedOnEveryRankingField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "caller_kind", RowLess, WitnessRow{CallerKind: CallerInit}, WitnessRow{CallerKind: CallerMain})
	assertOrders(t, "tier", RowLess,
		WitnessRow{Capability: CapabilityLogWrite}, WitnessRow{Capability: CapabilityRuntimeInternal})
	assertOrders(t, "confidence", RowLess,
		WitnessRow{Confidence: cgdomain.ConfidenceDirect}, WitnessRow{Confidence: cgdomain.ConfidenceUnknown})
	assertOrders(t, "capability", RowLess,
		WitnessRow{Capability: CapabilityEnvRead}, WitnessRow{Capability: CapabilityNetDial})
	assertOrders(t, "callee", RowLess, WitnessRow{Callee: "a"}, WitnessRow{Callee: "b"})
	assertOrders(t, "caller", RowLess, WitnessRow{Caller: "a"}, WitnessRow{Caller: "b"})
	assertOrders(t, "reach", RowLess, WitnessRow{Reach: "a"}, WitnessRow{Reach: "b"})
}

func TestRollUpComparatorsAreTotal(t *testing.T) {
	t.Parallel()

	assertOrders(t, "package", packageDefaultLess, PackageDefault{Package: "a"}, PackageDefault{Package: "b"})
	assertOrders(t, "callees", packageDefaultLess, PackageDefault{Callees: 1}, PackageDefault{Callees: 2})
	assertOrders(t, "kind rank", callerKindLess, CallerInit, CallerMain)
	assertOrders(t, "kind name", callerKindLess, CallerKind("a"), CallerKind("b"))
	assertOrders(t, "function", coLocationLess, CoLocation{Function: "a"}, CoLocation{Function: "b"})
	assertOrders(t, "caller_kind", coLocationLess, CoLocation{CallerKind: "a"}, CoLocation{CallerKind: "b"})
	assertOrders(t, "collection", coLocationLess,
		CoLocation{Collection: []string{"a"}}, CoLocation{Collection: []string{"b"}})
	assertOrders(t, "egress", coLocationLess, CoLocation{Egress: []string{"a"}}, CoLocation{Egress: []string{"b"}})
}

// The report is a property of the graph, not of the order its nodes and edges
// were stored in: reversing both must not move a byte of it.
func TestAnalyseIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	rec := richGraph()
	rec.Nodes = append(rec.Nodes,
		node("m.init", "m", "init", false, false),
		node("os.Getenv", "os", "Getenv", true, false),
		node("io/ioutil.ReadFile", "io/ioutil", "ReadFile", true, false),
		node("os.ReadFile", "os", "ReadFile", true, false))
	rec.Edges = append(rec.Edges,
		edge("m.init", "m.Root", cgdomain.ConfidenceDirect),
		edge("m.Mid", "os.Getenv", cgdomain.ConfidenceDirect),
		edge("m.Mid", "io/ioutil.ReadFile", cgdomain.ConfidenceDirect),
		edge("m.Root", "os.ReadFile", cgdomain.ConfidenceDirect),
		edge("m.Root", "net.Dial", cgdomain.ConfidenceDirect))
	want := Analyse(rec, SelectRoots(rec, cgdomain.RootScopeProduction), cgdomain.RootScopeProduction)

	rev := rec
	rev.Nodes = slices.Clone(rec.Nodes)
	rev.Edges = slices.Clone(rec.Edges)
	slices.Reverse(rev.Nodes)
	slices.Reverse(rev.Edges)
	got := Analyse(rev, SelectRoots(rev, cgdomain.RootScopeProduction), cgdomain.RootScopeProduction)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the report moved with input order:\n got %+v\nwant %+v", got, want)
	}
	if len(want.CollectsAndEgresses) == 0 || len(want.InitReachesBoth) == 0 || len(want.SensitiveCalls) < 3 {
		t.Errorf("the fixture should exercise the roll-up: %+v", want)
	}
}
