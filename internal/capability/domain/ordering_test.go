package domain

import (
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
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
}
