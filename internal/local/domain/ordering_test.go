package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
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

// TestOrdering_IsKeyedOnEveryField exercises the local-context comparators
// against every field their elements carry. Each was keyed on the path alone,
// which is not an identity: a workspace can import two versions of one module.
func TestOrdering_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "imported.path", domain.ImportedModuleLess,
		domain.ImportedModule{Path: "a"}, domain.ImportedModule{Path: "b"})
	assertOrders(t, "imported.version", domain.ImportedModuleLess,
		domain.ImportedModule{Version: "v1"}, domain.ImportedModule{Version: "v2"})
	assertOrders(t, "imported.imported_packages count", domain.ImportedModuleLess,
		domain.ImportedModule{}, domain.ImportedModule{ImportedPackages: []string{"a"}})
	assertOrders(t, "imported.imported_packages value", domain.ImportedModuleLess,
		domain.ImportedModule{ImportedPackages: []string{"a"}}, domain.ImportedModule{ImportedPackages: []string{"b"}})
	assertOrders(t, "imported.used_symbols", domain.ImportedModuleLess,
		domain.ImportedModule{UsedSymbols: []string{"a"}}, domain.ImportedModule{UsedSymbols: []string{"b"}})
	assertOrders(t, "imported.test_only_packages", domain.ImportedModuleLess,
		domain.ImportedModule{TestOnlyPackages: []string{"a"}}, domain.ImportedModule{TestOnlyPackages: []string{"b"}})
	assertOrders(t, "imported.test_only_symbols", domain.ImportedModuleLess,
		domain.ImportedModule{TestOnlySymbols: []string{"a"}}, domain.ImportedModule{TestOnlySymbols: []string{"b"}})

	assertOrders(t, "uncovered.path", domain.UncoveredModuleLess,
		domain.UncoveredModule{Path: "a"}, domain.UncoveredModule{Path: "b"})
	assertOrders(t, "uncovered.version", domain.UncoveredModuleLess,
		domain.UncoveredModule{Version: "v1"}, domain.UncoveredModule{Version: "v2"})
	assertOrders(t, "uncovered.reason", domain.UncoveredModuleLess,
		domain.UncoveredModule{Reason: "a"}, domain.UncoveredModule{Reason: "b"})

	assertOrders(t, "binary.import_path", domain.ProbedBinaryLess,
		domain.ProbedBinary{ImportPath: "a"}, domain.ProbedBinary{ImportPath: "b"})
	assertOrders(t, "binary.build_error", domain.ProbedBinaryLess,
		domain.ProbedBinary{BuildError: "a"}, domain.ProbedBinary{BuildError: "b"})

	assertOrders(t, "probe.path", domain.ModuleProbeResultLess,
		domain.ModuleProbeResult{Path: "a"}, domain.ModuleProbeResult{Path: "b"})
	assertOrders(t, "probe.version", domain.ModuleProbeResultLess,
		domain.ModuleProbeResult{Version: "v1"}, domain.ModuleProbeResult{Version: "v2"})
	assertOrders(t, "probe.findings count", domain.ModuleProbeResultLess,
		domain.ModuleProbeResult{}, domain.ModuleProbeResult{Findings: []domain.SymbolProbeFinding{{CVEID: "a"}}})
	assertOrders(t, "probe.findings value", domain.ModuleProbeResultLess,
		domain.ModuleProbeResult{Findings: []domain.SymbolProbeFinding{{CVEID: "a"}}},
		domain.ModuleProbeResult{Findings: []domain.SymbolProbeFinding{{CVEID: "b"}}})
}
