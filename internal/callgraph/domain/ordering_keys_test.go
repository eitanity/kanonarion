package domain_test

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// assertOrdersOn requires less to order lo before hi and not the reverse.
func assertOrdersOn[T any](t *testing.T, name string, less func(a, b T) bool, lo, hi T) {
	t.Helper()
	if !less(lo, hi) || less(hi, lo) {
		t.Errorf("%s: want lo < hi and not hi < lo", name)
	}
}

// Every key of CallNodeLess decides a pair that agrees on the keys before it.
func TestCallNodeLess_EveryKeyDecides(t *testing.T) {
	base := domain.CallNode{ID: "id"}
	for _, tc := range []struct {
		name string
		hi   func(*domain.CallNode)
	}{
		{"module", func(n *domain.CallNode) { n.Module = "m" }},
		{"package", func(n *domain.CallNode) { n.Package = "p" }},
		{"symbol", func(n *domain.CallNode) { n.Symbol = "s" }},
		{"receiver", func(n *domain.CallNode) { n.Receiver = "r" }},
		{"line", func(n *domain.CallNode) { n.Position.Line = 1 }},
		{"external", func(n *domain.CallNode) { n.IsExternal = true }},
		{"unsafe", func(n *domain.CallNode) { n.UsesUnsafePointer = true }},
		{"assembly", func(n *domain.CallNode) { n.IsAssemblyOrLinkname = true }},
		{"plugin", func(n *domain.CallNode) { n.UsesPlugin = true }},
	} {
		hi := base
		tc.hi(&hi)
		assertOrdersOn(t, tc.name, domain.CallNodeLess, base, hi)
	}
}

func TestInterfaceTypeLess_EveryKeyDecides(t *testing.T) {
	base := domain.InterfaceType{ID: "id"}
	for _, tc := range []struct {
		name string
		hi   func(*domain.InterfaceType)
	}{
		{"package", func(i *domain.InterfaceType) { i.Package = "p" }},
		{"name", func(i *domain.InterfaceType) { i.Name = "n" }},
		{"line", func(i *domain.InterfaceType) { i.Position.Line = 1 }},
		{"test", func(i *domain.InterfaceType) { i.IsTest = true }},
	} {
		hi := base
		tc.hi(&hi)
		assertOrdersOn(t, tc.name, domain.InterfaceTypeLess, base, hi)
	}
}

func TestInterfaceImplementationLess_EveryKeyDecides(t *testing.T) {
	m := func(names ...string) []domain.ImplementedMethod {
		out := make([]domain.ImplementedMethod, 0, len(names))
		for _, n := range names {
			out = append(out, domain.ImplementedMethod{Method: n})
		}
		return out
	}
	base := domain.InterfaceImplementation{InterfaceID: "i", TypeID: "t", Methods: m("a")}
	for _, tc := range []struct {
		name string
		hi   func(*domain.InterfaceImplementation)
	}{
		{"package", func(i *domain.InterfaceImplementation) { i.Package = "p" }},
		{"line", func(i *domain.InterfaceImplementation) { i.Position.Line = 1 }},
		{"method count", func(i *domain.InterfaceImplementation) { i.Methods = m("a", "b") }},
		{"method", func(i *domain.InterfaceImplementation) { i.Methods = m("b") }},
	} {
		hi := base
		tc.hi(&hi)
		assertOrdersOn(t, tc.name, domain.InterfaceImplementationLess, base, hi)
	}
	if domain.InterfaceImplementationLess(base, base) {
		t.Error("an implementation orders before itself")
	}
}

func TestSortDroppedReplaces(t *testing.T) {
	ds := []domain.DroppedReplace{{Path: "b"}, {Path: "a"}}
	domain.SortDroppedReplaces(ds)
	if ds[0].Path != "a" {
		t.Errorf("SortDroppedReplaces left %v", ds)
	}
}

func TestSynthesisedGoModString_CountsRequires(t *testing.T) {
	one := domain.SynthesisedGoMod{ModulePath: "m", GoDirective: "1.21", Requires: []domain.SynthesisedRequire{{Path: "a", Version: "v1"}}}
	if got := one.String(); got != "synthesised go.mod (module m, go 1.21) [1 require directive pinned from a resolved build list, not resolved by the toolchain]" {
		t.Errorf("one: %s", got)
	}
	two := one
	two.Requires = append(two.Requires, domain.SynthesisedRequire{Path: "b", Version: "v1"})
	if got := two.String(); got != "synthesised go.mod (module m, go 1.21) [2 require directives pinned from a resolved build list, not resolved by the toolchain]" {
		t.Errorf("two: %s", got)
	}
}
