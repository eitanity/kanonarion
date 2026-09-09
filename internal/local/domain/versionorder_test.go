package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

// The uncovered listing is read by a person deciding what to scan next, so
// several versions of one module present in semantic order.
func TestSortUncovered_OrdersVersionsSemantically(t *testing.T) {
	t.Parallel()
	mods := []domain.UncoveredModule{
		{Path: "example.com/mod", Version: "v10.0.0", Reason: "r"},
		{Path: "example.com/mod", Version: "v9.0.0", Reason: "r"},
		{Path: "example.com/mod", Version: "v2.0.0", Reason: "r"},
	}
	domain.SortUncovered(mods)
	for i, want := range []string{"v2.0.0", "v9.0.0", "v10.0.0"} {
		if mods[i].Version != want {
			t.Fatalf("position %d is %q, want %q", i, mods[i].Version, want)
		}
	}
}

// A version semver refuses still has a defined place, so the comparator stays a
// total order and two entries never tie.
func TestUncoveredModuleLess_StaysTotalOnVersionsSemverRefuses(t *testing.T) {
	t.Parallel()
	a := domain.UncoveredModule{Path: "example.com/mod", Version: "main"}
	b := domain.UncoveredModule{Path: "example.com/mod", Version: "master"}
	if domain.UncoveredModuleLess(a, b) == domain.UncoveredModuleLess(b, a) {
		t.Error("two entries differing only in a non-semver version compare equal both ways; the order is not total")
	}
	if !domain.UncoveredModuleLess(a, domain.UncoveredModule{Path: "example.com/mod", Version: "v0.0.1"}) {
		t.Error("a version semver refuses does not rank below one it accepts")
	}
}

func TestModuleProbeResultLess_OrdersVersionsSemantically(t *testing.T) {
	t.Parallel()
	a := domain.ModuleProbeResult{Path: "example.com/mod", Version: "v9.0.0"}
	b := domain.ModuleProbeResult{Path: "example.com/mod", Version: "v10.0.0"}
	if !domain.ModuleProbeResultLess(a, b) {
		t.Error("v9.0.0 does not order before v10.0.0")
	}
	if domain.ModuleProbeResultLess(b, a) {
		t.Error("v10.0.0 orders before v9.0.0")
	}
}
