package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// A listing that holds several versions of one module presents them in
// semantic order. As text "v10.0.0" sorts before "v9.0.0", which is what a
// reader was shown.
func TestSortModules_OrdersVersionsSemantically(t *testing.T) {
	t.Parallel()
	mods := []domain.VendoredModule{
		{Path: "example.com/mod", Version: "v9.0.0"},
		{Path: "example.com/mod", Version: "v10.0.0"},
		{Path: "example.com/mod", Version: "v2.0.0"},
	}
	domain.SortModules(mods)
	want := []string{"v2.0.0", "v9.0.0", "v10.0.0"}
	for i, v := range want {
		if mods[i].Version != v {
			t.Fatalf("sorted versions %v, want %v", versionsOf(mods), want)
		}
	}
}

// The replacement coordinate orders the same way, on the same terms.
func TestSortModules_OrdersReplacementVersionsSemantically(t *testing.T) {
	t.Parallel()
	mods := []domain.VendoredModule{
		{Path: "example.com/mod", Version: "v1.0.0", ReplacementPath: "example.com/fork", ReplacementVersion: "v9.0.0"},
		{Path: "example.com/mod", Version: "v1.0.0", ReplacementPath: "example.com/fork", ReplacementVersion: "v10.0.0"},
	}
	domain.SortModules(mods)
	if mods[0].ReplacementVersion != "v9.0.0" {
		t.Errorf("first replacement is %q, want v9.0.0", mods[0].ReplacementVersion)
	}
}

func TestSortFindings_OrdersVersionsSemantically(t *testing.T) {
	t.Parallel()
	fs := []domain.Finding{
		{Module: "example.com/mod", Kind: "drift", Version: "v10.0.0"},
		{Module: "example.com/mod", Kind: "drift", Version: "v9.0.0"},
	}
	domain.SortFindings(fs)
	if fs[0].Version != "v9.0.0" {
		t.Errorf("first finding is %q, want v9.0.0", fs[0].Version)
	}
}

// A version that is not semver still has a defined place: the comparator is a
// total order, and it is what keeps the hash a function of the set alone.
func TestVendoredModuleLess_StaysTotalOnVersionsSemverRefuses(t *testing.T) {
	t.Parallel()
	a := domain.VendoredModule{Path: "example.com/mod", Version: "main"}
	b := domain.VendoredModule{Path: "example.com/mod", Version: "master"}
	if domain.VendoredModuleLess(a, b) == domain.VendoredModuleLess(b, a) {
		t.Error("two entries differing only in a non-semver version compare equal both ways; the order is not total")
	}
	valid := domain.VendoredModule{Path: "example.com/mod", Version: "v0.0.1"}
	if !domain.VendoredModuleLess(a, valid) {
		t.Error("a version semver refuses does not rank below one it accepts")
	}
}

// The control on the hash cost. A record holding at most one version per module
// path serialises in exactly the order it did before, so its content hash is
// unchanged and no stored record is darkened. That is the measured shape of the
// maintainer's store: every vendor record it holds has one version per path.
func TestHash_OneVersionPerPathIsUnchangedByTheComparator(t *testing.T) {
	t.Parallel()
	mods := []domain.VendoredModule{
		{Path: "example.com/b", Version: "v10.0.0"},
		{Path: "example.com/a", Version: "v9.0.0"},
		{Path: "example.com/c", Version: "v2.0.0"},
	}
	byPath := []domain.VendoredModule{
		{Path: "example.com/a", Version: "v9.0.0"},
		{Path: "example.com/b", Version: "v10.0.0"},
		{Path: "example.com/c", Version: "v2.0.0"},
	}
	domain.SortModules(mods)
	if got, want := domain.Hash(mods, nil), domain.Hash(byPath, nil); got != want {
		t.Errorf("hash %s, want %s: the version leg moved a record whose paths are all distinct", got, want)
	}
}

func versionsOf(mods []domain.VendoredModule) []string {
	out := make([]string, len(mods))
	for i, m := range mods {
		out[i] = m.Version
	}
	return out
}
