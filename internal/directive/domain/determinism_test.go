package domain_test

import (
	"math/rand"
	"testing"

	domain "github.com/eitanity/kanonarion/internal/directive/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// TestHash_IsIndependentOfInputOrder is the determinism guard for the directive
// set's content hash. The set holds pairs that tie on the keys the comparator
// used to stop at: one line of one file read as two directives, and one
// replace whose right-hand side is the only thing distinguishing it.
func TestHash_IsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	build := func() []domain.Directive {
		return []domain.Directive{
			{Kind: domain.KindReplace, Source: "go.mod", Line: 12, OldPath: "example.com/dep", NewPath: "example.com/fork", NewVersion: "v1.0.0", Applied: true},
			{Kind: domain.KindReplace, Source: "go.mod", Line: 12, OldPath: "example.com/dep", NewPath: "example.com/other", NewVersion: "v1.0.0", Applied: true},
			{Kind: domain.KindReplace, Source: "go.mod", Line: 12, OldPath: "example.com/dep", IsLocal: true, LocalPath: "../dep"},
			{Kind: domain.KindExclude, Source: "go.mod", Line: 3, OldPath: "example.com/bad", OldVersion: "v0.1.0"},
		}
	}
	var want string
	for i := range determinismShuffles {
		ds := build()
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		rng.Shuffle(len(ds), func(a, b int) { ds[a], ds[b] = ds[b], ds[a] })
		domain.Sort(ds)
		got := domain.Hash(ds)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("shuffle %d: hash %s, shuffle 0 gave %s: the canonical order is not a function of the set alone", i, got, want)
		}
	}
}

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

// TestDirectiveLess_IsKeyedOnEveryField exercises the comparator against every
// field a Directive carries. A field it does not read is a pair it cannot
// decide, which is the whole defect.
func TestDirectiveLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "source", domain.DirectiveLess,
		domain.Directive{Source: "go.mod"}, domain.Directive{Source: "go.work"})
	assertOrders(t, "line", domain.DirectiveLess,
		domain.Directive{Line: 1}, domain.Directive{Line: 2})
	assertOrders(t, "kind", domain.DirectiveLess,
		domain.Directive{Kind: domain.KindExclude}, domain.Directive{Kind: domain.KindReplace})
	assertOrders(t, "old_path", domain.DirectiveLess,
		domain.Directive{OldPath: "a"}, domain.Directive{OldPath: "b"})
	assertOrders(t, "old_version", domain.DirectiveLess,
		domain.Directive{OldVersion: "v1"}, domain.Directive{OldVersion: "v2"})
	assertOrders(t, "new_path", domain.DirectiveLess,
		domain.Directive{NewPath: "a"}, domain.Directive{NewPath: "b"})
	assertOrders(t, "new_version", domain.DirectiveLess,
		domain.Directive{NewVersion: "v1"}, domain.Directive{NewVersion: "v2"})
	assertOrders(t, "is_local", domain.DirectiveLess,
		domain.Directive{}, domain.Directive{IsLocal: true})
	assertOrders(t, "local_path", domain.DirectiveLess,
		domain.Directive{LocalPath: "a"}, domain.Directive{LocalPath: "b"})
	assertOrders(t, "applied", domain.DirectiveLess,
		domain.Directive{}, domain.Directive{Applied: true})
	assertOrders(t, "class", domain.DirectiveLess,
		domain.Directive{Class: domain.RiskUnknown}, domain.Directive{Class: domain.RiskHighest})
	assertOrders(t, "reachability_target", domain.DirectiveLess,
		domain.Directive{ReachabilityTarget: "a"}, domain.Directive{ReachabilityTarget: "b"})
	assertOrders(t, "policy_outcome", domain.DirectiveLess,
		domain.Directive{PolicyOutcome: "a"}, domain.Directive{PolicyOutcome: "b"})
	assertOrders(t, "policy_blocking", domain.DirectiveLess,
		domain.Directive{}, domain.Directive{PolicyBlocking: true})
}
