package domain_test

import (
	"math/rand"
	"testing"

	domain "github.com/eitanity/kanonarion/internal/godebug/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// TestHash_IsIndependentOfInputOrder is the determinism guard for the godebug
// setting set's content hash. The settings tie on source, line, name and value
// — the keys the comparator used to stop at — and differ in the module they
// were read from, whether they apply, and their tier.
func TestHash_IsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	build := func() []domain.Setting {
		return []domain.Setting{
			{Name: "http2client", Value: "0", Source: "main.go", Line: 3, Module: "example.com/mod", Applied: true},
			{Name: "http2client", Value: "0", Source: "main.go", Line: 3, Module: "example.com/dep", Applied: false},
			{Name: "x509sha1", Value: "1", Source: "main.go", Line: 4, Module: "example.com/mod", Applied: true},
		}
	}
	var want string
	for i := range determinismShuffles {
		ss := build()
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		rng.Shuffle(len(ss), func(a, b int) { ss[a], ss[b] = ss[b], ss[a] })
		domain.Sort(ss)
		got := domain.Hash(ss)
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

// TestSettingLess_IsKeyedOnEveryField exercises the comparator against every
// field a Setting carries.
func TestSettingLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "source", domain.SettingLess,
		domain.Setting{Source: "a.go"}, domain.Setting{Source: "b.go"})
	assertOrders(t, "line", domain.SettingLess,
		domain.Setting{Line: 1}, domain.Setting{Line: 2})
	assertOrders(t, "name", domain.SettingLess,
		domain.Setting{Name: "a"}, domain.Setting{Name: "b"})
	assertOrders(t, "value", domain.SettingLess,
		domain.Setting{Value: "0"}, domain.Setting{Value: "1"})
	assertOrders(t, "module", domain.SettingLess,
		domain.Setting{Module: "a"}, domain.Setting{Module: "b"})
	assertOrders(t, "applied", domain.SettingLess,
		domain.Setting{}, domain.Setting{Applied: true})
	assertOrders(t, "tier", domain.SettingLess,
		domain.Setting{Tier: domain.TierUnknown}, domain.Setting{Tier: domain.TierRed})
	assertOrders(t, "policy_outcome", domain.SettingLess,
		domain.Setting{PolicyOutcome: "a"}, domain.Setting{PolicyOutcome: "b"})
	assertOrders(t, "policy_blocking", domain.SettingLess,
		domain.Setting{}, domain.Setting{PolicyBlocking: true})
}
