package domain_test

import (
	"math/rand"
	"testing"

	domain "github.com/eitanity/kanonarion/internal/fips/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// TestHash_IsIndependentOfInputOrder is the determinism guard for the FIPS
// finding set's content hash. Two toolchain findings hold no source or line at
// all — the type documents that — so they tied on every key the comparator had
// and differed only in the variant they name.
func TestHash_IsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	build := func() []domain.Finding {
		return []domain.Finding{
			{Kind: domain.FindingToolchain, Toolchain: "boringcrypto", ToolchainRaw: "GOEXPERIMENT=boringcrypto"},
			{Kind: domain.FindingToolchain, Toolchain: "microsoft/go", ToolchainRaw: "GOFIPS=1"},
			{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/mod", Source: "a.go", Line: 7},
			{Kind: domain.FindingAlgorithm, Package: "crypto/md5", Module: "example.com/mod", Source: "a.go", Line: 7, Category: domain.CategoryDeviation},
		}
	}
	var want string
	for i := range determinismShuffles {
		fs := build()
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		rng.Shuffle(len(fs), func(a, b int) { fs[a], fs[b] = fs[b], fs[a] })
		domain.Sort(fs)
		got := domain.Hash(true, "boringcrypto", "GOEXPERIMENT=boringcrypto", fs)
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

// TestFindingLess_IsKeyedOnEveryField exercises the comparator against every
// field a Finding carries. The kind is keyed as well as its RANK: every kind
// outside the catalogue collapses to one rank, so the rank alone leaves two
// findings of different kinds tied.
func TestFindingLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "kind rank", domain.FindingLess,
		domain.Finding{Kind: domain.FindingToolchain}, domain.Finding{Kind: domain.FindingAlgorithm})
	assertOrders(t, "kind within one rank", domain.FindingLess,
		domain.Finding{Kind: "unlisted-a"}, domain.Finding{Kind: "unlisted-b"})
	assertOrders(t, "source", domain.FindingLess,
		domain.Finding{Source: "a.go"}, domain.Finding{Source: "b.go"})
	assertOrders(t, "line", domain.FindingLess,
		domain.Finding{Line: 1}, domain.Finding{Line: 2})
	assertOrders(t, "package", domain.FindingLess,
		domain.Finding{Package: "a"}, domain.Finding{Package: "b"})
	assertOrders(t, "module", domain.FindingLess,
		domain.Finding{Module: "a"}, domain.Finding{Module: "b"})
	assertOrders(t, "toolchain", domain.FindingLess,
		domain.Finding{Toolchain: "a"}, domain.Finding{Toolchain: "b"})
	assertOrders(t, "toolchain_raw", domain.FindingLess,
		domain.Finding{ToolchainRaw: "a"}, domain.Finding{ToolchainRaw: "b"})
	assertOrders(t, "category", domain.FindingLess,
		domain.Finding{Category: domain.CategoryCompliant}, domain.Finding{Category: domain.CategoryDeviation})
	assertOrders(t, "policy_outcome", domain.FindingLess,
		domain.Finding{PolicyOutcome: "a"}, domain.Finding{PolicyOutcome: "b"})
	assertOrders(t, "policy_blocking", domain.FindingLess,
		domain.Finding{}, domain.Finding{PolicyBlocking: true})
}
