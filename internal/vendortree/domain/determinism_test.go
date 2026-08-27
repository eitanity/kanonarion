package domain_test

import (
	"math/rand"
	"testing"

	domain "github.com/eitanity/kanonarion/internal/vendortree/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// TestHash_IsIndependentOfInputOrder is the determinism guard for the vendor
// tree reconciliation's content hash. The modules tie on path and version and
// differ in the replacement they were vendored from; the findings tie on
// module, kind, version and file and differ in what was expected against what
// was found.
func TestHash_IsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	buildModules := func() []domain.VendoredModule {
		return []domain.VendoredModule{
			{Path: "example.com/dep", Version: "v1.0.0", Present: true, PackageCount: 3, FilesCompared: 9},
			{Path: "example.com/dep", Version: "v1.0.0", Present: true, PackageCount: 3, FilesCompared: 9, ReplacementPath: "example.com/fork", ReplacementVersion: "v1.0.1"},
			{Path: "example.com/other", Version: "v2.0.0", Explicit: true, Present: true},
		}
	}
	buildFindings := func() []domain.Finding {
		return []domain.Finding{
			{Kind: domain.FindingDrift, Module: "example.com/dep", Version: "v1.0.0", File: "a.go", Expected: "sha256:aa", Actual: "sha256:bb"},
			{Kind: domain.FindingDrift, Module: "example.com/dep", Version: "v1.0.0", File: "a.go", Expected: "sha256:cc", Actual: "sha256:dd"},
		}
	}
	var want string
	for i := range determinismShuffles {
		ms, fs := buildModules(), buildFindings()
		rng := rand.New(rand.NewSource(int64(i))) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		rng.Shuffle(len(ms), func(a, b int) { ms[a], ms[b] = ms[b], ms[a] })
		rng.Shuffle(len(fs), func(a, b int) { fs[a], fs[b] = fs[b], fs[a] })
		domain.SortModules(ms)
		domain.SortFindings(fs)
		got := domain.Hash(ms, fs)
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

// TestOrdering_IsKeyedOnEveryField exercises both comparators against every
// field their elements carry.
func TestOrdering_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	assertOrders(t, "module.path", domain.VendoredModuleLess,
		domain.VendoredModule{Path: "a"}, domain.VendoredModule{Path: "b"})
	assertOrders(t, "module.version", domain.VendoredModuleLess,
		domain.VendoredModule{Version: "v1"}, domain.VendoredModule{Version: "v2"})
	assertOrders(t, "module.replacement_path", domain.VendoredModuleLess,
		domain.VendoredModule{ReplacementPath: "a"}, domain.VendoredModule{ReplacementPath: "b"})
	assertOrders(t, "module.replacement_version", domain.VendoredModuleLess,
		domain.VendoredModule{ReplacementVersion: "v1"}, domain.VendoredModule{ReplacementVersion: "v2"})
	assertOrders(t, "module.expected_hash", domain.VendoredModuleLess,
		domain.VendoredModule{ExpectedHash: "a"}, domain.VendoredModule{ExpectedHash: "b"})
	assertOrders(t, "module.package_count", domain.VendoredModuleLess,
		domain.VendoredModule{PackageCount: 1}, domain.VendoredModule{PackageCount: 2})
	assertOrders(t, "module.files_compared", domain.VendoredModuleLess,
		domain.VendoredModule{FilesCompared: 1}, domain.VendoredModule{FilesCompared: 2})
	assertOrders(t, "module.explicit", domain.VendoredModuleLess,
		domain.VendoredModule{}, domain.VendoredModule{Explicit: true})
	assertOrders(t, "module.present", domain.VendoredModuleLess,
		domain.VendoredModule{}, domain.VendoredModule{Present: true})
	assertOrders(t, "module.dir", domain.VendoredModuleLess,
		domain.VendoredModule{Dir: "a"}, domain.VendoredModule{Dir: "b"})

	assertOrders(t, "finding.module", domain.FindingLess,
		domain.Finding{Module: "a"}, domain.Finding{Module: "b"})
	assertOrders(t, "finding.kind", domain.FindingLess,
		domain.Finding{Kind: domain.FindingDrift}, domain.Finding{Kind: domain.FindingExtraInVendor})
	assertOrders(t, "finding.version", domain.FindingLess,
		domain.Finding{Version: "v1"}, domain.Finding{Version: "v2"})
	assertOrders(t, "finding.file", domain.FindingLess,
		domain.Finding{File: "a.go"}, domain.Finding{File: "b.go"})
	assertOrders(t, "finding.expected", domain.FindingLess,
		domain.Finding{Expected: "a"}, domain.Finding{Expected: "b"})
	assertOrders(t, "finding.actual", domain.FindingLess,
		domain.Finding{Actual: "a"}, domain.Finding{Actual: "b"})
	assertOrders(t, "finding.detail", domain.FindingLess,
		domain.Finding{Detail: "a"}, domain.Finding{Detail: "b"})
	assertOrders(t, "finding.policy_outcome", domain.FindingLess,
		domain.Finding{PolicyOutcome: "a"}, domain.Finding{PolicyOutcome: "b"})
	assertOrders(t, "finding.policy_blocking", domain.FindingLess,
		domain.Finding{}, domain.Finding{PolicyBlocking: true})
}
