package domain_test

import (
	"math/rand"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/example/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// makeTiedExampleRecord builds an ExampleRecord whose collections hold two
// DISTINCT elements that tie on the keys the collection used to be ordered by.
// Package is a directory, not a package clause, so an internal and an external
// test package in one directory both report the same Package; each may declare
// ExampleFoo, and the pair then ties on all three keys. ParseFailures ties
// whenever one file fails for two reasons.
func makeTiedExampleRecord(t *testing.T) domain2.ExampleRecord {
	t.Helper()
	return domain2.ExampleRecord{
		SchemaVersion: domain2.ExampleSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    mustCoord(t, "example.com/mod", "v1.2.3"),
		Examples: []domain2.ExampleEntry{
			{
				Name:             "ExampleFoo",
				Package:          "apiv1",
				AssociatedSymbol: "Foo",
				Body:             "fmt.Println(Foo())",
				Imports:          []string{"fmt", "os"},
				Position:         domain2.SourcePosition{File: "apiv1/foo_test.go", Line: 10},
				Validates:        true,
				Output:           "1\n",
			},
			{
				Name:             "ExampleFoo",
				Package:          "apiv1",
				AssociatedSymbol: "Foo",
				Body:             "_ = foo()",
				Imports:          []string{"os", "fmt"},
				Position:         domain2.SourcePosition{File: "apiv1/internal_test.go", Line: 10},
			},
		},
		ParseFailures: []domain2.ParseFailure{
			{File: "apiv1/broken_test.go", Error: "expected ';', found 'EOF'"},
			{File: "apiv1/broken_test.go", Error: "expected declaration"},
		},
		OverallStatus:   domain2.ExampleStatusFound,
		ExtractedAt:     time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

func shuffleExampleRecord(rng *rand.Rand, r *domain2.ExampleRecord) {
	rng.Shuffle(len(r.Examples), func(i, j int) { r.Examples[i], r.Examples[j] = r.Examples[j], r.Examples[i] })
	for i := range r.Examples {
		imp := r.Examples[i].Imports
		rng.Shuffle(len(imp), func(a, b int) { imp[a], imp[b] = imp[b], imp[a] })
	}
	rng.Shuffle(len(r.ParseFailures), func(i, j int) {
		r.ParseFailures[i], r.ParseFailures[j] = r.ParseFailures[j], r.ParseFailures[i]
	})
}

// TestExampleRecord_ContentHashIsIndependentOfInputOrder is the determinism
// guard for the example record.
func TestExampleRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain2.ExampleRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedExampleRecord(t)
		shuffleExampleRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("shuffle %d: content hash %s, shuffle 0 gave %s: the canonical order is not a function of the record alone",
				i, sealed.ContentHash, want)
		}
	}
}

// TestExampleRecord_SortExamplesIsIndependentOfInputOrder checks the record's
// own SortExamples agrees with the hasher on the canonical order.
func TestExampleRecord_SortExamplesIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain2.ExampleRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedExampleRecord(t)
		shuffleExampleRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		r.SortExamples()
		got, err := h.Marshal(r)
		if err != nil {
			t.Fatalf("shuffle %d: Marshal: %v", i, err)
		}
		if i == 0 {
			want = string(got)
			continue
		}
		if string(got) != want {
			t.Fatalf("shuffle %d: SortExamples produced a different canonical rendering than shuffle 0", i)
		}
	}
}

// assertOrders checks that less decides a pair differing in exactly one field,
// in both directions, and reports an element equal to itself. Together over
// every field the wire shape carries, that is what "total order" means: no two
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

// TestOrdering_IsKeyedOnEveryWireField exercises each comparator against every
// field the canonical shape carries.
func TestOrdering_IsKeyedOnEveryWireField(t *testing.T) {
	t.Parallel()

	pos := func(file string, line int) domain2.SourcePosition {
		return domain2.SourcePosition{File: file, Line: line}
	}

	assertOrders(t, "example.package", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Package: "a"}, domain2.ExampleEntry{Package: "b"})
	assertOrders(t, "example.associated_symbol", domain2.ExampleEntryLess,
		domain2.ExampleEntry{AssociatedSymbol: "A"}, domain2.ExampleEntry{AssociatedSymbol: "B"})
	assertOrders(t, "example.name", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Name: "ExampleA"}, domain2.ExampleEntry{Name: "ExampleB"})
	assertOrders(t, "example.sub_example", domain2.ExampleEntryLess,
		domain2.ExampleEntry{SubExample: "a"}, domain2.ExampleEntry{SubExample: "b"})
	assertOrders(t, "example.position.file", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Position: pos("a_test.go", 1)}, domain2.ExampleEntry{Position: pos("b_test.go", 1)})
	assertOrders(t, "example.position.line", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Position: pos("a_test.go", 1)}, domain2.ExampleEntry{Position: pos("a_test.go", 2)})
	assertOrders(t, "example.body", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Body: "a"}, domain2.ExampleEntry{Body: "b"})
	assertOrders(t, "example.output", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Output: "a"}, domain2.ExampleEntry{Output: "b"})
	assertOrders(t, "example.doc", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Doc: "a"}, domain2.ExampleEntry{Doc: "b"})
	assertOrders(t, "example.validates", domain2.ExampleEntryLess,
		domain2.ExampleEntry{}, domain2.ExampleEntry{Validates: true})
	assertOrders(t, "example.imports count", domain2.ExampleEntryLess,
		domain2.ExampleEntry{}, domain2.ExampleEntry{Imports: []string{"fmt"}})
	assertOrders(t, "example.imports value", domain2.ExampleEntryLess,
		domain2.ExampleEntry{Imports: []string{"fmt"}}, domain2.ExampleEntry{Imports: []string{"os"}})

	assertOrders(t, "parse_failure.file", domain2.ParseFailureLess,
		domain2.ParseFailure{File: "a.go"}, domain2.ParseFailure{File: "b.go"})
	assertOrders(t, "parse_failure.error", domain2.ParseFailureLess,
		domain2.ParseFailure{Error: "a"}, domain2.ParseFailure{Error: "b"})
}
