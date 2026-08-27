package domain

import "sort"

// This file holds the one canonical ordering per collection in an
// ExampleRecord.
//
// Examples were ordered on (Package, AssociatedSymbol, Name) and parse failures
// on File alone. Neither is an identity. Package is a DIRECTORY, not a package
// clause, so the internal and the external test package of one directory report
// the same value, and each may declare ExampleFoo; and one file fails to parse
// for as many reasons as the parser finds. On a tie the comparator gave no
// answer and sort.Slice, which is not stable, decided the pair by the order the
// walk emitted it in, so the sealed bytes moved between extractions.
//
// Each comparator is keyed on every field the canonical wire shape carries, so
// no two distinct elements compare equal and the order is a function of the set
// alone. sort.SliceStable is not the alternative: the input order comes from a
// directory walk, so it is not a property of the module either.

// ExampleEntryLess is the canonical ordering for ExampleEntry slices. The three
// documented keys lead, because that is the order a reader scans the list in;
// the remaining wire fields follow so that two examples of one name in one
// directory still have a defined order.
func ExampleEntryLess(a, b ExampleEntry) bool {
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	if a.AssociatedSymbol != b.AssociatedSymbol {
		return a.AssociatedSymbol < b.AssociatedSymbol
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.SubExample != b.SubExample {
		return a.SubExample < b.SubExample
	}
	if a.Position.File != b.Position.File {
		return a.Position.File < b.Position.File
	}
	if a.Position.Line != b.Position.Line {
		return a.Position.Line < b.Position.Line
	}
	if a.Body != b.Body {
		return a.Body < b.Body
	}
	if a.Output != b.Output {
		return a.Output < b.Output
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.Validates != b.Validates {
		return !a.Validates
	}
	result, _ := sliceLess(a.Imports, b.Imports, stringLess)
	return result
}

// ParseFailureLess is the canonical ordering for ParseFailure slices. One file
// can fail for more than one reason, so File alone does not identify a failure.
func ParseFailureLess(a, b ParseFailure) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Error < b.Error
}

// stringLess adapts string ordering to the generic slice comparator.
func stringLess(a, b string) bool { return a < b }

// sliceLess orders two slices of already-canonically-ordered elements,
// shorter-first, then element by element. decided is false when the two slices
// hold equal elements throughout, which lets a caller fall through to its next
// key rather than reading "not less" as "less-or-equal".
func sliceLess[T any](a, b []T, less func(x, y T) bool) (result, decided bool) {
	if len(a) != len(b) {
		return len(a) < len(b), true
	}
	for i := range a {
		switch {
		case less(a[i], b[i]):
			return true, true
		case less(b[i], a[i]):
			return false, true
		}
	}
	return false, false
}

// sortSlice orders a slice through one of the named comparators above.
func sortSlice[T any](s []T, less func(a, b T) bool) {
	sort.Slice(s, func(i, j int) bool { return less(s[i], s[j]) })
}

// sortExamples puts an example list into canonical order, each entry's own
// import list first: the comparator descends into it, and only compares like
// with like once it is itself sorted.
func sortExamples(examples []ExampleEntry) {
	for i := range examples {
		sort.Strings(examples[i].Imports)
	}
	sortSlice(examples, ExampleEntryLess)
}
