package domain

import "sort"

// This file holds the one canonical ordering per collection in an
// InterfaceRecord.
//
// Every collection here used to be ordered on a single key — Name for
// declarations, ImportPath for packages, File for parse failures. A single key
// is only an ordering if it identifies the element, and in Go source it does
// not: two files in one directory can each declare a function of the same name
// (only one of them is in any given build, and the extractor reads the
// directory, not a build), a struct can carry two fields of one name across
// build-constrained files, and one file can fail to parse for two reasons. On a
// tie the comparator gave no answer, sort.Slice is not stable, and the relative
// order of the tied pair was whatever the sort happened to do with the order
// the extractor emitted. The sealed bytes moved with it, so two extractions of
// one module version disagreed and the coordinate could never be served.
//
// Each comparator below is keyed on every field its collection puts on the
// wire, descending into nested collections rather than stopping at a scalar
// prefix, so no two distinct elements compare equal and the sorted order is a
// function of the set alone. That makes sort.Slice correct here.
// sort.SliceStable would not be an alternative: stability decides ties by input
// order, and the input order comes from a directory walk and from map
// iteration, so it is not a property of the module either.
//
// Sorting is bottom-up. A comparator that descends into a nested collection
// compares like with like only once that collection is itself in canonical
// order, so sortPackage sorts the leaves before the branches.

// TypeParamLess is the canonical ordering for TypeParam slices. Name and
// Constraint are the whole of the type, so this is total.
func TypeParamLess(a, b TypeParam) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Constraint < b.Constraint
}

// FieldDeclLess is the canonical ordering for FieldDecl slices, keyed on every
// field the canonical wire shape carries.
func FieldDeclLess(a, b FieldDecl) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Tag != b.Tag {
		return a.Tag < b.Tag
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.Embedded != b.Embedded {
		return !a.Embedded
	}
	if a.IsGenerated != b.IsGenerated {
		return !a.IsGenerated
	}
	return positionLess(a.Position, b.Position)
}

// MethodDeclLess is the canonical ordering for MethodDecl slices, keyed on
// every field the canonical wire shape carries.
func MethodDeclLess(a, b MethodDecl) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Signature != b.Signature {
		return a.Signature < b.Signature
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.PtrReceiver != b.PtrReceiver {
		return !a.PtrReceiver
	}
	return positionLess(a.Position, b.Position)
}

// ValueDeclLess is the canonical ordering for the Consts and Vars slices, keyed
// on every field the canonical wire shape carries.
func ValueDeclLess(a, b ValueDecl) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.IsGenerated != b.IsGenerated {
		return !a.IsGenerated
	}
	return positionLess(a.Position, b.Position)
}

// ParseFailureLess is the canonical ordering for ParseFailure slices. One file
// can fail for more than one reason, so File alone does not identify a failure.
func ParseFailureLess(a, b ParseFailure) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Error < b.Error
}

// FuncDeclLess is the canonical ordering for FuncDecl slices. This is the
// comparator the defect was found on: golang.org/x/tools ships testdata
// directories where two files each declare a function of one name, and Name
// alone left that pair to the sort. Sort each function's TypeParams before
// comparing, so the final key compares like with like.
func FuncDeclLess(a, b FuncDecl) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Signature != b.Signature {
		return a.Signature < b.Signature
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.IsGenerated != b.IsGenerated {
		return !a.IsGenerated
	}
	if a.Position != b.Position {
		return positionLess(a.Position, b.Position)
	}
	result, _ := sliceLess(a.TypeParams, b.TypeParams, TypeParamLess)
	return result
}

// TypeDeclLess is the canonical ordering for TypeDecl slices. The scalars come
// first because that is the order a reader scans a declaration in; the member
// lists follow so that two declarations sharing a name, kind and signature
// still order by their members. Sort the member lists themselves first.
func TypeDeclLess(a, b TypeDecl) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Signature != b.Signature {
		return a.Signature < b.Signature
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.IsGenerated != b.IsGenerated {
		return !a.IsGenerated
	}
	if a.Position != b.Position {
		return positionLess(a.Position, b.Position)
	}
	if result, decided := sliceLess(a.TypeParams, b.TypeParams, TypeParamLess); decided {
		return result
	}
	if result, decided := sliceLess(a.Fields, b.Fields, FieldDeclLess); decided {
		return result
	}
	if result, decided := sliceLess(a.Methods, b.Methods, MethodDeclLess); decided {
		return result
	}
	result, _ := sliceLess(a.EmbeddedTypes, b.EmbeddedTypes, stringLess)
	return result
}

// PackageInterfaceLess is the canonical ordering for the record's Packages.
// ImportPath is very nearly an identity, but "very nearly" is what put every
// other comparator in this file wrong, so the remaining wire fields follow it,
// ending in the package's own declaration lists. Sort those lists first.
func PackageInterfaceLess(a, b PackageInterface) bool {
	if a.ImportPath != b.ImportPath {
		return a.ImportPath < b.ImportPath
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Doc != b.Doc {
		return a.Doc < b.Doc
	}
	if a.IsInternal != b.IsInternal {
		return !a.IsInternal
	}
	if a.IsMain != b.IsMain {
		return !a.IsMain
	}
	if a.OutOfFrame != b.OutOfFrame {
		return !a.OutOfFrame
	}
	if result, decided := sliceLess(a.Types, b.Types, TypeDeclLess); decided {
		return result
	}
	if result, decided := sliceLess(a.Funcs, b.Funcs, FuncDeclLess); decided {
		return result
	}
	if result, decided := sliceLess(a.Consts, b.Consts, ValueDeclLess); decided {
		return result
	}
	if result, decided := sliceLess(a.Vars, b.Vars, ValueDeclLess); decided {
		return result
	}
	result, _ := sliceLess(a.ParseFailures, b.ParseFailures, ParseFailureLess)
	return result
}

// positionLess orders two source positions.
func positionLess(a, b SourcePosition) bool {
	if a.File != b.File {
		return a.File < b.File
	}
	return a.Line < b.Line
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

// sortPackage puts one package's collections into canonical order, leaves
// first: a comparator that descends into a nested collection is only comparing
// like with like once that collection is itself sorted.
func sortPackage(p *PackageInterface) {
	for i := range p.Types {
		t := &p.Types[i]
		sort.Slice(t.TypeParams, func(a, b int) bool { return TypeParamLess(t.TypeParams[a], t.TypeParams[b]) })
		sort.Slice(t.Fields, func(a, b int) bool { return FieldDeclLess(t.Fields[a], t.Fields[b]) })
		sort.Slice(t.Methods, func(a, b int) bool { return MethodDeclLess(t.Methods[a], t.Methods[b]) })
		sort.Strings(t.EmbeddedTypes)
	}
	for i := range p.Funcs {
		tp := p.Funcs[i].TypeParams
		sort.Slice(tp, func(a, b int) bool { return TypeParamLess(tp[a], tp[b]) })
	}
	sort.Slice(p.Types, func(i, j int) bool { return TypeDeclLess(p.Types[i], p.Types[j]) })
	sort.Slice(p.Funcs, func(i, j int) bool { return FuncDeclLess(p.Funcs[i], p.Funcs[j]) })
	sort.Slice(p.Consts, func(i, j int) bool { return ValueDeclLess(p.Consts[i], p.Consts[j]) })
	sort.Slice(p.Vars, func(i, j int) bool { return ValueDeclLess(p.Vars[i], p.Vars[j]) })
	sort.Slice(p.ParseFailures, func(i, j int) bool { return ParseFailureLess(p.ParseFailures[i], p.ParseFailures[j]) })
}

// sortPackages puts a package list into canonical order, each package's own
// collections first.
func sortPackages(pkgs []PackageInterface) {
	for i := range pkgs {
		sortPackage(&pkgs[i])
	}
	sort.Slice(pkgs, func(i, j int) bool { return PackageInterfaceLess(pkgs[i], pkgs[j]) })
}
