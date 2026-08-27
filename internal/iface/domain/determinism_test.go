package domain_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	domain2 "github.com/eitanity/kanonarion/internal/iface/domain"
)

// determinismShuffles is how many independent input orders every determinism
// guard in this repo puts through the canonical form. A comparator that is not
// a total order decides a tied pair by whatever the sort happened to do with
// the input order, so the guard has to supply many input orders; one or two
// would pass on a broken comparator by luck.
const determinismShuffles = 50

// makeTiedRecord builds an InterfaceRecord in which every collection holds two
// DISTINCT elements that tie on the key the collection used to be ordered by.
// The Funcs pair is the real one: golang.org/x/tools ships testdata directories
// where two files in one package each declare a function of the same name, and
// that is the pair whose order used to flip between extractions.
func makeTiedRecord(t *testing.T) domain2.InterfaceRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	return domain2.InterfaceRecord{
		SchemaVersion: domain2.InterfaceSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Packages: []domain2.PackageInterface{
			{
				ImportPath: "example.com/mod/pkg",
				Name:       "pkg",
				Types: []domain2.TypeDecl{
					{
						Name:      "Tied",
						Kind:      domain2.TypeKindStruct,
						Signature: "type Tied struct{ A int }",
						Position:  domain2.SourcePosition{File: "a.go", Line: 3},
						Fields: []domain2.FieldDecl{
							{Name: "Same", Type: "int", Position: domain2.SourcePosition{File: "a.go", Line: 4}},
							{Name: "Same", Type: "string", Position: domain2.SourcePosition{File: "b.go", Line: 4}},
						},
						Methods: []domain2.MethodDecl{
							{Name: "Do", Signature: "func (t Tied) Do()", Position: domain2.SourcePosition{File: "a.go", Line: 9}},
							{Name: "Do", Signature: "func (t *Tied) Do(int)", PtrReceiver: true, Position: domain2.SourcePosition{File: "b.go", Line: 9}},
						},
						EmbeddedTypes: []string{"io.Reader", "io.Writer"},
						TypeParams: []domain2.TypeParam{
							{Name: "T", Constraint: "any"},
							{Name: "T", Constraint: "comparable"},
						},
					},
					{
						Name:      "Tied",
						Kind:      domain2.TypeKindInterface,
						Signature: "type Tied interface{ Do() }",
						Position:  domain2.SourcePosition{File: "b.go", Line: 3},
					},
				},
				Funcs: []domain2.FuncDecl{
					{
						Name:      "BadFunc",
						Signature: "func BadFunc()",
						Position:  domain2.SourcePosition{File: "testdata/src/a/copylock.go", Line: 11},
					},
					{
						Name:      "BadFunc",
						Signature: "func BadFunc(FieldMutex, int)",
						Position:  domain2.SourcePosition{File: "testdata/src/a/copylock_func.go", Line: 11},
						TypeParams: []domain2.TypeParam{
							{Name: "T", Constraint: "any"},
							{Name: "T", Constraint: "comparable"},
						},
					},
				},
				Consts: []domain2.ValueDecl{
					{Name: "Limit", Type: "int", Position: domain2.SourcePosition{File: "a.go", Line: 20}},
					{Name: "Limit", Type: "int64", Position: domain2.SourcePosition{File: "b.go", Line: 20}},
				},
				Vars: []domain2.ValueDecl{
					{Name: "ErrX", Type: "error", Position: domain2.SourcePosition{File: "a.go", Line: 30}},
					{Name: "ErrX", Type: "*Err", Position: domain2.SourcePosition{File: "b.go", Line: 30}},
				},
				ParseFailures: []domain2.ParseFailure{
					{File: "broken.go", Error: "expected ';', found 'EOF'"},
					{File: "broken.go", Error: "expected declaration"},
				},
			},
			// Two packages under one import path: the same directory read in
			// two build frames, or a directory holding two package clauses.
			{ImportPath: "example.com/mod/pkg", Name: "pkg_test", IsMain: false},
		},
		OverallStatus:   domain2.InterfaceStatusPartial,
		ExtractedAt:     time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

// shuffleInterfaceRecord permutes every collection in the record, including
// the nested ones, so no collection keeps the order the builder wrote.
func shuffleInterfaceRecord(rng *rand.Rand, r *domain2.InterfaceRecord) {
	rng.Shuffle(len(r.Packages), func(i, j int) { r.Packages[i], r.Packages[j] = r.Packages[j], r.Packages[i] })
	for pi := range r.Packages {
		p := &r.Packages[pi]
		rng.Shuffle(len(p.Types), func(i, j int) { p.Types[i], p.Types[j] = p.Types[j], p.Types[i] })
		rng.Shuffle(len(p.Funcs), func(i, j int) { p.Funcs[i], p.Funcs[j] = p.Funcs[j], p.Funcs[i] })
		rng.Shuffle(len(p.Consts), func(i, j int) { p.Consts[i], p.Consts[j] = p.Consts[j], p.Consts[i] })
		rng.Shuffle(len(p.Vars), func(i, j int) { p.Vars[i], p.Vars[j] = p.Vars[j], p.Vars[i] })
		rng.Shuffle(len(p.ParseFailures), func(i, j int) {
			p.ParseFailures[i], p.ParseFailures[j] = p.ParseFailures[j], p.ParseFailures[i]
		})
		for ti := range p.Types {
			ty := &p.Types[ti]
			rng.Shuffle(len(ty.Fields), func(i, j int) { ty.Fields[i], ty.Fields[j] = ty.Fields[j], ty.Fields[i] })
			rng.Shuffle(len(ty.Methods), func(i, j int) { ty.Methods[i], ty.Methods[j] = ty.Methods[j], ty.Methods[i] })
			rng.Shuffle(len(ty.EmbeddedTypes), func(i, j int) {
				ty.EmbeddedTypes[i], ty.EmbeddedTypes[j] = ty.EmbeddedTypes[j], ty.EmbeddedTypes[i]
			})
			rng.Shuffle(len(ty.TypeParams), func(i, j int) {
				ty.TypeParams[i], ty.TypeParams[j] = ty.TypeParams[j], ty.TypeParams[i]
			})
		}
		for fi := range p.Funcs {
			tp := p.Funcs[fi].TypeParams
			rng.Shuffle(len(tp), func(i, j int) { tp[i], tp[j] = tp[j], tp[i] })
		}
	}
}

// TestInterfaceRecord_ContentHashIsIndependentOfInputOrder is the determinism
// guard for the interface record. The extractor reads packages from a directory
// walk and collects them through maps, so the order it hands the record in is
// not a property of the module; the sealed bytes must be.
func TestInterfaceRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain2.InterfaceRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedRecord(t)
		shuffleInterfaceRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
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

// TestInterfaceRecord_SortIsIndependentOfInputOrder checks the record's own
// Sort, which callers use before serialising through paths other than the
// hasher, agrees with the hasher on the canonical order.
func TestInterfaceRecord_SortIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	var h domain2.InterfaceRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedRecord(t)
		shuffleInterfaceRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		r.Sort()
		got, err := h.Marshal(r)
		if err != nil {
			t.Fatalf("shuffle %d: Marshal: %v", i, err)
		}
		if i == 0 {
			want = string(got)
			continue
		}
		if string(got) != want {
			t.Fatalf("shuffle %d: Sort produced a different canonical rendering than shuffle 0", i)
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
// field the canonical shape carries. A field the comparator does not read is a
// pair it cannot decide, which is the whole defect: two declarations differing
// only there tie, and sort.Slice puts them in input order.
func TestOrdering_IsKeyedOnEveryWireField(t *testing.T) {
	t.Parallel()

	pos := func(file string, line int) domain2.SourcePosition {
		return domain2.SourcePosition{File: file, Line: line}
	}

	assertOrders(t, "type_param.name", domain2.TypeParamLess,
		domain2.TypeParam{Name: "A"}, domain2.TypeParam{Name: "B"})
	assertOrders(t, "type_param.constraint", domain2.TypeParamLess,
		domain2.TypeParam{Constraint: "any"}, domain2.TypeParam{Constraint: "comparable"})

	assertOrders(t, "field.name", domain2.FieldDeclLess,
		domain2.FieldDecl{Name: "A"}, domain2.FieldDecl{Name: "B"})
	assertOrders(t, "field.type", domain2.FieldDeclLess,
		domain2.FieldDecl{Type: "int"}, domain2.FieldDecl{Type: "string"})
	assertOrders(t, "field.tag", domain2.FieldDeclLess,
		domain2.FieldDecl{Tag: "a"}, domain2.FieldDecl{Tag: "b"})
	assertOrders(t, "field.doc", domain2.FieldDeclLess,
		domain2.FieldDecl{Doc: "a"}, domain2.FieldDecl{Doc: "b"})
	assertOrders(t, "field.embedded", domain2.FieldDeclLess,
		domain2.FieldDecl{}, domain2.FieldDecl{Embedded: true})
	assertOrders(t, "field.is_generated", domain2.FieldDeclLess,
		domain2.FieldDecl{}, domain2.FieldDecl{IsGenerated: true})
	assertOrders(t, "field.position.file", domain2.FieldDeclLess,
		domain2.FieldDecl{Position: pos("a.go", 1)}, domain2.FieldDecl{Position: pos("b.go", 1)})
	assertOrders(t, "field.position.line", domain2.FieldDeclLess,
		domain2.FieldDecl{Position: pos("a.go", 1)}, domain2.FieldDecl{Position: pos("a.go", 2)})

	assertOrders(t, "method.name", domain2.MethodDeclLess,
		domain2.MethodDecl{Name: "A"}, domain2.MethodDecl{Name: "B"})
	assertOrders(t, "method.signature", domain2.MethodDeclLess,
		domain2.MethodDecl{Signature: "a"}, domain2.MethodDecl{Signature: "b"})
	assertOrders(t, "method.doc", domain2.MethodDeclLess,
		domain2.MethodDecl{Doc: "a"}, domain2.MethodDecl{Doc: "b"})
	assertOrders(t, "method.ptr_receiver", domain2.MethodDeclLess,
		domain2.MethodDecl{}, domain2.MethodDecl{PtrReceiver: true})
	assertOrders(t, "method.position", domain2.MethodDeclLess,
		domain2.MethodDecl{Position: pos("a.go", 1)}, domain2.MethodDecl{Position: pos("a.go", 2)})

	assertOrders(t, "value.name", domain2.ValueDeclLess,
		domain2.ValueDecl{Name: "A"}, domain2.ValueDecl{Name: "B"})
	assertOrders(t, "value.type", domain2.ValueDeclLess,
		domain2.ValueDecl{Type: "int"}, domain2.ValueDecl{Type: "string"})
	assertOrders(t, "value.doc", domain2.ValueDeclLess,
		domain2.ValueDecl{Doc: "a"}, domain2.ValueDecl{Doc: "b"})
	assertOrders(t, "value.is_generated", domain2.ValueDeclLess,
		domain2.ValueDecl{}, domain2.ValueDecl{IsGenerated: true})
	assertOrders(t, "value.position", domain2.ValueDeclLess,
		domain2.ValueDecl{Position: pos("a.go", 1)}, domain2.ValueDecl{Position: pos("b.go", 1)})

	assertOrders(t, "parse_failure.file", domain2.ParseFailureLess,
		domain2.ParseFailure{File: "a.go"}, domain2.ParseFailure{File: "b.go"})
	assertOrders(t, "parse_failure.error", domain2.ParseFailureLess,
		domain2.ParseFailure{Error: "a"}, domain2.ParseFailure{Error: "b"})

	assertOrders(t, "func.name", domain2.FuncDeclLess,
		domain2.FuncDecl{Name: "A"}, domain2.FuncDecl{Name: "B"})
	assertOrders(t, "func.signature", domain2.FuncDeclLess,
		domain2.FuncDecl{Signature: "func F()"}, domain2.FuncDecl{Signature: "func F(int)"})
	assertOrders(t, "func.doc", domain2.FuncDeclLess,
		domain2.FuncDecl{Doc: "a"}, domain2.FuncDecl{Doc: "b"})
	assertOrders(t, "func.is_generated", domain2.FuncDeclLess,
		domain2.FuncDecl{}, domain2.FuncDecl{IsGenerated: true})
	assertOrders(t, "func.position", domain2.FuncDeclLess,
		domain2.FuncDecl{Position: pos("a.go", 1)}, domain2.FuncDecl{Position: pos("b.go", 1)})
	assertOrders(t, "func.type_params count", domain2.FuncDeclLess,
		domain2.FuncDecl{}, domain2.FuncDecl{TypeParams: []domain2.TypeParam{{Name: "T"}}})
	assertOrders(t, "func.type_params value", domain2.FuncDeclLess,
		domain2.FuncDecl{TypeParams: []domain2.TypeParam{{Name: "T"}}},
		domain2.FuncDecl{TypeParams: []domain2.TypeParam{{Name: "U"}}})

	assertOrders(t, "type.name", domain2.TypeDeclLess,
		domain2.TypeDecl{Name: "A"}, domain2.TypeDecl{Name: "B"})
	assertOrders(t, "type.kind", domain2.TypeDeclLess,
		domain2.TypeDecl{Kind: domain2.TypeKindStruct}, domain2.TypeDecl{Kind: domain2.TypeKindInterface})
	assertOrders(t, "type.signature", domain2.TypeDeclLess,
		domain2.TypeDecl{Signature: "a"}, domain2.TypeDecl{Signature: "b"})
	assertOrders(t, "type.doc", domain2.TypeDeclLess,
		domain2.TypeDecl{Doc: "a"}, domain2.TypeDecl{Doc: "b"})
	assertOrders(t, "type.is_generated", domain2.TypeDeclLess,
		domain2.TypeDecl{}, domain2.TypeDecl{IsGenerated: true})
	assertOrders(t, "type.position", domain2.TypeDeclLess,
		domain2.TypeDecl{Position: pos("a.go", 1)}, domain2.TypeDecl{Position: pos("b.go", 1)})
	assertOrders(t, "type.type_params", domain2.TypeDeclLess,
		domain2.TypeDecl{}, domain2.TypeDecl{TypeParams: []domain2.TypeParam{{Name: "T"}}})
	assertOrders(t, "type.fields", domain2.TypeDeclLess,
		domain2.TypeDecl{}, domain2.TypeDecl{Fields: []domain2.FieldDecl{{Name: "A"}}})
	assertOrders(t, "type.methods", domain2.TypeDeclLess,
		domain2.TypeDecl{}, domain2.TypeDecl{Methods: []domain2.MethodDecl{{Name: "A"}}})
	assertOrders(t, "type.embedded_types", domain2.TypeDeclLess,
		domain2.TypeDecl{EmbeddedTypes: []string{"a"}}, domain2.TypeDecl{EmbeddedTypes: []string{"b"}})

	assertOrders(t, "package.import_path", domain2.PackageInterfaceLess,
		domain2.PackageInterface{ImportPath: "a"}, domain2.PackageInterface{ImportPath: "b"})
	assertOrders(t, "package.name", domain2.PackageInterfaceLess,
		domain2.PackageInterface{Name: "a"}, domain2.PackageInterface{Name: "b"})
	assertOrders(t, "package.doc", domain2.PackageInterfaceLess,
		domain2.PackageInterface{Doc: "a"}, domain2.PackageInterface{Doc: "b"})
	assertOrders(t, "package.is_internal", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{IsInternal: true})
	assertOrders(t, "package.is_main", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{IsMain: true})
	assertOrders(t, "package.out_of_frame", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{OutOfFrame: true})
	assertOrders(t, "package.types", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{Types: []domain2.TypeDecl{{Name: "A"}}})
	assertOrders(t, "package.funcs", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{Funcs: []domain2.FuncDecl{{Name: "A"}}})
	assertOrders(t, "package.consts", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{Consts: []domain2.ValueDecl{{Name: "A"}}})
	assertOrders(t, "package.vars", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{Vars: []domain2.ValueDecl{{Name: "A"}}})
	assertOrders(t, "package.parse_failures", domain2.PackageInterfaceLess,
		domain2.PackageInterface{}, domain2.PackageInterface{ParseFailures: []domain2.ParseFailure{{File: "a.go"}}})
}
