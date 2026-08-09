package domain_test

import (
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/iface/domain"
)

func record(t *testing.T, version string, pkgs ...domain.PackageInterface) domain.InterfaceRecord {
	t.Helper()
	return domain.InterfaceRecord{
		Coordinate:    coordinatetest.MustNew("example.com/mod", version),
		Packages:      pkgs,
		OverallStatus: domain.InterfaceStatusExtracted,
	}
}

func pkg(path string, opts ...func(*domain.PackageInterface)) domain.PackageInterface {
	p := domain.PackageInterface{ImportPath: path, Name: "mod"}
	for _, o := range opts {
		o(&p)
	}
	return p
}

func withFunc(name, signature string) func(*domain.PackageInterface) {
	return func(p *domain.PackageInterface) {
		p.Funcs = append(p.Funcs, domain.FuncDecl{Name: name, Signature: signature})
	}
}

func withType(name, signature string, methods ...domain.MethodDecl) func(*domain.PackageInterface) {
	return func(p *domain.PackageInterface) {
		p.Types = append(p.Types, domain.TypeDecl{Name: name, Signature: signature, Methods: methods})
	}
}

func withConst(name, typ string) func(*domain.PackageInterface) {
	return func(p *domain.PackageInterface) {
		p.Consts = append(p.Consts, domain.ValueDecl{Name: name, Type: typ})
	}
}

func withVar(name, typ string) func(*domain.PackageInterface) {
	return func(p *domain.PackageInterface) {
		p.Vars = append(p.Vars, domain.ValueDecl{Name: name, Type: typ})
	}
}

// stubReader is the domain's SignatureReader for these tests: a deterministic
// stand-in that answers from a table rather than by parsing Go.
//
// The domain does not read Go — the port exists precisely so it does not — so
// its tests must not depend on the real parser either. What the real reader
// says about real signatures is measured where it lives, in
// iface/adapters/spelling/goast, and the two are put together in the use-case
// test.
type stubReader struct {
	// spelling holds the pairs this reader calls spelling-equivalent, keyed
	// "from|to".
	spelling map[string]bool
	// registries holds the type texts it calls registry-shaped.
	registries map[string]bool
	// results holds the signatures whose results it calls registry-shaped.
	results map[string]bool
}

func (r stubReader) DiffersOnlyInSpelling(a, b string) bool {
	return a != b && r.spelling[a+"|"+b]
}

func (r stubReader) RegistryShape(typeText string, _ map[string]string) (string, bool) {
	if r.registries[typeText] {
		return typeText, true
	}
	return "", false
}

func (r stubReader) ResultRegistryShape(signature string, _ map[string]string) (string, bool) {
	if r.results[signature] {
		return signature, true
	}
	return "", false
}

var _ domain.SignatureReader = stubReader{}

// respelt is the reader for a comparison in which exactly the named pairs are
// spelling and nothing is a registry.
func respelt(pairs ...[2]string) stubReader {
	r := stubReader{spelling: map[string]bool{}}
	for _, p := range pairs {
		r.spelling[p[0]+"|"+p[1]] = true
	}
	return r
}

// The four categories, each earned by a declaration that belongs in exactly one
// of them. The spelling change is the one that must NOT reach the breaking
// count.
func TestDiffRecords_Categories(t *testing.T) {
	a := record(t, "v1.0.0", pkg("example.com/mod",
		withFunc("Kept", "func Kept() error"),
		withFunc("Gone", "func Gone() error"),
		withFunc("Narrowed", "func Narrowed(s string) error"),
		withFunc("Respelt", "func Respelt(i interface{}) error"),
	))
	b := record(t, "v2.0.0", pkg("example.com/mod",
		withFunc("Kept", "func Kept() error"),
		withFunc("New", "func New() error"),
		withFunc("Narrowed", "func Narrowed(s string, strict bool) error"),
		withFunc("Respelt", "func Respelt(i any) error"),
	))

	diff := domain.DiffRecords(a, b, respelt(
		[2]string{"func Respelt(i interface{}) error", "func Respelt(i any) error"},
	))

	if got, want := len(diff.Added), 1; got != want {
		t.Errorf("added = %d, want %d", got, want)
	}
	if got, want := len(diff.Removed), 1; got != want {
		t.Errorf("removed = %d, want %d", got, want)
	}
	if got, want := len(diff.Changed), 1; got != want {
		t.Errorf("changed = %d, want %d: %+v", got, want, diff.Changed)
	}
	if got, want := len(diff.Spelling), 1; got != want {
		t.Errorf("spelling = %d, want %d: %+v", got, want, diff.Spelling)
	}
	if got, want := diff.BreakingCount(), 2; got != want {
		t.Errorf("BreakingCount = %d, want %d (removed + changed, never spelling)", got, want)
	}
	if !diff.HasChanges() {
		t.Error("HasChanges = false on a record pair with four deltas")
	}
	if diff.Spelling[0].From != "func Respelt(i interface{}) error" ||
		diff.Spelling[0].To != "func Respelt(i any) error" {
		t.Errorf("spelling change lost its texts: %+v", diff.Spelling[0])
	}
}

// The measured shape of the cast bump, at the scale the count is read at: a
// whole surface respelt, nothing broken. With the normalisation removed every
// one of these lands in Changed instead, which is the report the ticket exists
// to prevent.
func TestDiffRecords_WholeSurfaceRespeltIsZeroBreaking(t *testing.T) {
	var oldOpts, newOpts []func(*domain.PackageInterface)
	var pairs [][2]string
	const n = 56
	for i := range n {
		name := string(rune('A'+i%26)) + string(rune('a'+i/26))
		from := "func " + name + "(i interface{}) (v interface{}, err error)"
		to := "func " + name + "(i any) (any, error)"
		oldOpts = append(oldOpts, withFunc(name, from))
		newOpts = append(newOpts, withFunc(name, to))
		pairs = append(pairs, [2]string{from, to})
	}
	reader := respelt(pairs...)
	diff := domain.DiffRecords(
		record(t, "v1.4.1", pkg("example.com/mod", oldOpts...)),
		record(t, "v1.10.0", pkg("example.com/mod", newOpts...)),
		reader,
	)

	if got := diff.BreakingCount(); got != 0 {
		t.Errorf("BreakingCount = %d, want 0", got)
	}
	if got := len(diff.Spelling); got != n {
		t.Errorf("spelling = %d, want %d", got, n)
	}
}

// A version bump that only moved declarations down their files is not a change.
// Positions are deliberately not compared.
func TestDiffRecords_PositionOnlyDeltaIsNoChange(t *testing.T) {
	a := record(t, "v4.5.1", pkg("example.com/mod",
		withType("Parser", "type Parser struct{}", domain.MethodDecl{
			Name: "Parse", Signature: "func Parse(s string) error",
			Position: domain.SourcePosition{File: "parser.go", Line: 10},
		}),
	))
	b := record(t, "v4.5.2", pkg("example.com/mod",
		withType("Parser", "type Parser struct{}", domain.MethodDecl{
			Name: "Parse", Signature: "func Parse(s string) error",
			Position: domain.SourcePosition{File: "parser.go", Line: 91},
		}),
	))

	diff := domain.DiffRecords(a, b, stubReader{})
	if diff.HasChanges() {
		t.Errorf("a line-number move was reported as a change: %+v", diff)
	}
}

// A package under testdata is not part of any module's API: the go tool will not
// build it and no consumer can import it. A version that carries one more of
// them has not added a package, and the exclusion is stated rather than silent.
func TestDiffRecords_TestdataPackagesAreExcludedAndNamed(t *testing.T) {
	a := record(t, "v0.17.0",
		pkg("example.com/mod/text", withFunc("Fold", "func Fold(s string) string")),
	)
	b := record(t, "v0.21.0",
		pkg("example.com/mod/text", withFunc("Fold", "func Fold(s string) string")),
		pkg("example.com/mod/internal/cldrtree/testdata/test1", withFunc("Fixture", "func Fixture() error")),
	)

	diff := domain.DiffRecords(a, b, stubReader{})
	if len(diff.PackagesAdded) != 0 {
		t.Errorf("testdata package reported as added: %v", diff.PackagesAdded)
	}
	if len(diff.Added) != 0 {
		t.Errorf("testdata declarations reported as added: %+v", diff.Added)
	}
	if got, want := diff.ExcludedTestdataPackages,
		[]string{"example.com/mod/internal/cldrtree/testdata/test1"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("excluded packages = %v, want %v", got, want)
	}
}

// A testdata package on the A side is excluded too, and each excluded path is
// named once however many sides it appears on.
func TestDiffRecords_TestdataExclusionIsDeduplicatedAcrossSides(t *testing.T) {
	td := pkg("example.com/mod/testdata/fixture", withFunc("Fixture", "func Fixture() error"))
	diff := domain.DiffRecords(
		record(t, "v1.0.0", pkg("example.com/mod"), td),
		record(t, "v2.0.0", pkg("example.com/mod"), td),
		stubReader{},
	)
	if got := diff.ExcludedTestdataPackages; len(got) != 1 {
		t.Errorf("excluded packages = %v, want exactly one entry", got)
	}
	if len(diff.PackagesRemoved) != 0 || len(diff.PackagesAdded) != 0 {
		t.Errorf("testdata package leaked into the package delta: +%v -%v",
			diff.PackagesAdded, diff.PackagesRemoved)
	}
}

// A whole package appearing or disappearing is reported, and its declarations
// are counted once — in Added/Removed, where the breaking count reads them.
func TestDiffRecords_PackageDelta(t *testing.T) {
	a := record(t, "v1.0.0",
		pkg("example.com/mod", withFunc("F", "func F() error")),
		pkg("example.com/mod/gone", withFunc("G", "func G() error")),
	)
	b := record(t, "v2.0.0",
		pkg("example.com/mod", withFunc("F", "func F() error")),
		pkg("example.com/mod/fresh", withFunc("H", "func H() error")),
	)

	diff := domain.DiffRecords(a, b, stubReader{})
	if got, want := diff.PackagesRemoved, []string{"example.com/mod/gone"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("packages removed = %v, want %v", got, want)
	}
	if got, want := diff.PackagesAdded, []string{"example.com/mod/fresh"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("packages added = %v, want %v", got, want)
	}
	if got, want := diff.BreakingCount(), 1; got != want {
		t.Errorf("BreakingCount = %d, want %d (the removed package's one declaration)", got, want)
	}
}

// Every kind of exported declaration is compared, and a method is told apart
// from a package-level function of the same name.
func TestDiffRecords_EveryDeclarationKind(t *testing.T) {
	a := record(t, "v1.0.0", pkg("example.com/mod",
		withFunc("Run", "func Run() error"),
		withType("Client", "type Client struct{}", domain.MethodDecl{
			Name: "Run", Signature: "func Run() error", PtrReceiver: true,
		}),
		withConst("Limit", "int"),
		withVar("Default", "*Client"),
	))
	b := record(t, "v2.0.0", pkg("example.com/mod",
		withFunc("Run", "func Run(ctx context.Context) error"),
		withType("Client", "type Client struct{ Name string }", domain.MethodDecl{
			Name: "Run", Signature: "func Run(ctx context.Context) error", PtrReceiver: true,
		}),
		withConst("Limit", "int64"),
		withVar("Default", "Client"),
	))

	diff := domain.DiffRecords(a, b, stubReader{})
	if got, want := len(diff.Changed), 5; got != want {
		t.Fatalf("changed = %d, want %d: %+v", got, want, diff.Changed)
	}
	kinds := map[domain.SymbolKind]string{}
	for _, c := range diff.Changed {
		kinds[c.Symbol.Kind] = c.Symbol.Name
	}
	for kind, name := range map[domain.SymbolKind]string{
		domain.SymbolFunc:   "Run",
		domain.SymbolType:   "Client",
		domain.SymbolMethod: "Client.Run",
		domain.SymbolConst:  "Limit",
		domain.SymbolVar:    "Default",
	} {
		if kinds[kind] != name {
			t.Errorf("kind %s = %q, want %q", kind, kinds[kind], name)
		}
	}
	for _, c := range diff.Changed {
		if c.Symbol.Kind == domain.SymbolMethod && !c.PtrReceiver {
			t.Error("a pointer-receiver method lost its receiver form, which a call-graph lookup needs")
		}
	}
}

// The order of every collection is fixed, so two runs over the same records
// produce the same output and a JSON diff of two runs is empty.
func TestDiffRecords_DeterministicOrder(t *testing.T) {
	a := record(t, "v1.0.0",
		pkg("example.com/mod/z", withFunc("Z", "func Z() error")),
		pkg("example.com/mod/a", withFunc("A", "func A() error"), withType("T", "type T int")),
	)
	b := record(t, "v2.0.0")

	diff := domain.DiffRecords(a, b, stubReader{})
	want := []domain.SymbolID{
		{Package: "example.com/mod/a", Kind: domain.SymbolFunc, Name: "A"},
		{Package: "example.com/mod/a", Kind: domain.SymbolType, Name: "T"},
		{Package: "example.com/mod/z", Kind: domain.SymbolFunc, Name: "Z"},
	}
	if len(diff.Removed) != len(want) {
		t.Fatalf("removed = %d, want %d", len(diff.Removed), len(want))
	}
	for i, w := range want {
		if diff.Removed[i].ID != w {
			t.Errorf("removed[%d] = %+v, want %+v", i, diff.Removed[i].ID, w)
		}
	}
	if got, want := diff.PackagesRemoved,
		[]string{"example.com/mod/a", "example.com/mod/z"}; got[0] != want[0] || got[1] != want[1] {
		t.Errorf("packages removed = %v, want %v", got, want)
	}
}

// An empty comparison says nothing changed and nothing was excluded, and the
// records it compared are carried through for the renderer to name.
func TestDiffRecords_IdenticalRecords(t *testing.T) {
	a := record(t, "v1.0.0", pkg("example.com/mod", withFunc("F", "func F() error")))
	diff := domain.DiffRecords(a, a, stubReader{})
	if diff.HasChanges() || diff.BreakingCount() != 0 {
		t.Errorf("identical records reported a delta: %+v", diff)
	}
	if diff.RecordA.Coordinate.Version() != "v1.0.0" || diff.RecordB.Coordinate.Version() != "v1.0.0" {
		t.Error("the compared records did not survive into the diff")
	}
	if diff.Registries != nil {
		t.Errorf("registries = %v, want nil on a record with no registry surface", diff.Registries)
	}
}

// The registry blind spot, at the level this package owns it: the surfaces the
// reader flags are collected from every place a package can publish one — a
// variable, a constant, a function result, a method result — attributed to the
// side they were seen on, and deduplicated across the two.
//
// What COUNTS as a registry shape is the reader's judgement and is measured in
// iface/adapters/spelling/goast; sprig hands its FuncMap out from a function,
// which is why the function and method legs exist here at all.
func TestDiffRecords_RegistrySurfacesCollected(t *testing.T) {
	reader := stubReader{
		registries: map[string]bool{
			"map[string]func(int) error": true,
			"map[string]any":             true,
		},
		results: map[string]bool{
			"func FuncMap() template.FuncMap": true,
			"func Funcs() map[string]any":     true,
		},
	}
	a := record(t, "v2.22.0", pkg("example.com/mod",
		withFunc("FuncMap", "func FuncMap() template.FuncMap"),
		withVar("Handlers", "map[string]func(int) error"),
		withConst("Aliases", "map[string]any"),
		withType("Codec", "type Codec struct{}", domain.MethodDecl{
			Name: "Funcs", Signature: "func Funcs() map[string]any",
		}),
		withConst("Nope", "int"),
		withFunc("Plain", "func Plain() error"),
	))
	b := record(t, "v3.3.0", pkg("example.com/mod",
		withFunc("FuncMap", "func FuncMap() template.FuncMap"),
	))

	diff := domain.DiffRecords(a, b, reader)
	got := map[string]domain.RegistrySurface{}
	for _, r := range diff.Registries {
		got[r.Symbol.Name] = r
	}
	for _, want := range []string{"FuncMap", "Handlers", "Aliases", "Codec.Funcs"} {
		if _, ok := got[want]; !ok {
			t.Errorf("registry surface %q not collected; got %v", want, keysOf(got))
		}
	}
	for _, unwanted := range []string{"Nope", "Plain"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("%q flagged as a registry surface", unwanted)
		}
	}
	if got["FuncMap"].Side != domain.RegistryInBoth {
		t.Errorf("FuncMap side = %q, want %q", got["FuncMap"].Side, domain.RegistryInBoth)
	}
	if got["Handlers"].Side != domain.RegistryInA {
		t.Errorf("Handlers side = %q, want %q", got["Handlers"].Side, domain.RegistryInA)
	}
	if got["Handlers"].Shape == "" {
		t.Error("a collected surface carries no shape")
	}
}

// A surface only the newer record has is attributed to B.
func TestDiffRecords_RegistryIntroducedInB(t *testing.T) {
	diff := domain.DiffRecords(
		record(t, "v1.0.0", pkg("example.com/mod")),
		record(t, "v2.0.0", pkg("example.com/mod", withVar("Funcs", "map[string]any"))),
		stubReader{registries: map[string]bool{"map[string]any": true}},
	)
	if len(diff.Registries) != 1 || diff.Registries[0].Side != domain.RegistryInB {
		t.Errorf("registries = %+v, want one surface attributed to B", diff.Registries)
	}
}

// A comparison handed no reader does not quietly do less: it discounts nothing
// as spelling and detects no registry, which overstates the delta rather than
// understating it — the safe direction for a count a consumer acts on.
func TestDiffRecords_NoReaderIsConservative(t *testing.T) {
	a := record(t, "v1.0.0", pkg("example.com/mod",
		withFunc("Cast", "func Cast(i interface{}) error"),
		withVar("Funcs", "map[string]any"),
	))
	b := record(t, "v2.0.0", pkg("example.com/mod",
		withFunc("Cast", "func Cast(i any) error"),
		withVar("Funcs", "map[string]any"),
	))

	diff := domain.DiffRecords(a, b, nil)
	if got, want := diff.BreakingCount(), 1; got != want {
		t.Errorf("BreakingCount = %d, want %d: without a reader nothing is discounted", got, want)
	}
	if len(diff.Spelling) != 0 {
		t.Errorf("spelling = %+v, want none without a reader", diff.Spelling)
	}
	if len(diff.Registries) != 0 {
		t.Errorf("registries = %+v, want none without a reader", diff.Registries)
	}
}

// SymbolID renders for display with its package, name and kind.
func TestSymbolID_String(t *testing.T) {
	id := domain.SymbolID{Package: "example.com/mod", Kind: domain.SymbolMethod, Name: "Parser.Parse"}
	if got, want := id.String(), "example.com/mod.Parser.Parse (method)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// A record that carries no packages at all still diffs, and a coordinate is
// still what the result is about.
func TestDiffRecords_EmptyRecords(t *testing.T) {
	var zero coordinate.ModuleCoordinate
	diff := domain.DiffRecords(domain.InterfaceRecord{}, domain.InterfaceRecord{}, stubReader{})
	if diff.HasChanges() {
		t.Error("two empty records reported a delta")
	}
	if diff.RecordA.Coordinate != zero {
		t.Error("an empty record did not survive into the diff")
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// -- cross-major path pairs --

// recordAt builds a record for an arbitrary module path, which the same-path
// helper above cannot: a cross-major comparison is precisely one where the two
// sides do not share a module path.
func recordAt(t *testing.T, path, version string, pkgs ...domain.PackageInterface) domain.InterfaceRecord {
	t.Helper()
	return domain.InterfaceRecord{
		Coordinate:    coordinatetest.MustNew(path, version),
		Packages:      pkgs,
		OverallStatus: domain.InterfaceStatusExtracted,
	}
}

// The sprig shape: every declaration carried over byte-identical under a new
// module path. Comparing by fully-qualified identity called that seven removals
// and seven additions; it is one import rewrite and no breaking change at all.
func TestDiffRecords_CrossMajorCarriesTheSurfaceOverAsRenamedPath(t *testing.T) {
	a := recordAt(t, "example.com/mod", "v2.22.0+incompatible", pkg("example.com/mod",
		withFunc("TxtFuncMap", "func TxtFuncMap() ttemplate.FuncMap"),
		withType("DSAKeyFormat", "type DSAKeyFormat int"),
	))
	b := recordAt(t, "example.com/mod/v3", "v3.3.0", pkg("example.com/mod/v3",
		withFunc("TxtFuncMap", "func TxtFuncMap() ttemplate.FuncMap"),
		withType("DSAKeyFormat", "type DSAKeyFormat int"),
	))

	diff := domain.DiffRecords(a, b, nil)

	if !diff.MajorPathPair {
		t.Error("a /v3 bump was not recognised as a major-version path pair")
	}
	if diff.BreakingCount() != 0 {
		t.Errorf("breaking count = %d, want 0: nothing was removed and no signature changed",
			diff.BreakingCount())
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Changed) != 0 {
		t.Errorf("added=%d removed=%d changed=%d, want all zero", len(diff.Added), len(diff.Removed), len(diff.Changed))
	}
	if len(diff.RenamedPath) != 2 {
		t.Fatalf("renamed-path = %d, want 2:\n%+v", len(diff.RenamedPath), diff.RenamedPath)
	}
	// The pair's own path shift is not a package coming or going.
	if len(diff.PackagesAdded) != 0 || len(diff.PackagesRemoved) != 0 {
		t.Errorf("packages added=%v removed=%v; the pair's own path shift must not read as either",
			diff.PackagesAdded, diff.PackagesRemoved)
	}
	got := diff.RenamedPath[0]
	if got.From.Package != "example.com/mod" || got.To.Package != "example.com/mod/v3" {
		t.Errorf("rename does not name both sides: %+v", got)
	}
	if got.Signature != "func TxtFuncMap() ttemplate.FuncMap" {
		t.Errorf("rename carries no signature: %+v", got)
	}
	if !diff.HasChanges() {
		t.Error("a surface that must be re-imported reported no change at all")
	}
	if !diff.ZeroBreakingOverNonTrivialDelta() {
		t.Error("a zero over seven forced import rewrites was treated as an empty delta")
	}
}

// The control the reclassification must not swallow: a declaration that really
// is gone across the major bump still counts, and a really new one is still an
// addition.
func TestDiffRecords_CrossMajorGenuineRemovalStillBreaks(t *testing.T) {
	a := recordAt(t, "example.com/mod", "v1.5.0", pkg("example.com/mod",
		withFunc("Kept", "func Kept() error"),
		withFunc("Gone", "func Gone() error"),
	))
	b := recordAt(t, "example.com/mod/v3", "v3.3.0", pkg("example.com/mod/v3",
		withFunc("Kept", "func Kept() error"),
		withFunc("Fresh", "func Fresh() error"),
	))

	diff := domain.DiffRecords(a, b, nil)

	if diff.BreakingCount() != 1 {
		t.Errorf("breaking count = %d, want 1", diff.BreakingCount())
	}
	if len(diff.Removed) != 1 || diff.Removed[0].ID.Name != "Gone" {
		t.Errorf("removed = %+v, want only Gone", diff.Removed)
	}
	if len(diff.Added) != 1 || diff.Added[0].ID.Name != "Fresh" {
		t.Errorf("added = %+v, want only Fresh", diff.Added)
	}
	if len(diff.RenamedPath) != 1 || diff.RenamedPath[0].From.Name != "Kept" {
		t.Errorf("renamed-path = %+v, want only Kept", diff.RenamedPath)
	}
}

// A declaration that matches on identity and whose signature genuinely changed
// is ONE breaking change, not a removal and an addition. Counting it twice
// inflated both columns and told the reader to look for a symbol that is still
// there.
func TestDiffRecords_CrossMajorSignatureChangeIsOneChangeNotTwo(t *testing.T) {
	a := recordAt(t, "example.com/mod", "v1.5.0", pkg("example.com/mod",
		withFunc("Parse", "func Parse(s string) (*Token, error)"),
	))
	b := recordAt(t, "example.com/mod/v3", "v3.3.0", pkg("example.com/mod/v3",
		withFunc("Parse", "func Parse(s string, opts ...ParserOption) (*Token, error)"),
	))

	diff := domain.DiffRecords(a, b, nil)

	if diff.BreakingCount() != 1 {
		t.Errorf("breaking count = %d, want 1", diff.BreakingCount())
	}
	if len(diff.Removed) != 0 || len(diff.Added) != 0 {
		t.Errorf("a changed declaration was double-counted: removed=%+v added=%+v", diff.Removed, diff.Added)
	}
	if len(diff.Changed) != 1 {
		t.Fatalf("changed = %+v, want one", diff.Changed)
	}
	c := diff.Changed[0]
	// Symbol is the A side — what a consumer of the baseline calls today, and
	// what its recorded call-graph nodes are spelled as.
	if c.Symbol.Package != "example.com/mod" || c.MovedTo.Package != "example.com/mod/v3" {
		t.Errorf("change does not name both identities: %+v", c)
	}
	if diff.ZeroBreakingOverNonTrivialDelta() {
		t.Error("a delta with a real breaking change claimed to be zero-breaking")
	}
}

// The spelling discount survives the identity change: a signature that differs
// only in a spelling the language treats as identical is a spelling change on a
// cross-major pair too, and stays out of the breaking count.
func TestDiffRecords_CrossMajorSpellingIsStillSpelling(t *testing.T) {
	a := recordAt(t, "example.com/mod", "v1.0.0", pkg("example.com/mod",
		withFunc("Cast", "func Cast(i interface{}) error"),
	))
	b := recordAt(t, "example.com/mod/v2", "v2.0.0", pkg("example.com/mod/v2",
		withFunc("Cast", "func Cast(i any) error"),
	))

	diff := domain.DiffRecords(a, b, respelt(
		[2]string{"func Cast(i interface{}) error", "func Cast(i any) error"},
	))

	if diff.BreakingCount() != 0 {
		t.Errorf("breaking count = %d, want 0", diff.BreakingCount())
	}
	if len(diff.Spelling) != 1 || diff.Spelling[0].MovedTo.Package != "example.com/mod/v2" {
		t.Errorf("spelling = %+v, want one naming both identities", diff.Spelling)
	}
	if len(diff.RenamedPath) != 0 {
		t.Errorf("a respelt declaration was also reported as a pure rename: %+v", diff.RenamedPath)
	}
}

// A subpackage that really came or went across the major bump is still reported,
// under the import path the side it exists on actually spells. Only the pair's
// own path shift is suppressed.
func TestDiffRecords_CrossMajorSubpackageDeltaSurvivesSuppression(t *testing.T) {
	a := recordAt(t, "example.com/mod", "v1.0.0",
		pkg("example.com/mod", withFunc("Kept", "func Kept()")),
		pkg("example.com/mod/old", withFunc("Old", "func Old()")),
	)
	b := recordAt(t, "example.com/mod/v2", "v2.0.0",
		pkg("example.com/mod/v2", withFunc("Kept", "func Kept()")),
		pkg("example.com/mod/v2/fresh", withFunc("Fresh", "func Fresh()")),
	)

	diff := domain.DiffRecords(a, b, nil)

	if len(diff.PackagesRemoved) != 1 || diff.PackagesRemoved[0] != "example.com/mod/old" {
		t.Errorf("packages removed = %v, want the A-side path of the dropped subpackage", diff.PackagesRemoved)
	}
	if len(diff.PackagesAdded) != 1 || diff.PackagesAdded[0] != "example.com/mod/v2/fresh" {
		t.Errorf("packages added = %v, want the B-side path of the new subpackage", diff.PackagesAdded)
	}
}

// A same-path comparison is untouched: no pair is recognised, nothing is
// renamed, and the categories are what they were.
func TestDiffRecords_SamePathIsNotAMajorPair(t *testing.T) {
	a := record(t, "v1.0.0", pkg("example.com/mod", withFunc("Gone", "func Gone()")))
	b := record(t, "v2.0.0", pkg("example.com/mod", withFunc("Fresh", "func Fresh()")))

	diff := domain.DiffRecords(a, b, nil)

	if diff.MajorPathPair {
		t.Error("two versions of one module path were called a major path pair")
	}
	if len(diff.RenamedPath) != 0 {
		t.Errorf("renamed-path = %+v on a same-path comparison", diff.RenamedPath)
	}
	if len(diff.Removed) != 1 || len(diff.Added) != 1 || diff.BreakingCount() != 1 {
		t.Errorf("same-path categories changed: removed=%d added=%d breaking=%d",
			len(diff.Removed), len(diff.Added), diff.BreakingCount())
	}
}

// /v0 and /v1 are not module path suffixes, and a trailing element that merely
// looks like one is not a major. Treating them as a pair would fold two
// unrelated modules' symbols onto each other.
func TestDiffRecords_OnlyRealMajorSuffixesPair(t *testing.T) {
	cases := []struct{ pathA, pathB string }{
		{"example.com/mod", "example.com/mod/v1"},
		{"example.com/mod", "example.com/mod/v0"},
		{"example.com/mod", "example.com/mod/v02"},
		{"example.com/mod", "example.com/mod/vNext"},
		{"example.com/mod", "example.com/other/v2"},
		{"example.com/mod", "example.com/mod/v"},
	}
	for _, tc := range cases {
		t.Run(tc.pathA+" vs "+tc.pathB, func(t *testing.T) {
			a := recordAt(t, tc.pathA, "v1.0.0", pkg(tc.pathA, withFunc("F", "func F()")))
			b := recordAt(t, tc.pathB, "v1.0.0", pkg(tc.pathB, withFunc("F", "func F()")))
			diff := domain.DiffRecords(a, b, nil)
			if diff.MajorPathPair {
				t.Errorf("%s and %s were paired as one module's two majors", tc.pathA, tc.pathB)
			}
			if len(diff.RenamedPath) != 0 {
				t.Errorf("symbols were folded together across unrelated paths: %+v", diff.RenamedPath)
			}
			if diff.BreakingCount() != 1 {
				t.Errorf("breaking count = %d, want 1 — F is gone from the A path", diff.BreakingCount())
			}
		})
	}
}

// The real pair is recognised in both directions, including from one /vN to a
// higher one.
func TestDiffRecords_MajorPairBetweenTwoSuffixedPaths(t *testing.T) {
	a := recordAt(t, "example.com/mod/v4", "v4.5.2", pkg("example.com/mod/v4", withFunc("F", "func F()")))
	b := recordAt(t, "example.com/mod/v5", "v5.3.0", pkg("example.com/mod/v5", withFunc("F", "func F()")))
	diff := domain.DiffRecords(a, b, nil)
	if !diff.MajorPathPair || len(diff.RenamedPath) != 1 {
		t.Errorf("v4 → v5 was not paired: major=%v renamed=%+v", diff.MajorPathPair, diff.RenamedPath)
	}
}

// A package a record carries that does not sit under its own module path keeps
// its full import path as its identity, so it cannot be folded onto some other
// package's declarations by accident.
func TestDiffRecords_ForeignPackageIsNotFoldedOntoTheModuleRoot(t *testing.T) {
	a := recordAt(t, "example.com/mod", "v1.0.0",
		pkg("elsewhere.com/other", withFunc("F", "func F()")),
	)
	b := recordAt(t, "example.com/mod/v2", "v2.0.0",
		pkg("example.com/mod/v2", withFunc("F", "func F()")),
	)

	diff := domain.DiffRecords(a, b, nil)

	if len(diff.RenamedPath) != 0 {
		t.Errorf("a package outside the module was folded onto the module root: %+v", diff.RenamedPath)
	}
	if len(diff.Removed) != 1 || len(diff.Added) != 1 {
		t.Errorf("removed=%+v added=%+v, want the conservative reading", diff.Removed, diff.Added)
	}
}

// The statement's own gate: a zero over an empty delta is not the case the
// statement is for, and a non-zero breaking count never is.
func TestInterfaceDiff_ZeroBreakingOverNonTrivialDelta(t *testing.T) {
	sym := domain.SymbolID{Package: "example.com/mod", Kind: domain.SymbolFunc, Name: "F"}
	cases := []struct {
		name string
		diff domain.InterfaceDiff
		want bool
	}{
		{"empty delta", domain.InterfaceDiff{}, false},
		{"spelling only", domain.InterfaceDiff{Spelling: []domain.SignatureChange{{Symbol: sym}}}, true},
		{"addition only", domain.InterfaceDiff{Added: []domain.Symbol{{ID: sym}}}, true},
		{"rename only", domain.InterfaceDiff{RenamedPath: []domain.RenamedSymbol{{From: sym, To: sym}}}, true},
		{"a removal is breaking", domain.InterfaceDiff{Removed: []domain.Symbol{{ID: sym}}}, false},
		{"a change is breaking", domain.InterfaceDiff{Changed: []domain.SignatureChange{{Symbol: sym}}}, false},
		{
			"a removal beside a respelling is still breaking",
			domain.InterfaceDiff{
				Removed:  []domain.Symbol{{ID: sym}},
				Spelling: []domain.SignatureChange{{Symbol: sym}},
			},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.diff.ZeroBreakingOverNonTrivialDelta(); got != tc.want {
				t.Errorf("ZeroBreakingOverNonTrivialDelta = %v, want %v", got, tc.want)
			}
		})
	}
}
