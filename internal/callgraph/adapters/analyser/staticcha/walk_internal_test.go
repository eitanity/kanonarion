package staticcha

import (
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// wrapperModule takes a method value on a concrete receiver, which is what makes
// SSA materialise the "$bound" wrapper the split below is about.
var wrapperModule = map[string]string{
	"go.mod": "module example.com/wrapprobe\n\ngo 1.21\n",
	"probe.go": `package wrapprobe

var sink func()

type Thing struct{}

func (t *Thing) Work() {}

func init() { sink = nil }

func Register(t *Thing) { sink = t.Work }
`,
}

// buildWrapperProg builds a whole-program SSA for wrapperModule with real
// bodies. Skips (not fails) when no Go toolchain is available in the sandbox.
func buildWrapperProg(t *testing.T) *ssa.Program {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range wrapperModule {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedFiles | packages.NeedImports | packages.NeedDeps,
		Dir:  dir,
		Fset: token.NewFileSet(),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Skipf("packages.Load failed (no Go env?): %v", err)
	}
	if len(pkgs) == 0 || len(pkgs[0].Errors) > 0 {
		t.Skipf("wrapper probe package did not load cleanly; skipping")
	}
	prog, _ := ssautil.AllPackages(pkgs, ssa.BuilderMode(0))
	prog.Build()
	return prog
}

// TestPredicateSplit_WrapperIsNotARealBodyAndIsStillARecordableCaller is the
// point of the change stated as one assertion. Both predicates look at the same
// synthetic wrapper and give OPPOSITE answers, because they answer different
// questions: fnHasRealBody asks "is this a real dispatch site worth
// devirtualizing", where a wrapper is deliberately excluded, and
// fnIsMethodWrapper asks "are this node's outgoing edges worth recording",
// where a wrapper is the whole point. Merging them back into one predicate
// breaks this test in one direction or the devirtualization exclusion in the
// other.
func TestPredicateSplit_WrapperIsNotARealBodyAndIsStillARecordableCaller(t *testing.T) {
	prog := buildWrapperProg(t)

	var wrapper *ssa.Function
	for fn := range ssautil.AllFunctions(prog) {
		if strings.HasSuffix(fn.Name(), "Work$bound") {
			wrapper = fn
			break
		}
	}
	if wrapper == nil {
		t.Fatal("no $bound wrapper in the built program; the fixture no longer materialises one")
	}

	if fnHasRealBody(wrapper) {
		t.Errorf("fnHasRealBody(%s) = true: the devirtualization exclusion was widened, not split", wrapper)
	}
	if !fnIsMethodWrapper(wrapper) {
		t.Errorf("fnIsMethodWrapper(%s) = false: the wrapper's outgoing edges are still discarded", wrapper)
	}
}

// TestFnIsMethodWrapper_ExcludesEverythingElseSynthetic pins the two synthetic
// forms that must NOT be admitted, because each would widen the recorded caller
// set well past a method value.
//
// A package initialiser is synthetic and has a body, and stands for no declared
// method — it is admitted or not by fnInModule like any other package member,
// never by this predicate.
//
// A function loaded from type information carries a declared object and a
// signature and no code. Admitting those would promote the entire type-only
// dependency tier into the recorded caller set, which is a separate decision
// with a separate cost and not one to make as a side effect.
func TestFnIsMethodWrapper_ExcludesEverythingElseSynthetic(t *testing.T) {
	if fnIsMethodWrapper(nil) {
		t.Error("fnIsMethodWrapper(nil) = true, want false")
	}

	prog := buildWrapperProg(t)
	var sawInit bool
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Synthetic == "package initializer" {
			sawInit = true
			if fnIsMethodWrapper(fn) {
				t.Errorf("fnIsMethodWrapper(%s) = true for a package initialiser", fn)
			}
		}
	}
	if !sawInit {
		t.Error("no package initialiser in the built program, so its exclusion is untested")
	}

	// The type-only tier, from the fidelity split the devirtualization harness
	// already sets up: impl is registered from type information alone, so its
	// method carries a declared object and no code.
	depProg, _ := buildDepWidenProg(t, true)
	implPkg := depProg.ImportedPackage("example.com/testmod/impl")
	if implPkg == nil || implPkg.Pkg == nil {
		t.Skip("type-only package not registered; nothing to exercise the exclusion")
	}
	client, isTypeName := implPkg.Pkg.Scope().Lookup("Client").(*types.TypeName)
	if !isTypeName {
		t.Skip("impl.Client not found; nothing to exercise the exclusion")
	}
	typeOnly := depProg.LookupMethod(client.Type(), implPkg.Pkg, "RunKanonarionProbe")
	if typeOnly == nil {
		t.Skip("impl.Client method not materialised; nothing to exercise the exclusion")
	}
	if typeOnly.Synthetic == "" || len(typeOnly.Blocks) != 0 {
		t.Fatalf("the fixture no longer models the type-only tier: %s synthetic=%q blocks=%d",
			typeOnly, typeOnly.Synthetic, len(typeOnly.Blocks))
	}
	if fnIsMethodWrapper(typeOnly) {
		t.Errorf("fnIsMethodWrapper(%s) = true for a function loaded from type information (synthetic=%q, blocks=%d)",
			typeOnly, typeOnly.Synthetic, len(typeOnly.Blocks))
	}
}
