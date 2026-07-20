package staticcha

import (
	"context"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// depWidenModule is a two-package module: dep holds an interface and a function
// (Drive) that dispatches through it from inside dep's own body; impl holds the
// sole structural implementer. The interface method name is deliberately unusual
// so no stdlib type accidentally becomes a second implementer.
var depWidenModule = map[string]string{
	"go.mod": "module example.com/testmod\n\ngo 1.21\n",
	"dep/dep.go": `package dep

type Runner interface {
	RunKanonarionProbe()
}

// Drive invokes the interface method from inside the dependency's own body.
func Drive(r Runner) {
	r.RunKanonarionProbe()
}
`,
	"impl/impl.go": `package impl

// Client structurally implements example.com/testmod/dep.Runner but, when loaded
// type-only, is never a runtime Runner — so CHA drops the dispatch to it.
type Client struct{}

func (Client) RunKanonarionProbe() {}
`,
}

// buildDepWidenProg writes depWidenModule to a temp dir, loads both packages,
// and builds an SSA program in which dep is built with real bodies while impl is
// registered type-only — the exact fidelity split the widening targets. When
// buildDep is false, dep is left type-only too, modelling the pre-tier state
// where no dependency body is built. Skips (not fails) when no Go toolchain is
// available in the sandbox.
func buildDepWidenProg(t *testing.T, buildDep bool) (*ssa.Program, *token.FileSet) {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range depWidenModule {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedFiles | packages.NeedImports | packages.NeedDeps,
		Dir:   dir,
		Fset:  fset,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./dep", "./impl")
	if err != nil {
		t.Skipf("packages.Load failed (no Go env?): %v", err)
	}
	if len(pkgs) < 2 {
		t.Skipf("expected 2 packages, got %d; skipping", len(pkgs))
	}

	const depPath = "example.com/testmod/dep"
	var depPkg *packages.Package
	for _, p := range pkgs {
		if len(p.Errors) > 0 || p.Types == nil {
			t.Skipf("package %s failed to load cleanly; skipping", p.PkgPath)
		}
		if p.PkgPath == depPath {
			depPkg = p
		}
	}
	if depPkg == nil {
		t.Fatalf("dependency package %s not loaded", depPath)
	}

	prog := ssa.NewProgram(fset, ssa.BuilderMode(0))
	// Register everything type-only, except dep when it is to be built (a
	// package registered type-only cannot later be re-created with syntax).
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Types == nil {
			return
		}
		if buildDep && p.PkgPath == depPath {
			return
		}
		if prog.Package(p.Types) == nil {
			prog.CreatePackage(p.Types, nil, nil, true)
		}
	})
	if buildDep {
		depSSA := prog.CreatePackage(depPkg.Types, depPkg.Syntax, depPkg.TypesInfo, true)
		depSSA.Build()
	}
	return prog, fset
}

func findFunc(prog *ssa.Program, id string) *ssa.Function {
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Package() == nil {
			continue
		}
		if nodeID(fn) == id {
			return fn
		}
	}
	return nil
}

// TestDevirt_WidensToBuiltDependencyBody is the crux: when a dependency body is
// built into SSA, the single-implementer sweep must reach its invoke sites and
// recover the dispatch CHA drops for a type-only sole implementer — exactly as
// it already does for module bodies.
func TestDevirt_WidensToBuiltDependencyBody(t *testing.T) {
	prog, fset := buildDepWidenProg(t, true)

	a := New("0.1.0", "", slog.Default())
	coord, err := fetchdomain.NewModuleCoordinate("example.com/analysed", "v0.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}

	nodes, edges := a.devirtualizeSingleImplementer(context.Background(), prog, coord, fset, "", nil, nil)

	const (
		fromID = "example.com/testmod/dep.Drive"
		toID   = "example.com/testmod/impl.(Client).RunKanonarionProbe"
	)
	var foundEdge bool
	for _, e := range edges {
		if e.FromID == fromID && e.ToID == toID {
			foundEdge = true
		}
	}
	if !foundEdge {
		t.Fatalf("expected recovered dependency-internal edge %s→%s; edges: %v", fromID, toID, edges)
	}

	var target, hasTarget = nodeByIDInSlice(nodes, toID)
	if !hasTarget {
		t.Fatalf("expected recovered target node %q; nodes: %v", toID, nodes)
	}
	if !target.IsExternal {
		t.Errorf("dependency target node should be IsExternal=true, got %+v", target)
	}
}

// TestDevirt_NoOpWhenDependencyBodyUnbuilt pins the latent-no-op guarantee: with
// the dependency registered type-only (the default loader state), no dependency
// body is swept and nothing is recovered.
func TestDevirt_NoOpWhenDependencyBodyUnbuilt(t *testing.T) {
	prog, fset := buildDepWidenProg(t, false)

	a := New("0.1.0", "", slog.Default())
	coord, err := fetchdomain.NewModuleCoordinate("example.com/analysed", "v0.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}

	nodes, edges := a.devirtualizeSingleImplementer(context.Background(), prog, coord, fset, "", nil, nil)

	if len(edges) != 0 || len(nodes) != 0 {
		t.Fatalf("expected no recovery with dependency unbuilt, got %d nodes, %d edges", len(nodes), len(edges))
	}
}

// TestFnHasRealBody covers the predicate that gates both the sweep and the
// recorded-caller set: a built body is real, a nil function and a synthetic
// wrapper are not.
func TestFnHasRealBody(t *testing.T) {
	prog, _ := buildDepWidenProg(t, true)

	if fnHasRealBody(nil) {
		t.Error("fnHasRealBody(nil) = true, want false")
	}

	drive := findFunc(prog, "example.com/testmod/dep.Drive")
	if drive == nil {
		t.Fatal("dep.Drive not found in built program")
	}
	if !fnHasRealBody(drive) {
		t.Error("fnHasRealBody(dep.Drive) = false, want true (built body)")
	}

	var checkedSynthetic bool
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Synthetic != "" {
			if fnHasRealBody(fn) {
				t.Errorf("fnHasRealBody(%s) = true for synthetic wrapper, want false", fn)
			}
			checkedSynthetic = true
			break
		}
	}
	if !checkedSynthetic {
		t.Log("no synthetic function present to exercise the synthetic branch")
	}
}

// TestRecordedCallerNodes verifies that a built dependency caller is recorded
// even though it is outside the analysed module, while the cha root (nil func)
// is not.
func TestRecordedCallerNodes(t *testing.T) {
	prog, _ := buildDepWidenProg(t, true)
	cg := cha.CallGraph(prog)

	coord, err := fetchdomain.NewModuleCoordinate("example.com/analysed", "v0.0.0")
	if err != nil {
		t.Fatalf("coord: %v", err)
	}
	recorded := recordedCallerNodes(cg, coord)

	drive := findFunc(prog, "example.com/testmod/dep.Drive")
	if drive == nil {
		t.Fatal("dep.Drive not found")
	}
	node, ok := cg.Nodes[drive]
	if !ok {
		t.Fatal("dep.Drive has no callgraph node")
	}
	if !recorded[node] {
		t.Error("built dependency caller dep.Drive should be recorded, was not")
	}
	if cg.Root != nil && recorded[cg.Root] {
		t.Error("cha root node (nil func) must not be recorded")
	}
}

func nodeByIDInSlice(nodes []domain.CallNode, id string) (domain.CallNode, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return domain.CallNode{}, false
}
