package cmd_test

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// producerGuarded names the enum constants that must be WRITTEN somewhere in
// production code, keyed by "<package path>.<constant name>".
//
// It exists because an enum value nothing produces is a claim the tool cannot
// back. A reader of the type, of a stored record, or of the docs is told the
// analyser can report a state it has never once reported, and every ladder built
// on the enum then orders on a rung nobody can occupy. A green suite does not
// notice: the value is exercised by tests that construct it directly, which is
// precisely how two dead rungs survived in the completeness ladder while both
// the composition rule and the negative-soundness rule ranked on them.
//
// Adding a value here is cheap; the guard is what makes "grepped for a
// production producer" a property of the build rather than a step someone
// remembers.
var producerGuarded = map[string]bool{}

func init() {
	// The completeness ladder, taken from the domain that publishes it so a level
	// added there is guarded without an edit here. The zero value is excluded: it
	// is what a record carries when nothing was recorded, so it is produced by
	// omission rather than by an assignment.
	names := map[cgdomain.CompletenessLevel]string{
		cgdomain.CompletenessBuiltWithBodies: "CompletenessBuiltWithBodies",
		cgdomain.CompletenessTypeOnly:        "CompletenessTypeOnly",
		cgdomain.CompletenessMetadataOnly:    "CompletenessMetadataOnly",
		cgdomain.CompletenessFailed:          "CompletenessFailed",
	}
	for _, l := range cgdomain.CompletenessLevels() {
		if l == cgdomain.CompletenessUnknown {
			continue
		}
		name, ok := names[l]
		if !ok {
			// A level was added to the ladder without being named here. Register an
			// impossible key so the test fails loudly rather than skipping it.
			producerGuarded[modulePath+"/internal/callgraph/domain.<unnamed level "+string(l)+">"] = true
			continue
		}
		producerGuarded[modulePath+"/internal/callgraph/domain."+name] = true
	}

	// The analysis source: which kind of thing the analysed bytes came from. Both
	// values are set explicitly by a producer and neither is inferred from the
	// coordinate, which is the whole point of the field.
	for _, name := range []string{"AnalysisSourceModuleZip", "AnalysisSourceWorktree"} {
		producerGuarded[modulePath+"/internal/callgraph/domain."+name] = true
	}
}

// TestGuardedEnumValuesHaveAProductionProducer fails when a guarded constant is
// never written outside its own declaration and outside test code.
//
// "Written" is the distinction that matters and the reason this is not a grep. A
// comparison (`x == CompletenessTypeOnly`, `case CompletenessTypeOnly:`) is a
// CONSUMER: it reads the value and proves nothing about whether anything ever
// produces it. Both dead rungs the completeness ladder carried had consumers —
// the verdict classifier reads TYPE_ONLY to downgrade a negative answer — and no
// producer at all. Every other use of the constant (a composite-literal field, an
// assignment, a return, a call argument) puts the value somewhere, and that is
// what counts.
func TestGuardedEnumValuesHaveAProductionProducer(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedName | packages.NeedFiles | packages.NeedDeps | packages.NeedImports,
		// Production code only. A test that constructs the value is exactly the
		// evidence this guard must not accept.
		Tests: false,
		Dir:   "..",
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}

	produced := map[string]string{} // guarded key -> "file:line" of a producing use

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			consumer := consumerUses(file)
			ast.Inspect(file, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || consumer[id] {
					return true
				}
				konst, ok := pkg.TypesInfo.Uses[id].(*types.Const)
				if !ok || konst.Pkg() == nil {
					return true
				}
				key := konst.Pkg().Path() + "." + konst.Name()
				if !producerGuarded[key] {
					return true
				}
				if _, already := produced[key]; !already {
					pos := pkg.Fset.Position(id.Pos())
					produced[key] = trimRepoPath(pos.Filename) + ":" + strconv.Itoa(pos.Line)
				}
				return true
			})
		}
	}

	var missing []string
	for key := range producerGuarded {
		if _, ok := produced[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		t.Errorf("%s has no production producer: nothing outside tests ever writes this value.\n"+
			"Give it a producer, or delete it — a rung nobody can climb is not a ladder.", key)
	}

	if t.Failed() {
		return
	}
	// Report the witnesses so a passing run says WHERE each value is produced,
	// rather than only that it is.
	keys := make([]string, 0, len(produced))
	for k := range produced {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%s produced at %s", k, produced[k])
	}
}

// consumerUses marks the identifiers that only READ an enum value: the operands
// of an equality comparison and the expressions of a switch case. Everything
// else is treated as putting the value somewhere.
func consumerUses(file *ast.File) map[*ast.Ident]bool {
	out := map[*ast.Ident]bool{}
	mark := func(e ast.Expr) {
		if id, ok := e.(*ast.Ident); ok {
			out[id] = true
		}
		if sel, ok := e.(*ast.SelectorExpr); ok {
			out[sel.Sel] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BinaryExpr:
			if v.Op == token.EQL || v.Op == token.NEQ {
				mark(v.X)
				mark(v.Y)
			}
		case *ast.CaseClause:
			for _, e := range v.List {
				mark(e)
			}
		}
		return true
	})
	return out
}

// trimRepoPath renders an absolute path from the loader as a repo-relative one.
func trimRepoPath(p string) string {
	if i := strings.Index(p, "/kanonarion/"); i >= 0 {
		return p[i+len("/kanonarion/"):]
	}
	return p
}
