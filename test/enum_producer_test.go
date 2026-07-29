package cmd_test

import (
	"go/ast"
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

	// The standard library's acquisition route. Same reasoning: it is stated by
	// the acquirer that took it, not derived from the verification status that
	// happens to correlate with it today.
	for _, name := range []string{"RouteGoDev", "RouteLocalToolchain"} {
		producerGuarded[modulePath+"/internal/stdlib/domain."+name] = true
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
			strong, weak := producingUses(file)
			ast.Inspect(file, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				isStrong, isWeak := strong[id], weak[id]
				if !isStrong && !isWeak {
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
				pos := pkg.Fset.Position(id.Pos())
				// A use in the file that DECLARES the constant does not count. That
				// file is where the ladder-publishing helpers live — CompletenessLevels,
				// AcquisitionRoutes — and a value listed in its own ladder is exactly the
				// dead rung this guard exists to catch: enumerated, documented, and
				// written by nothing. Found by reading the guard's own output, which
				// reported the ladder literal as the producer of all four levels.
				if pkg.Fset.Position(konst.Pos()).Filename == pos.Filename {
					return true
				}
				where := trimRepoPath(pos.Filename) + ":" + strconv.Itoa(pos.Line)
				if !isStrong {
					// Evidence that the value reaches a function, not that anything
					// stores it. Recorded, and labelled, so a reader can see that the
					// producer was never directly observed.
					where += " (passed to a call — construction not directly observed)"
				}
				if prev, already := produced[key]; !already || (isStrong && strings.Contains(prev, "(passed to a call")) {
					produced[key] = where
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

// producingUses splits the identifiers that PUT an enum value somewhere into two
// strengths.
//
// STRONG is unambiguous: the right-hand side of an assignment, a value in a
// composite literal, a return operand, a var/const initialiser. The value
// demonstrably lands in something.
//
// WEAK is a call argument. It is often a producer — `failRecord(coord, status,
// completeness, detail)` sets the field from its parameter — and often not, since
// the same shape covers filters and lookups. It counts, because rejecting it
// would fail the legitimate constructor pattern, but it is labelled in the
// report so nobody reads "produced at" as "written at" when it was not.
//
// What is NOT a producing use at all: an equality operand, a switch case, or any
// other bare read. That distinction is the guard's whole point, and getting it
// too loose was the first version's bug — it reported `withSource(records,
// RouteGoDev)` as a producer, under which a constant used only to filter,
// compare and enumerate would pass as produced.
//
// It is a positive match rather than "everything that is not a comparison", and
// the difference is not academic. The first version excluded only equality
// operands and switch cases, and it reported `withSource(records, RouteGoDev)` —
// a filter ARGUMENT, which reads the value — as the producer. Under that
// definition a constant used exclusively to filter, compare and enumerate counts
// as produced, which is precisely the dead rung this guard exists to catch. A
// value nothing ever WRITES is not produced, however often it is read.
//
// A call argument is deliberately not a write. It can be one — a constructor
// taking the value and storing it — but it is far more often a filter or a
// lookup, and a guard that accepts the ambiguous case cannot fail on the case it
// was built for. A genuine constructor-only producer would need a named
// assignment somewhere to satisfy this, which is a small price for the guard
// meaning what it says.
func producingUses(file *ast.File) (strong, weak map[*ast.Ident]bool) {
	strong, weak = map[*ast.Ident]bool{}, map[*ast.Ident]bool{}
	into := func(m map[*ast.Ident]bool) func(ast.Expr) {
		return func(e ast.Expr) {
			switch v := e.(type) {
			case *ast.Ident:
				m[v] = true
			case *ast.SelectorExpr:
				m[v.Sel] = true
			}
		}
	}
	mark, markWeak := into(strong), into(weak)
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			for _, a := range v.Args {
				markWeak(a)
			}
		case *ast.AssignStmt:
			for _, rhs := range v.Rhs {
				mark(rhs)
			}
		case *ast.CompositeLit:
			for _, elt := range v.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					mark(kv.Value)
					continue
				}
				mark(elt)
			}
		case *ast.ReturnStmt:
			for _, r := range v.Results {
				mark(r)
			}
		case *ast.ValueSpec:
			for _, val := range v.Values {
				mark(val)
			}
		}
		return true
	})
	return strong, weak
}

// trimRepoPath renders an absolute path from the loader as a repo-relative one.
func trimRepoPath(p string) string {
	if i := strings.Index(p, "/kanonarion/"); i >= 0 {
		return p[i+len("/kanonarion/"):]
	}
	return p
}
