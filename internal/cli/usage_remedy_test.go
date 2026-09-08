package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// fetchFirstCommands are the subcommands that read a module's already-fetched
// bytes. Handed a coordinate whose bytes the store does not hold they exit 20
// with "module not fetched: run 'kanonarion fetch <coord>' first" — a refusal on
// the argument's own shape, not on anything the reader got wrong — so a remedy
// naming one of them without the fetch that satisfies it costs its reader
// exactly the round trip the remedy existed to save.
//
// That is a class this repo has closed four times at individual sites, and it
// came back each time because nothing checked the SET. The two tests below are
// the set: one holds the builder to the contract, the other refuses the shape
// anywhere in the shipped source, so a site written by hand is caught even
// though it never goes near the builder.
//
// The list is written down because there is no flag on a cobra command that
// says "this one needs the bytes". A command missing from it is not checked;
// a command wrongly in it fails the second test on its first legitimate use.
var fetchFirstCommands = []string{"callgraph", "license", "interface", "capability", "examples"}

// remedyGuardFiles are the sources whose printed remedies this guard covers.
//
// It is a list rather than the whole tree because the rule is a rule about a
// coordinate the reader was handed, and a few sites name a command over a
// coordinate that never needs fetching: `kanonarion license stdlib@<version>`
// short-circuits to the recorded chain of custody and answers without one,
// measured. The guard cannot see that from the source — the coordinate is a
// variable — so a file joins this list once its invocations are all of the
// plain kind.
var remedyGuardFiles = []string{"usage.go"}

func TestFetchFirstCommands_AllNameARealSubcommand(t *testing.T) {
	for _, name := range fetchFirstCommands {
		if err := parseInvocation(t, "kanonarion "+name+" example.com/mod@v1.0.0"); err != nil {
			t.Errorf("%q is not a subcommand that takes a module coordinate: %v", name, err)
		}
	}
}

// assertRemedyConjunction holds one printed line to the whole contract. A line
// may be a shell conjunction, which is what a pair of steps looks like when it
// has to sit inside a sentence: every conjunct is an invocation in its own
// right, so every conjunct is parsed, and a conjunct needing fetched bytes has
// to have its fetch ahead of it on the same line.
func assertRemedyConjunction(t *testing.T, coord coordinate.ModuleCoordinate, line string) {
	t.Helper()
	parts := strings.Split(line, " && ")
	for _, p := range parts {
		assertRemedyLine(t, coord, strings.TrimSpace(p))
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		fields := splitInvocation(p)
		if len(fields) < 3 || fields[0] != "kanonarion" {
			continue
		}
		if !contains(fetchFirstCommands, fields[1]) {
			continue
		}
		if fetchedAheadOf(parts[:i], fields[2]) {
			continue
		}
		t.Errorf("remedy %q names %q for %s with no 'kanonarion fetch %s' ahead of it: that invocation "+
			"exits 20 telling the reader to fetch first, which is the round trip the remedy exists to save",
			line, fields[1], fields[2], fields[2])
	}
}

// fetchedAheadOf reports whether one of the earlier conjuncts fetches target.
func fetchedAheadOf(earlier []string, target string) bool {
	for _, e := range earlier {
		f := splitInvocation(strings.TrimSpace(e))
		if len(f) >= 3 && f[0] == "kanonarion" && f[1] == "fetch" && f[2] == target {
			return true
		}
	}
	return false
}

func contains(in []string, v string) bool {
	for _, s := range in {
		if s == v {
			return true
		}
	}
	return false
}

// The builder every callgraph remedy in usage.go goes through, over both
// coordinate kinds and both re-run forms. A project coordinate names a working
// tree, so it must NOT be handed to fetch — that is the other half of the same
// class, and assertRemedyLine is what refuses it.
func TestUsageMeasureRemedy_IsARunnablePairForEveryCoordinateKind(t *testing.T) {
	for _, coord := range []coordinate.ModuleCoordinate{
		coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1"),
		coordinatetest.MustNew("github.com/Masterminds/sprig", "v2.22.0+incompatible"),
		coordinatetest.MustNew("github.com/cortezaproject/corteza/server", coordinate.LocalVersion),
	} {
		for _, force := range []bool{false, true} {
			t.Run(coord.String(), func(t *testing.T) {
				assertRemedyConjunction(t, coord, usageMeasureRemedy(coord, force))
			})
		}
	}
	// The pair is a pair. A published coordinate that lost its fetch step would
	// still pass every parse above, because the line it leaves behind is a
	// perfectly well-formed invocation of a command that refuses.
	pub := coordinatetest.MustNew("github.com/spf13/cobra", "v1.8.1")
	got := usageMeasureRemedy(pub, false)
	if want := "kanonarion fetch " + pub.String() + " && kanonarion callgraph " + pub.String(); got != want {
		t.Errorf("usageMeasureRemedy = %q, want %q", got, want)
	}
	if forced := usageMeasureRemedy(pub, true); !strings.HasSuffix(forced, " --force") {
		t.Errorf("the forced form dropped its flag: %q", forced)
	}
	// The unmeasured-kinds note is the other chain usage prints, and it is three
	// commands deep: interface-show reads a record, interface writes one from
	// fetched bytes, and fetch gets the bytes.
	assertRemedyConjunction(t, pub, strings.TrimPrefix(usageUnmeasuredKindsNote(pub), usageUnmeasuredKindsLead))
}

// A builder that cannot produce a bare fetch-first invocation closes only half
// the class: the sites that shipped one wrote it out by hand, and no unit test
// over a builder sees those. This reads the shipped source and refuses the
// shape in any string a reader could be handed.
//
// It works over concatenation chains rather than single literals because a
// remedy is almost always built from several: "kanonarion fetch " + coord +
// " && kanonarion callgraph " + coord is four literals, and judging each alone
// would flag the third for a fetch that is right there in the first.
func TestNoRemedySourceNamesAFetchFirstCommandAlone(t *testing.T) {
	found := 0
	for _, name := range remedyGuardFiles {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, text := range stringExpressions(file) {
			for _, cmd := range fetchFirstCommands {
				at := strings.Index(text, "kanonarion "+cmd+" ")
				if at < 0 {
					continue
				}
				found++
				fetchAt := strings.Index(text, "kanonarion fetch ")
				if fetchAt < 0 || fetchAt > at {
					t.Errorf("%s writes %q, which names 'kanonarion %s' with no fetch ahead of it: "+
						"that invocation exits 20 on a module the store has not fetched",
						name, text, cmd)
				}
			}
		}
	}
	// A guard that matched nothing would pass while checking nothing.
	if found == 0 {
		t.Fatalf("no fetch-first invocation found in %v; the guard is not reaching the source", remedyGuardFiles)
	}
}

// stringExpressions renders every string-valued expression in a file as one
// piece of text, joining a "+" chain into the single line it prints as and
// standing a placeholder in for each non-literal operand so two literals never
// appear to abut.
func stringExpressions(file *ast.File) []string {
	consumed := map[ast.Node]bool{}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BinaryExpr:
			if e.Op != token.ADD || consumed[e] {
				return true
			}
			var parts []string
			if !flattenStringAdd(e, consumed, &parts) {
				return true
			}
			out = append(out, strings.Join(parts, ""))
		case *ast.BasicLit:
			if e.Kind == token.STRING && !consumed[e] {
				out = append(out, literalText(e))
			}
		}
		return true
	})
	return out
}

// flattenStringAdd walks a "+" chain left to right, appending each operand's
// text and marking every node it took so the outer Inspect does not judge an
// operand a second time on its own. It reports false for a chain holding no
// string literal at all, which is arithmetic rather than a printed line.
func flattenStringAdd(n ast.Expr, consumed map[ast.Node]bool, parts *[]string) bool {
	consumed[n] = true
	switch e := n.(type) {
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			*parts = append(*parts, "\x00")
			return false
		}
		left := flattenStringAdd(e.X, consumed, parts)
		right := flattenStringAdd(e.Y, consumed, parts)
		return left || right
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			*parts = append(*parts, "\x00")
			return false
		}
		*parts = append(*parts, literalText(e))
		return true
	default:
		// Any other operand is a value only the run knows — a coordinate, a
		// formatted count. A placeholder keeps the literals either side of it from
		// reading as one word.
		*parts = append(*parts, "\x00")
		return false
	}
}

// literalText is a string literal's content with its quoting removed, kept
// approximate on purpose: escape sequences other than the quotes do not change
// whether a command name is present, and a strconv.Unquote that failed would
// drop the literal from the guard entirely.
func literalText(lit *ast.BasicLit) string {
	return strings.Trim(lit.Value, "`\"")
}
