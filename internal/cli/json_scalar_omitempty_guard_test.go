package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// scalarZeroExemption is one field where an erased zero is correct, with the
// reason it is correct. An entry without a reason is not an entry: the list is
// the record of a design decision, and a list that grows silently has stopped
// being a guard.
type scalarZeroExemption struct {
	file   string // base name of the file the struct is declared in
	field  string // Go field name
	reason string
}

// scalarZeroExemptions is the allow-list for TestJSON_NoScalarOmitemptyInCLI.
//
// Each entry must state why zero is NOT a measurement for that field — either
// the value is 1-based by construction so zero can only mean "not recorded", or
// a named sibling on the same object already carries that absence.
// The whole list is one family: a source LINE. Every producer in this package
// takes its lines from go/token, which numbers them from 1, and writes the zero
// SourcePosition when a declaration or call site has no valid position — which
// leaves the File beside it empty on the same row. So 0 is not a measurement
// these fields can carry, and an absent line reads "no position was recorded",
// which is exactly true. Anything that is NOT a source line does not belong
// here.
var scalarZeroExemptions = []scalarZeroExemption{
	{
		file:  "interface_diff.go",
		field: "Line",
		reason: "declaration line of a consumer's own calling function, copied from a stored " +
			"call-graph node position; 1-based, and `file` is empty on the same row when none was recorded",
	},
	{
		file:  "callgraph_implementers.go",
		field: "Line",
		reason: "declaration line of a concrete type satisfying the queried interface, from the same " +
			"stored node positions; 1-based, paired with an empty `file`",
	},
	{
		file:  "callgraph_show.go",
		field: "PositionLine",
		reason: "declaration line of a call-graph node, written by the analyser only from a valid " +
			"token.Position; 1-based, paired with an empty `position_file`",
	},
	{
		file:  "callgraph_show.go",
		field: "CallSiteLine",
		reason: "line of a call site on an edge, from the same fileset; 1-based, paired with an " +
			"empty `call_site_file`",
	},
	{
		file:  "fips.go",
		field: "Line",
		reason: "line the FIPS finding was read from; the domain documents it as 1-based and empty " +
			"for toolchain findings, which carry no source position at all",
	},
	{
		file:  "jsonout.go",
		field: "Line",
		reason: "line of an interface declaration in the curated source-position DTO; 1-based, and " +
			"the whole object is the position, so `file` empty and `line` absent say the one thing together",
	},
}

// scalarKinds are the types whose zero value is a measurement rather than an
// absence: false is an answer, 0 is an answer, 0.0 is an answer.
var scalarKinds = map[string]bool{
	"bool": true, "int": true, "int64": true, "float64": true,
	"int32": true, "uint": true, "uint64": true, "float32": true,
}

// TestJSON_NoScalarOmitemptyInCLI is the package-wide net under the per-struct
// guards.
//
// A guard that names one struct protects one struct. This class has now been
// found by measuring real output five separate times, in structs nobody thought
// to guard — including structs declared inside the function that renders them,
// which reflection over exported package types cannot see at all. So this walks
// the package SOURCE: every .go file, every struct type, top-level and
// function-local alike, and fails any bool/int/int64/float64 field whose json
// tag carries omitempty.
//
// Strings and slices are deliberately out of scope. An empty string often does
// mean "does not apply", and no rule mechanical enough to run here can tell the
// cases apart; this guard is about the types where the zero is unambiguously an
// answer.
func TestJSON_NoScalarOmitemptyInCLI(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	exempt := make(map[string]scalarZeroExemption, len(scalarZeroExemptions))
	for _, e := range scalarZeroExemptions {
		if strings.TrimSpace(e.reason) == "" {
			t.Errorf("exemption %s:%s carries no reason; an exemption without a stated reason is a hole, not a decision", e.file, e.field)
		}
		exempt[e.file+":"+e.field] = e
	}

	files := 0
	structs := 0
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		files++
		ast.Inspect(file, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok {
				return true
			}
			structs++
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
				if !hasOmitempty(tag) {
					continue
				}
				kind, isScalar := scalarTypeName(field.Type)
				if !isScalar {
					continue
				}
				scanned++
				for _, ident := range field.Names {
					key := filepath.Base(name) + ":" + ident.Name
					if _, ok := exempt[key]; ok {
						continue
					}
					pos := fset.Position(ident.Pos())
					t.Errorf("%s:%d: %s is %s with `omitempty` (%q); zero and false are measurements for these types, "+
						"so the tag erases an answer and makes it indistinguishable from a build that does not derive it. "+
						"Drop omitempty, or — if the row can genuinely carry no answer and no sibling field says so — make it "+
						"a pointer emitted always. If an erased zero really is correct here, add it to scalarZeroExemptions with the reason.",
						filepath.Base(pos.Filename), pos.Line, ident.Name, kind, tag)
				}
			}
			return true
		})
	}

	if files == 0 || structs == 0 {
		t.Fatalf("guard scanned %d files and %d structs; it is not looking at the package", files, structs)
	}
	t.Logf("scanned %d files, %d struct declarations, %d scalar fields carrying omitempty (%d exempted)",
		files, structs, scanned, len(scalarZeroExemptions))
}

// hasOmitempty reports whether a json struct tag carries the omitempty option,
// without matching a field NAMED omitempty.
func hasOmitempty(tag string) bool {
	parts := strings.Split(tag, ",")
	for _, p := range parts[1:] {
		if p == "omitempty" {
			return true
		}
	}
	return false
}

// scalarTypeName resolves a field's declared type to a scalar name, seeing
// through a pointer: a *bool with omitempty is the same erasure as a bool with
// omitempty, because a nil pointer and a false one both vanish.
func scalarTypeName(expr ast.Expr) (string, bool) {
	if star, ok := expr.(*ast.StarExpr); ok {
		name, isScalar := scalarTypeName(star.X)
		if !isScalar {
			return "", false
		}
		return "*" + name, true
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return "", false
	}
	if !scalarKinds[ident.Name] {
		return "", false
	}
	return ident.Name, true
}
