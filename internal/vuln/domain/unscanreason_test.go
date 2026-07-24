package domain_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestAllUnscanReasons_MatchesDeclaredConstants is the completeness oracle for
// the reason inventory: it parses the domain package's own source, collects
// every constant declared with type UnscanReason, and requires AllUnscanReasons
// to return exactly that set.
//
// UnscanReason is an open string type, so no compiler check can catch a reason
// that is declared and then left out of a consumer's exhaustive table. Deriving
// the expected set from the declarations rather than restating it here means a
// new constant fails this test until it is listed, and every consumer that
// proves exhaustiveness against AllUnscanReasons inherits that guarantee.
func TestAllUnscanReasons_MatchesDeclaredConstants(t *testing.T) {
	declared := declaredUnscanReasons(t)
	if len(declared) == 0 {
		t.Fatal("parsed no UnscanReason constants: the oracle is not reading the declarations")
	}

	listed := make(map[domain.UnscanReason]bool, len(domain.AllUnscanReasons()))
	for _, r := range domain.AllUnscanReasons() {
		if listed[r] {
			t.Errorf("AllUnscanReasons lists %q twice", r)
		}
		listed[r] = true
	}

	for name, value := range declared {
		if !listed[value] {
			t.Errorf("constant %s (%q) is declared but missing from AllUnscanReasons", name, value)
		}
	}
	for r := range listed {
		if !hasValue(declared, r) {
			t.Errorf("AllUnscanReasons returns %q, which is not a declared UnscanReason constant", r)
		}
	}
}

// declaredUnscanReasons parses the package sources in the current directory and
// returns every constant explicitly typed UnscanReason, keyed by its Go name.
func declaredUnscanReasons(t *testing.T) map[string]domain.UnscanReason {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the domain package directory: %v", err)
	}

	fset := token.NewFileSet()
	out := map[string]domain.UnscanReason{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		collectUnscanReasonConsts(t, file, out)
	}
	return out
}

// collectUnscanReasonConsts adds every `X UnscanReason = "..."` constant
// declared in file to out.
func collectUnscanReasonConsts(t *testing.T, file *ast.File, out map[string]domain.UnscanReason) {
	t.Helper()

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "UnscanReason" {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					t.Fatalf("unquoting %s = %s: %v", name.Name, lit.Value, uerr)
				}
				out[name.Name] = domain.UnscanReason(value)
			}
		}
	}
}

func hasValue(m map[string]domain.UnscanReason, want domain.UnscanReason) bool {
	for _, v := range m {
		if v == want {
			return true
		}
	}
	return false
}
