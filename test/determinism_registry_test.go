package cmd_test

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// A record's content hash is taken over its canonical JSON, so the ORDER of
// every collection in that JSON is part of the seal. A comparator that is not a
// total order leaves two tied elements to sort.Slice, which is not stable, and
// the order it lands on comes from the directory walk or the map iteration that
// produced the input. Two measurements of one unchanged thing then seal
// differently, the composition refuses to serve a coordinate its records
// disagree about, and every run appends another disagreeing record.
//
// That is not a risk; it is what golang.org/x/tools@v0.49.0 did — eight
// interface records under seven digests, five taken minutes apart, because a
// package's functions were ordered on Name alone and x/tools ships testdata
// directories where two files declare one name.
//
// The per-type guards state the property. This one states that every hashed
// type HAS a per-type guard, derived from the code rather than from a list, so
// a record type added later cannot arrive without one. That is the half the
// earlier sweeps of this defect were missing: each fixed the sites it found,
// and nothing stopped the next collection arriving unordered.

// determinismGuardSuffix is the name every per-type determinism guard ends
// with. The prefix is "Test" plus the sealed type's name, so
// VulnerabilityRecord's guard is
// TestVulnerabilityRecord_ContentHashIsIndependentOfInputOrder.
const determinismGuardSuffix = "_ContentHashIsIndependentOfInputOrder"

// hashGuardName is the guard a package-level Hash function must carry. Such a
// function hashes a COLLECTION passed to it rather than a record type, so the
// guard is named for the function and not for a type.
const hashGuardName = "TestHash_IsIndependentOfInputOrder"

// TestEveryHashedTypeHasADeterminismGuard fails when a type carrying a content
// hash has no determinism guard in its own package.
//
// The requirement is DERIVED, twice over, from production code:
//
//   - every method named SetContentHash contributes the type it seals, which is
//     the receiver's parameter type;
//   - every exported package-level function named Hash whose body sums a SHA-256
//     contributes its package.
//
// A hand-written list of record types would drift, and drift is exactly the
// failure this guard exists to prevent: the list would be edited by whoever
// remembered, and the type nobody remembered is the one that reaches the store
// unordered.
func TestEveryHashedTypeHasADeterminismGuard(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedName | packages.NeedFiles | packages.NeedDeps | packages.NeedImports,
		// Tests are loaded so the guards themselves are visible: the requirement
		// comes from production code, the evidence comes from test code.
		Tests: true,
		Dir:   "..",
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}

	required := map[string]string{} // "<package path> <guard name>" -> what it guards
	guards := map[string]bool{}     // "<package path> <guard name>" seen in a test file

	for _, pkg := range pkgs {
		// A package's external test package is "<path>_test" and its internal
		// test binary re-reports "<path>"; both hold guards for "<path>".
		owner := strings.TrimSuffix(strings.TrimSuffix(pkg.PkgPath, "_test"), ".test")
		if i := strings.Index(owner, " ["); i >= 0 {
			owner = owner[:i]
		}
		for _, file := range pkg.Syntax {
			isTest := strings.HasSuffix(pkg.Fset.Position(file.Pos()).Filename, "_test.go")
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if isTest {
					if strings.HasSuffix(fn.Name.Name, determinismGuardSuffix) || fn.Name.Name == hashGuardName {
						guards[owner+" "+fn.Name.Name] = true
					}
					continue
				}
				if name, ok := sealedTypeName(fn); ok {
					required[owner+" Test"+name+determinismGuardSuffix] = owner + "." + name
				}
				if hashesACollection(fn) {
					required[owner+" "+hashGuardName] = owner + ".Hash"
				}
			}
		}
	}

	if len(required) == 0 {
		t.Fatal("no sealed types found: the derivation is broken, which would make this guard pass by finding nothing")
	}

	var missing []string
	for key, what := range required {
		if !guards[key] {
			pkgPath, guard, _ := strings.Cut(key, " ")
			missing = append(missing, fmt.Sprintf("%s carries a content hash and has no determinism guard: "+
				"add %s to %s. It must build a value whose collections hold elements that TIE on the "+
				"ordering keys, shuffle every collection with a seeded PRNG at least 50 times, and assert "+
				"one digest. See internal/iface/domain/determinism_test.go", what, guard, pkgPath))
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Error(m)
	}

	if t.Failed() {
		return
	}
	keys := make([]string, 0, len(required))
	for k := range required {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("%s guarded by %s", required[k], k)
	}
}

// sealedTypeName reports the type a SetContentHash method seals. The hashers in
// this repo are stateless value types whose method takes the record and returns
// it sealed, so the type is the first parameter's.
func sealedTypeName(fn *ast.FuncDecl) (string, bool) {
	if fn.Recv == nil || fn.Name.Name != "SetContentHash" {
		return "", false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return "", false
	}
	ident, ok := fn.Type.Params.List[0].Type.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// hashesACollection reports whether fn is an exported package-level Hash that
// sums a SHA-256 over a slice it was handed. Those are the domains that seal a
// SET rather than a record — directives, godebug settings, FIPS findings, the
// vendor-tree reconciliation — and their ordering reaches a stored hash exactly
// as a record's does.
func hashesACollection(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Name.Name != "Hash" || fn.Body == nil {
		return false
	}
	takesSlice := false
	if fn.Type.Params != nil {
		for _, param := range fn.Type.Params.List {
			if _, ok := param.Type.(*ast.ArrayType); ok {
				takesSlice = true
			}
		}
	}
	if !takesSlice {
		return false
	}
	sums := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "sha256" && strings.HasPrefix(sel.Sel.Name, "Sum") {
			sums = true
		}
		return true
	})
	return sums
}
