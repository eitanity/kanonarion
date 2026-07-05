package kanonarion_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	callgraphports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	configports "github.com/eitanity/kanonarion/internal/config/ports"
	exampleports "github.com/eitanity/kanonarion/internal/example/ports"
	extractports "github.com/eitanity/kanonarion/internal/extract/ports"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	ifaceports "github.com/eitanity/kanonarion/internal/iface/ports"
	licenseports "github.com/eitanity/kanonarion/internal/license/ports"
	sbomports "github.com/eitanity/kanonarion/internal/sbom/ports"
	vulnports "github.com/eitanity/kanonarion/internal/vuln/ports"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// The compile-time assignments below pin every published substitution port to
// the internal interface it must alias (§2.3). Each assigns a typed nil
// of the internal interface to the façade name and back; both directions compile
// only when the two names denote the identical interface type, so a re-wired or
// forked port alias fails the build. These also serve as the reachability proof:
// each named port resolves through pkg/kanonarion.
var (
	_ kanonarion.FactStore          = (fetchports.FactStore)(nil)
	_ fetchports.FactStore          = (kanonarion.FactStore)(nil)
	_ kanonarion.WalkStore          = (walkports.WalkStore)(nil)
	_ walkports.WalkStore           = (kanonarion.WalkStore)(nil)
	_ kanonarion.LicenseStore       = (licenseports.LicenseStore)(nil)
	_ licenseports.LicenseStore     = (kanonarion.LicenseStore)(nil)
	_ kanonarion.InterfaceStore     = (ifaceports.InterfaceStore)(nil)
	_ ifaceports.InterfaceStore     = (kanonarion.InterfaceStore)(nil)
	_ kanonarion.CallGraphStore     = (callgraphports.CallGraphStore)(nil)
	_ callgraphports.CallGraphStore = (kanonarion.CallGraphStore)(nil)
	_ kanonarion.ExampleStore       = (exampleports.ExampleStore)(nil)
	_ exampleports.ExampleStore     = (kanonarion.ExampleStore)(nil)
	_ kanonarion.ExtractionStore    = (extractports.ExtractionStore)(nil)
	_ extractports.ExtractionStore  = (kanonarion.ExtractionStore)(nil)
	_ kanonarion.VulnerabilityStore = (vulnports.VulnerabilityStore)(nil)
	_ vulnports.VulnerabilityStore  = (kanonarion.VulnerabilityStore)(nil)
	_ kanonarion.SBOMStore          = (sbomports.SBOMStore)(nil)
	_ sbomports.SBOMStore           = (kanonarion.SBOMStore)(nil)

	_ kanonarion.BlobStore         = (fetchports.BlobStore)(nil)
	_ fetchports.BlobStore         = (kanonarion.BlobStore)(nil)
	_ kanonarion.BlobPathOptimizer = (fetchports.BlobPathOptimizer)(nil)
	_ fetchports.BlobPathOptimizer = (kanonarion.BlobPathOptimizer)(nil)
	_ kanonarion.BlobHandle        = fetchports.BlobHandle("")
	_ fetchports.BlobHandle        = kanonarion.BlobHandle("")

	_ kanonarion.ConfigStore  = (configports.ConfigStore)(nil)
	_ configports.ConfigStore = (kanonarion.ConfigStore)(nil)
	_ kanonarion.Clock        = (fetchports.Clock)(nil)
	_ fetchports.Clock        = (kanonarion.Clock)(nil)
	_ kanonarion.ModuleProxy  = (fetchports.ModuleProxy)(nil)
	_ fetchports.ModuleProxy  = (kanonarion.ModuleProxy)(nil)
	_ kanonarion.VCSClient    = (fetchports.VCSClient)(nil)
	_ fetchports.VCSClient    = (kanonarion.VCSClient)(nil)
	_ kanonarion.SumDBClient  = (fetchports.SumDBClient)(nil)
	_ fetchports.SumDBClient  = (kanonarion.SumDBClient)(nil)
	// Signer is aliased in signer.go; pin it here with the other ports.
	_ kanonarion.Signer = (fetchports.Signer)(nil)
	_ fetchports.Signer = (kanonarion.Signer)(nil)
)

// staysInternalPorts is the §3 deny-list: AST/parse-coupled and
// infrastructure-leaning ports that must never become reachable through the
// façade. Enterprise reuses core's implementations of these via the DI
// container, so they need no public contract.
var staysInternalPorts = map[string]bool{
	"Extractor":            true,
	"InterfaceExtractor":   true,
	"CallGraphAnalyser":    true,
	"ReachabilityAnalyser": true,
	"GoModParser":          true,
	"ExampleParser":        true,
	"LicenseDetector":      true,
	"SBOMGenerator":        true,
	"ZipFS":                true,
}

// allowedPortAliases is the closed set of names the façade may alias out of an
// internal ".../ports" package. It is the named substitution-port surface
// (§2.3) plus the supporting value types that travel with those ports
// (BlobHandle for BlobStore; SubjectDigest/Attestation for Signer). Any new
// ports-package alias outside this set fails TestPorts_NoUnexpectedPortAlias,
// forcing a deliberate decision rather than an accidental surface growth.
var allowedPortAliases = map[string]bool{
	"FactStore": true, "WalkStore": true, "LicenseStore": true,
	"InterfaceStore": true, "CallGraphStore": true, "ExampleStore": true,
	"ExtractionStore": true, "VulnerabilityStore": true, "SBOMStore": true,
	"BlobStore": true, "BlobPathOptimizer": true, "BlobHandle": true,
	"ConfigStore": true, "Clock": true, "ModuleProxy": true,
	"VCSClient": true, "SumDBClient": true,
	"Signer": true, "SubjectDigest": true, "Attestation": true,
}

// facadeAlias is one exported type-alias declaration in the façade package.
type facadeAlias struct {
	name    string // the exported façade name (LHS)
	pkg     string // the RHS package identifier (e.g. "fetchports")
	sel     string // the RHS internal type name (e.g. "FactStore")
	imports map[string]string
}

// parseFacadeAliases parses every non-test.go file in the façade package and
// returns its exported type-alias declarations. It works at the source level so
// the deny-list guard sees exactly what a consumer could import.
func parseFacadeAliases(t *testing.T) []facadeAlias {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read façade package dir: %v", err)
	}

	fset := token.NewFileSet()
	var aliases []facadeAlias
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		imports := map[string]string{}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			alias := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			imports[alias] = path
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !ts.Assign.IsValid() || !ts.Name.IsExported() {
					continue
				}
				a := facadeAlias{name: ts.Name.Name, imports: imports}
				if sel, ok := ts.Type.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok {
						a.pkg = x.Name
					}
					a.sel = sel.Sel.Name
				}
				aliases = append(aliases, a)
			}
		}
	}
	return aliases
}

// TestPorts_StaysInternalNotReachable is the §3 acceptance guard: no
// exported façade alias names a stays-internal port or a *Hasher, on either the
// façade name or the internal type it re-exports.
func TestPorts_StaysInternalNotReachable(t *testing.T) {
	t.Parallel()

	aliases := parseFacadeAliases(t)
	if len(aliases) == 0 {
		t.Fatal("no exported aliases found in façade; parser wiring is broken")
	}
	for _, a := range aliases {
		for _, name := range []string{a.name, a.sel} {
			if staysInternalPorts[name] {
				t.Errorf("façade exposes stays-internal port %q (alias %q); it must remain internal", name, a.name)
			}
			if strings.Contains(name, "Hasher") {
				t.Errorf("façade alias %q reaches a Hasher (%q); hashers must stay internal", a.name, name)
			}
		}
	}
}

// TestPorts_NoUnexpectedPortAlias asserts the façade aliases exactly the named
// ports out of internal ".../ports" packages — no more (§2.3). A new
// ports alias outside allowedPortAliases fails here, so the substitution surface
// cannot grow by accident.
func TestPorts_NoUnexpectedPortAlias(t *testing.T) {
	t.Parallel()

	for _, a := range parseFacadeAliases(t) {
		path := a.imports[a.pkg]
		if !strings.HasSuffix(path, "/ports") {
			continue
		}
		if !allowedPortAliases[a.name] {
			t.Errorf("façade aliases %q from %q, which is not an approved substitution-port export", a.name, path)
		}
	}
}
