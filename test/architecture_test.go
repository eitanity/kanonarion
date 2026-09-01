package cmd_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/childproc"
	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"golang.org/x/tools/go/packages"
)

// modulePath is the Go module path; package paths are made repo-relative by
// trimming this prefix.
const modulePath = "github.com/eitanity/kanonarion"

// boundedContexts is the set of DDD bounded contexts, DERIVED from the tree: a
// directory under internal/ holding an application or a domain layer is one.
// Only these count as "another context" for the cross-context import rule; the
// shared kernel under internal/adapters/** has neither layer and so is exempt by
// construction rather than by an entry somebody remembered to leave out.
//
// It is derived because a hand-written list drifts and this one had — it named
// ten contexts while the tree held eighteen, so the application and domain
// layers of eight contexts sat outside every guard below while reading as
// covered. The derivation is the one test/determinism_registry_test.go makes,
// for the same reason: a requirement read off the code cannot fall behind it.
//
// It is computed on first use rather than at package initialisation because
// TestScript re-executes this binary as the CLI from a script's own working
// directory, where ../internal does not exist. A guard calls this; the CLI
// entry point does not.
var boundedContexts = sync.OnceValue(deriveBoundedContexts)

// notBoundedContexts names a directory that holds an application or a domain
// layer and is still not a bounded context, with the reason it is not.
//
// It is empty. config is the shape that invites an entry — a domain layer and no
// application layer — and it does not get one: a supporting context is entitled
// to that shape, its domain is where the governance overlay's rules live, and
// nothing about the shape makes those rules cheaper to leave unguarded.
//
// An entry here is checked by TestBoundedContextExemptionsAreLive, so one that
// stops applying is a failure rather than a fossil.
var notBoundedContexts = map[string]string{}

// deriveBoundedContexts reads the context set off the tree.
//
// It panics rather than returning an error because it runs at package
// initialisation, before any test has a *testing.T to fail: a broken derivation
// must stop the package, since the alternative is an empty set under which every
// guard below passes by finding nothing to check.
func deriveBoundedContexts() map[string]bool {
	const internalDir = "../internal"
	entries, err := os.ReadDir(internalDir)
	if err != nil {
		panic(fmt.Sprintf("deriving the bounded-context set from %s: %v", internalDir, err))
	}
	out := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, exempt := notBoundedContexts[entry.Name()]; exempt {
			continue
		}
		for _, layer := range []string{"application", "domain"} {
			if info, serr := os.Stat(filepath.Join(internalDir, entry.Name(), layer)); serr == nil && info.IsDir() {
				out[entry.Name()] = true
				break
			}
		}
	}
	if len(out) == 0 {
		panic("no bounded contexts derived from ../internal: the derivation is broken, " +
			"which would make every guard in this file pass by finding nothing to check")
	}
	return out
}

// TestBoundedContextExemptionsAreLive fails on an entry in notBoundedContexts
// that no longer names a directory with an application or a domain layer. Such
// an entry exempts nothing and reads as a live decision, which is how the list
// this file replaced came to describe a tree that had moved on.
func TestBoundedContextExemptionsAreLive(t *testing.T) {
	for dir, reason := range notBoundedContexts {
		if boundedContexts()[dir] {
			t.Errorf("internal/%s is exempt (%s) and also derived as a context — the derivation and the exemption disagree", dir, reason)
			continue
		}
		layered := false
		for _, layer := range []string{"application", "domain"} {
			if info, err := os.Stat(filepath.Join("../internal", dir, layer)); err == nil && info.IsDir() {
				layered = true
			}
		}
		if !layered {
			t.Errorf("notBoundedContexts exempts %q (%s), which has no application or domain layer — "+
				"the derivation already skips it, so remove the entry", dir, reason)
		}
	}
}

// forbiddenLayerImports are infrastructure/parsing packages that must never
// be imported from an application or domain layer (prevention 2a).
// Source/format parsing belongs behind a port-backed adapter; raw SQL belongs
// in an adapters store.
var forbiddenLayerImports = map[string]string{
	"archive/zip":  "archive extraction belongs behind a port-backed adapter",
	"go/ast":       "AST parsing belongs behind a port-backed adapter",
	"go/parser":    "Go source parsing belongs behind a port-backed adapter",
	"go/printer":   "Go source printing belongs behind a port-backed adapter",
	"go/format":    "Go source formatting belongs behind a port-backed adapter",
	"database/sql": "SQL access belongs in an adapters store, not application/domain",
}

// knownInfraViolations grandfathers infrastructure imports that predate the
// enforcement. Each entry is tracked by a remediation ticket and MUST
// be removed when that ticket lands. The test fails both on a NEW violation
// (regression guard) and on a STALE entry here that no longer violates
// (forces this baseline to drain as the tickets close). Key:
// "<repo-relative package path> <import path>".
//
// The original archive/zip baseline (..) has fully drained: ZIP
// access now routes through the shared internal/adapters/ziparchive adapter.
var knownInfraViolations = map[string]string{}

// layerOf returns the bounded context and layer for a repo-relative package
// path like "internal/vuln/application/foo". ctx is "" when the path is not a
// context-scoped layer (e.g. the shared internal/adapters/** kernel).
func layerOf(rel string) (ctx, layer string) {
	parts := strings.Split(rel, "/")
	if len(parts) < 3 || parts[0] != "internal" {
		return "", ""
	}
	if !boundedContexts()[parts[1]] {
		return "", ""
	}
	return parts[1], parts[2]
}

func loadInternalPackages(t *testing.T) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedImports | packages.NeedFiles,
		Dir:  "..",
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatalf("packages.Load reported errors")
	}
	return pkgs
}

func rel(pkgPath string) string {
	return strings.TrimPrefix(pkgPath, modulePath+"/")
}

// zipWriterPackages names the packages allowed to construct an archive/zip
// writer in non-test code, with the reason each one may.
//
// A module zip fetched from a proxy or the module cache is stored byte for byte
// as it arrived: its hash is what the checksum database attests and what every
// later reader recomputes, so recompressing one would replace the artefact the
// anchor covers with a different one that says the same thing. Nothing in the
// tree may build a zip writer without saying why, because "we never re-zip" is
// only worth stating while it is true of every path, and a second re-zipper
// would be indistinguishable from the first at a glance.
//
// The one entry is the local working tree, which has no upstream zip at all.
// Key: repo-relative package directory.
var zipWriterPackages = map[string]string{
	"internal/walk/adapters/localfs": "a local module is packaged from its working tree rather than fetched, " +
		"and modzip requires a canonical semver, so the synthetic zip is rewritten to carry the local " +
		"coordinate's entry prefix; no fetched artefact reaches this path",
}

// TestNoZipRewritingOutsideNamedPackages enforces that module zips are stored
// verbatim: an archive/zip writer exists only where zipWriterPackages says one
// may, and each entry states why.
//
// It fails on a NEW writer and on a STALE entry that no longer constructs one,
// so the list drains as paths change rather than accumulating permissions
// nobody needs. Test files are exempt: a fixture zip is an input to a test, not
// an artefact any store keeps.
//
// It resolves the local name bound to "archive/zip" per file, so an aliased
// import is caught and an unrelated package that happens to be called zip is
// not.
func TestNoZipRewritingOutsideNamedPackages(t *testing.T) {
	seen := map[string]bool{}
	for _, path := range repoGoFiles(t, "../internal", "../pkg", "../cmd") {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		local := zipImportName(f)
		if local == "" {
			continue
		}
		pkgDir := strings.TrimPrefix(filepath.ToSlash(filepath.Dir(path)), "../")
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewWriter" {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != local {
				return true
			}
			if _, allowed := zipWriterPackages[pkgDir]; allowed {
				seen[pkgDir] = true
				return true
			}
			pos := fset.Position(sel.Pos())
			t.Errorf("%s:%d: constructs an archive/zip writer — a fetched module zip is stored verbatim and "+
				"never recompressed, so a writer here either re-zips an artefact (which breaks the hash its "+
				"trust anchor covers) or builds one that is not a fetched artefact. If it is the second, add "+
				"%s to zipWriterPackages with the reason no fetched artefact reaches it",
				strings.TrimPrefix(filepath.ToSlash(path), "../"), pos.Line, pkgDir)
			return true
		})
	}
	for pkgDir, reason := range zipWriterPackages {
		if !seen[pkgDir] {
			t.Errorf("zipWriterPackages allows %q (%s), which no longer constructs an archive/zip writer — "+
				"remove the entry rather than leaving a permission nothing uses", pkgDir, reason)
		}
	}
}

// zipImportName returns the name "archive/zip" is bound to in f, or "" when f
// does not import it. A blank or dot import binds no selector and is reported
// as absent.
func zipImportName(f *ast.File) string {
	for _, spec := range f.Imports {
		if spec.Path.Value != `"archive/zip"` {
			continue
		}
		if spec.Name == nil {
			return "zip"
		}
		if spec.Name.Name == "_" || spec.Name.Name == "." {
			return ""
		}
		return spec.Name.Name
	}
	return ""
}

// repoGoFiles lists every non-test Go file under the given roots. A root that
// does not exist is an error, not an empty result: a guard reading nothing
// passes by finding nothing.
func repoGoFiles(t *testing.T, roots ...string) []string {
	t.Helper()
	var out []string
	for _, root := range roots {
		before := len(out)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("walk %s: %w", path, err)
			}
			if info.IsDir() {
				if info.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
		if len(out) == before {
			t.Fatalf("%s holds no non-test Go files: the walk is reading the wrong place", root)
		}
	}
	return out
}

// TestNoCrossContextApplicationImports enforces that an application layer
// never reaches into another bounded context's application or adapters
// package. Cross-context use must go through the other context's ports (or
// the shared fetch/domain coordinate), with composition pushed into adapters
// (prevention 2a, first bullet).
func TestNoCrossContextApplicationImports(t *testing.T) {
	for _, pkg := range loadInternalPackages(t) {
		ctx, layer := layerOf(rel(pkg.PkgPath))
		if ctx == "" || layer != "application" {
			continue
		}
		for impPath := range pkg.Imports {
			impCtx, impLayer := layerOf(rel(impPath))
			if impCtx == "" || impCtx == ctx {
				continue
			}
			if impLayer == "application" || impLayer == "adapters" {
				t.Errorf("%s imports %s: application must not depend on another context's %s layer — use %s/ports and compose in adapters",
					rel(pkg.PkgPath), rel(impPath), impLayer, impCtx)
			}
		}
	}
}

// sharedAdaptersPrefix is the repo-relative package prefix of the shared-kernel
// adapters. layerOf reports no context for one, so it is matched by prefix
// where a context's own adapters layer is matched by layer.
const sharedAdaptersPrefix = "internal/adapters/"

// adapterImportReason returns why a package in layer may not import impRel, or
// "" when it may. It is the whole of the rule, so the guard below and the two
// controls that pin its scope read the same function rather than three copies
// that could drift apart.
//
// Only "domain" is restricted. application is deliberately out of scope: the
// shared adapters exist for it to call, ziparchive's own package doc names the
// contexts that consume parsed entries through it, and docs/ARCHITECTURE.md
// lists it among the shared adapters. TestApplicationMayImportSharedAdapters
// holds that decision by assertion.
func adapterImportReason(layer, impRel string) string {
	if layer != "domain" {
		return ""
	}
	if strings.HasPrefix(impRel, sharedAdaptersPrefix) {
		return "a shared-kernel adapter is infrastructure"
	}
	if impCtx, impLayer := layerOf(impRel); impCtx != "" && impLayer == "adapters" {
		return "another context's adapters layer is infrastructure"
	}
	return ""
}

// TestNoAdapterImportsInDomain enforces that a domain layer never imports an
// adapters package — neither the shared kernel under internal/adapters/ nor a
// context's own internal/<ctx>/adapters. docs/ARCHITECTURE.md says a domain
// layer is pure Go with no I/O, and says outright that the shared value types
// are imported from domain layers that must not reach an adapter. Nothing
// checked it: TestNoInfraImportsInApplicationOrDomain checks six stdlib imports
// and TestNoCrossContextApplicationImports skips every layer but application,
// so a domain file importing an adapter fell between them.
//
// There is no exemption list because there is nothing to exempt: no domain
// package imports an adapters package. A violation is a real one, to be fixed
// by depending on a port the context owns and wiring the adapter above.
//
// It names the file, not just the package, by parsing the package's files —
// but only once a violation is found, so a green run parses nothing. The files
// are the ones loadInternalPackages compiles, which is the scope every guard in
// this file reads.
func TestNoAdapterImportsInDomain(t *testing.T) {
	for _, pkg := range loadInternalPackages(t) {
		relPath := rel(pkg.PkgPath)
		ctx, layer := layerOf(relPath)
		if ctx == "" || layer != "domain" {
			continue
		}
		forbidden := map[string]string{}
		for impPath := range pkg.Imports {
			impRel := rel(impPath)
			if reason := adapterImportReason(layer, impRel); reason != "" {
				forbidden[impRel] = reason
			}
		}
		if len(forbidden) == 0 {
			continue
		}
		named := 0
		for _, file := range pkg.GoFiles {
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", file, err)
			}
			for _, spec := range parsed.Imports {
				impRel := rel(strings.Trim(spec.Path.Value, `"`))
				reason, bad := forbidden[impRel]
				if !bad {
					continue
				}
				named++
				t.Errorf("%s imports %s: %s — a domain layer is pure Go with no I/O "+
					"(docs/ARCHITECTURE.md, \"Layers\"); depend on a port the context owns and wire the adapter "+
					"in the application or adapters layer",
					repoRelFile(file), impRel, reason)
			}
		}
		if named == 0 {
			// The package imports an adapter and no file of it does, so the
			// attribution missed the file rather than the tree being clean.
			for impRel, reason := range forbidden {
				t.Errorf("%s imports %s: %s — a domain layer is pure Go with no I/O; the importing file was not "+
					"found among the package's %d compiled files, so report the package",
					relPath, impRel, reason, len(pkg.GoFiles))
			}
		}
	}
}

// repoRelFile makes an absolute file path from packages.Load repo-relative, so
// a failure names the path a reader can open.
func repoRelFile(path string) string {
	slashed := filepath.ToSlash(path)
	if i := strings.LastIndex(slashed, "/internal/"); i >= 0 {
		return slashed[i+1:]
	}
	return slashed
}

// pinnedApplicationAdapterImport is one of the application imports of a shared
// adapter that TestNoAdapterImportsInDomain must not forbid. Nine such imports
// exist across seven files, six of them of ziparchive; this is one of them,
// asserted so the scope decision is held by a test rather than by the absence
// of one.
var pinnedApplicationAdapterImport = struct{ pkg, imported string }{
	pkg:      "internal/fetch/application",
	imported: "internal/adapters/ziparchive",
}

// TestApplicationMayImportSharedAdapters pins application out of scope. It
// fails if the rule started forbidding the import, and it fails if the import
// stopped existing — a pin nothing exercises would let the rule widen unnoticed.
func TestApplicationMayImportSharedAdapters(t *testing.T) {
	pin := pinnedApplicationAdapterImport
	if reason := adapterImportReason("application", pin.imported); reason != "" {
		t.Errorf("%s imports %s and the rule now forbids it (%s) — application is deliberately in scope for no "+
			"adapter ban: the shared adapters exist for it to call", pin.pkg, pin.imported, reason)
	}
	found := false
	for _, pkg := range loadInternalPackages(t) {
		if rel(pkg.PkgPath) != pin.pkg {
			continue
		}
		for impPath := range pkg.Imports {
			if rel(impPath) == pin.imported {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("%s no longer imports %s — the pin exercises nothing, so pick another of the application imports "+
			"of internal/adapters/ and name it here", pin.pkg, pin.imported)
	}
}

// sharedValueTypesImportableFromDomain are the packages docs/ARCHITECTURE.md
// classifies as shared value types: names several contexts agree on rather than
// services one of them calls. They live outside internal/adapters/ precisely
// because a domain layer imports them, which is the reason their exemption in
// sharedInternalExemptions states.
var sharedValueTypesImportableFromDomain = []string{
	"internal/coordinate",
	"internal/gotoolchain",
}

// TestDomainMayImportSharedValueTypes is the control on the other side of the
// rule: the guard must forbid adapters and nothing else. It fails if the rule
// grew to cover a shared value type, and if a domain layer stopped importing
// one — at which point the placement reason recorded for it would have gone
// stale.
func TestDomainMayImportSharedValueTypes(t *testing.T) {
	pkgs := loadInternalPackages(t)
	for _, shared := range sharedValueTypesImportableFromDomain {
		if reason := adapterImportReason("domain", shared); reason != "" {
			t.Errorf("the rule forbids a domain layer from importing %s (%s) — it is a shared value type, "+
				"not an adapter", shared, reason)
		}
		importers := 0
		for _, pkg := range pkgs {
			if ctx, layer := layerOf(rel(pkg.PkgPath)); ctx == "" || layer != "domain" {
				continue
			}
			for impPath := range pkg.Imports {
				if rel(impPath) == shared {
					importers++
				}
			}
		}
		if importers == 0 {
			t.Errorf("no domain package imports %s — sharedInternalExemptions says it stays outside "+
				"internal/adapters/ because a domain layer imports it, and that reason has gone stale",
				shared)
		}
	}
}

// sharedInternalExemptions classifies every directory directly under internal/
// that is not a bounded context, naming the reason it is not infrastructure and
// so may stay out of internal/adapters/ however many contexts import it.
//
// docs/ARCHITECTURE.md ("Shared Adapters") says infrastructure used by more
// than one context lives under internal/adapters/ rather than being re-declared
// per context. Nothing checked that, so the rule held only where somebody
// remembered it. TestSharedInternalPackagesLiveUnderAdapters checks it, and
// this map is the whole of the escape hatch: an entry is a claim that the
// directory is not infrastructure, not that its placement is inconvenient to
// fix.
//
// Five reasons appear, and each is a category the architecture already has:
//
//   - a shared value type is a name three contexts agree on, not a service one
//     of them calls, and it is imported from domain layers — where an adapters
//     package must never be reached from;
//   - the composition layer sits above the contexts and is exempt from the
//     cross-context import ban for the same reason it is exempt from this one;
//   - a context-shaped concern with its own documented section is placed by
//     that section, not by importer count;
//   - test infrastructure is not used by any context at run time;
//   - and internal/adapters is the destination, so it satisfies the rule by
//     being it.
//
// The map covers directories no context imports today (the composition layer),
// because the classification is what the entry records: leaving them out would
// mean discovering the category the first time an import crossed a second
// context, under a failing test. TestSharedInternalExemptionsAreLive fails on
// an entry that no longer names a non-context directory, so the list drains as
// the tree moves.
var sharedInternalExemptions = map[string]string{
	"adapters": "the destination itself",
	"coordinate": "shared value type: the module coordinate every context names, " +
		"imported from domain layers that must not reach an adapter",
	"gotoolchain": "shared value type: names a fact about a record, shared so that three " +
		"ledgers render \"not recorded\" the same way; imported from the vuln, iface and " +
		"callgraph domains, which must not reach an adapter",
	"audit": "its own documented section: the context-neutral audit-event vocabulary, pure and " +
		"placed by docs/ARCHITECTURE.md (\"Audit Log\"); the JSONL adapter that persists it is " +
		"already under internal/adapters",
	"cli":         "composition layer: the cobra command surface, above the contexts",
	"composition": "composition layer: the neutral composition root shared by the CLI and the facade",
	"driver":      "composition layer: cross-context use cases that sit above the contexts",
	"canonicalshape": "test infrastructure: no production importer, so no context depends on it " +
		"at run time",
	"wireshape": "test infrastructure: no production importer, so no context depends on it " +
		"at run time",
}

// TestSharedInternalPackagesLiveUnderAdapters enforces the placement rule
// docs/ARCHITECTURE.md states and nothing checked: a package under internal/
// that more than one bounded context imports is infrastructure, and lives under
// internal/adapters/ unless sharedInternalExemptions says why it is not.
//
// It counts test importers as well as production ones. A helper shared by seven
// contexts' tests is shared code by the same argument, and counting it is what
// makes the "test infrastructure" exemptions load-bearing rather than decorative
// — an entry that gained a production importer would be caught by the reason it
// states no longer being true, not by an importer count quietly crossing two.
//
// The contexts are derived from the tree by boundedContexts, not listed here.
func TestSharedInternalPackagesLiveUnderAdapters(t *testing.T) {
	importers := internalDirImporters(t)
	dirs := make([]string, 0, len(importers))
	for dir := range importers {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		if boundedContexts()[dir] {
			continue
		}
		if _, exempt := sharedInternalExemptions[dir]; exempt {
			continue
		}
		ctxs := keysOf(importers[dir])
		if len(ctxs) < 2 {
			continue
		}
		sort.Strings(ctxs)
		t.Errorf("internal/%s is imported by %d bounded contexts (%s) and does not live under internal/adapters/ — "+
			"infrastructure used by more than one context lives under internal/adapters/ rather than at internal/ top level "+
			"(docs/ARCHITECTURE.md, \"Shared Adapters\"); move it there, or add it to sharedInternalExemptions with the "+
			"reason it is not infrastructure",
			dir, len(ctxs), strings.Join(ctxs, ", "))
	}
}

// TestSharedInternalExemptionsAreLive fails on an entry in
// sharedInternalExemptions that no longer names a directory directly under
// internal/, or that names one the tree now derives as a bounded context. Either
// way the entry exempts nothing from a rule that never reaches it, while reading
// as a live decision — which is how the hand-written context list this file
// replaced came to describe a tree that had moved on.
func TestSharedInternalExemptionsAreLive(t *testing.T) {
	for dir, reason := range sharedInternalExemptions {
		info, err := os.Stat(filepath.Join("../internal", dir))
		if err != nil || !info.IsDir() {
			t.Errorf("sharedInternalExemptions names internal/%s (%s), which is not a directory under internal/ — remove the entry",
				dir, reason)
			continue
		}
		if boundedContexts()[dir] {
			t.Errorf("sharedInternalExemptions exempts internal/%s (%s), which the tree derives as a bounded context — "+
				"the placement rule already skips a context, so remove the entry", dir, reason)
		}
	}
}

// internalDirImporters maps each directory directly under internal/ to the set
// of bounded contexts that import a package under it, from production or test
// code. A context importing its own directory is not an importer of it.
//
// It reads imports from the files rather than from packages.Load so that
// _test.go files count: a package every context's tests reach is shared across
// contexts whether or not a binary links it.
func internalDirImporters(t *testing.T) map[string]map[string]bool {
	t.Helper()
	const internalDir = "../internal"
	const internalPrefix = modulePath + "/internal/"
	out := map[string]map[string]bool{}
	files := 0
	err := filepath.Walk(internalDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if info.IsDir() {
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		ctx := topLevelInternalDir(filepath.Dir(path), internalDir)
		if ctx == "" || !boundedContexts()[ctx] {
			return nil
		}
		parsed, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return fmt.Errorf("parsing %s: %w", path, perr)
		}
		files++
		for _, spec := range parsed.Imports {
			imported := strings.Trim(spec.Path.Value, `"`)
			if !strings.HasPrefix(imported, internalPrefix) {
				continue
			}
			dir, _, _ := strings.Cut(strings.TrimPrefix(imported, internalPrefix), "/")
			if dir == "" || dir == ctx {
				continue
			}
			if out[dir] == nil {
				out[dir] = map[string]bool{}
			}
			out[dir][ctx] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", internalDir, err)
	}
	if files == 0 {
		t.Fatalf("no Go files read under %s: the walk is reading the wrong place, and a guard reading nothing passes by finding nothing", internalDir)
	}
	return out
}

// topLevelInternalDir returns the directory directly under internal/ that holds
// dir, or "" when dir is internal/ itself or outside it.
func topLevelInternalDir(dir, internalDir string) string {
	inner, err := filepath.Rel(internalDir, dir)
	if err != nil || inner == "." || strings.HasPrefix(inner, "..") {
		return ""
	}
	top, _, _ := strings.Cut(filepath.ToSlash(inner), "/")
	return top
}

// TestNoWallClockInApplicationOrDomain is the enforced equivalent of the
// .golangci.yml forbidigo rule (prevention 2b): no time.Now or
// time.Since in any application or domain layer. It is implemented as a
// test, not only as lint config, because `make lint` does not run
// golangci-lint — `make test` is the mechanism that actually gates CI.
// Wall-clock access must go through the injected Clock (record timestamps)
// or a Stopwatch (latency metrics). Comments do not count (AST-based).
func TestNoWallClockInApplicationOrDomain(t *testing.T) {
	const repoRoot = ".."
	banned := map[string]bool{"Now": true, "Since": true}

	for _, ctx := range keysOf(boundedContexts()) {
		for _, layer := range []string{"application", "domain"} {
			root := filepath.Join(repoRoot, "internal", ctx, layer)
			if _, err := os.Stat(root); err != nil {
				continue
			}
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return fmt.Errorf("walk %s: %w", path, err)
				}
				if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				fset := token.NewFileSet()
				f, perr := parser.ParseFile(fset, path, nil, 0)
				if perr != nil {
					return fmt.Errorf("parse %s: %w", path, perr)
				}
				ast.Inspect(f, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					pkgIdent, ok := sel.X.(*ast.Ident)
					if !ok || pkgIdent.Name != "time" || !banned[sel.Sel.Name] {
						return true
					}
					rp := strings.TrimPrefix(filepath.ToSlash(path), "../")
					t.Errorf("%s: time.%s in %s layer — inject clock.Clock (timestamps) or a Stopwatch (latency)",
						rp, sel.Sel.Name, layer)
					return true
				})
				return nil
			})
			if err != nil {
				t.Fatalf("walking %s: %v", root, err)
			}
		}
	}
}

// facadeExportViolations reports every exported top-level identifier in the
// given parsed files that lacks a doc comment or a Stability line (§5).
// A doc comment and Stability line may come from the identifier's own comment or,
// for a single-spec or grouped declaration, the enclosing GenDecl's comment — so
// a grouped const/var block documents its members collectively. Messages are
// "<name>: <reason>" so callers can prefix the file path. The check is purely
// AST-based: it never imports the package, so it runs even mid-refactor.
func facadeExportViolations(files []*ast.File) []string {
	var out []string
	check := func(name string, own, parent *ast.CommentGroup) {
		if !ast.IsExported(name) {
			return
		}
		var text string
		if own != nil {
			text += own.Text()
		}
		if parent != nil {
			text += parent.Text()
		}
		switch {
		case strings.TrimSpace(text) == "":
			out = append(out, name+": exported but undocumented — add a doc comment with a Stability line")
		case !strings.Contains(text, "Stability:"):
			out = append(out, name+": documented but untagged — add a Stability line stating its consumer relationship")
		}
	}
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					continue // methods are documented under their receiver type
				}
				check(d.Name.Name, d.Doc, nil)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						check(s.Name.Name, s.Doc, d.Doc)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							check(n.Name, s.Doc, d.Doc)
						}
					}
				}
			}
		}
	}
	return out
}

// TestPublicFacadeExportsDocumentedAndTagged enforces §5: the frozen
// public surface in pkg/kanonarion must not grow accidentally, so every exported
// identifier carries BOTH a doc comment and a Stability line stating its
// consumer relationship. This is the CI gate that fails on a new undocumented or
// untagged export and passes on the curated surface. The checker logic lives in
// facadeExportViolations and is exercised against synthetic sources by
// TestFacadeExportCheckerRejectsBadExports.
func TestPublicFacadeExportsDocumentedAndTagged(t *testing.T) {
	const dir = "../pkg/kanonarion"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test source files found in pkg/kanonarion")
	}
	for _, v := range facadeExportViolations(files) {
		t.Errorf("pkg/kanonarion %s", v)
	}
}

// TestFacadeExportCheckerRejectsBadExports is the regression guard for the gate
// itself: it proves facadeExportViolations actually rejects an undocumented
// export and a documented-but-untagged export, and accepts a properly curated
// one. Without a working checker this test fails, so the CI gate cannot silently
// degrade into a no-op.
func TestFacadeExportCheckerRejectsBadExports(t *testing.T) {
	const src = `package kanonarion

// Good is documented and tagged.
//
// Stability: result type (received by consumers); unstable pre-v1.
type Good = int

type Undocumented = int

// Untagged has a doc comment but no Stability line.
type Untagged = int

// unexported is ignored even without a Stability line.
type unexported = int
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	got := facadeExportViolations([]*ast.File{f})
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "Good:") {
		t.Errorf("checker flagged a well-formed export:\n%s", joined)
	}
	if strings.Contains(joined, "unexported") {
		t.Errorf("checker flagged an unexported identifier:\n%s", joined)
	}
	if !strings.Contains(joined, "Undocumented: exported but undocumented") {
		t.Errorf("checker did not reject the undocumented export:\n%s", joined)
	}
	if !strings.Contains(joined, "Untagged: documented but untagged") {
		t.Errorf("checker did not reject the untagged export:\n%s", joined)
	}
}

// TestConsumerCapstoneImportsPublicSurfaceOnly enforces the capstone
// acceptance mechanically: the consumer-shaped acceptance test under
// test/consumer must compile against the public façade ONLY. It fails if any
// file there imports an internal package — the boundary the façade exists to
// hold. It also asserts the public package IS imported, so the guard cannot pass
// vacuously against an empty directory.
func TestConsumerCapstoneImportsPublicSurfaceOnly(t *testing.T) {
	const dir = "consumer"
	const publicPkg = modulePath + "/pkg/kanonarion"
	internalPrefix := modulePath + "/internal/"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var importsPublic, sawGoFile bool
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		sawGoFile = true
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(path, internalPrefix) || path == modulePath+"/internal" {
				t.Errorf("%s imports internal package %q — the capstone must consume only the public façade", e.Name(), path)
			}
			if path == publicPkg {
				importsPublic = true
			}
		}
	}
	if !sawGoFile {
		t.Fatalf("no Go files found under %s", dir)
	}
	if !importsPublic {
		t.Errorf("no file under %s imports %q — the capstone must exercise the public façade", dir, publicPkg)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestNoInfraImportsInApplicationOrDomain enforces that the application and
// domain layers stay free of source/format parsing and raw SQL — those
// concerns belong behind port-backed adapters (prevention 2a,
// second bullet).
func TestNoInfraImportsInApplicationOrDomain(t *testing.T) {
	seen := make(map[string]bool, len(knownInfraViolations))
	for _, pkg := range loadInternalPackages(t) {
		relPath := rel(pkg.PkgPath)
		ctx, layer := layerOf(relPath)
		if ctx == "" || (layer != "application" && layer != "domain") {
			continue
		}
		for impPath := range pkg.Imports {
			reason, forbidden := forbiddenLayerImports[impPath]
			if !forbidden {
				continue
			}
			key := relPath + " " + impPath
			if ticket, grandfathered := knownInfraViolations[key]; grandfathered {
				seen[key] = true
				t.Logf("known layering violation (tracked by %s): %s imports %q", ticket, relPath, impPath)
				continue
			}
			t.Errorf("%s imports %q: %s — new violation; route through a port-backed adapter",
				relPath, impPath, reason)
		}
	}
	for key, ticket := range knownInfraViolations {
		if !seen[key] {
			t.Errorf("knownInfraViolations entry %q (%s) no longer violates — remove it from the baseline now that %s is fixed",
				key, ticket, ticket)
		}
	}
}

// valueObjectAccessors are the methods that replaced an exported field on each
// value object, keyed by the fully qualified receiver type. A missing call on
// one of these yields a func value rather than the string or bool the reader
// meant, which is what makes the omission dangerous rather than merely wrong.
//
// Each entry is one conversion: ModuleCoordinate, then the artefact identity
// and the hash inside it, then the blob identity that addresses an artefact in
// a store, then the advisory-database snapshot a vulnerability verdict was
// reached against. The identity is the key the fetch ledger composes on and the
// value the extraction contexts embed, so an uncalled accessor there reaches a
// SQL parameter by the same route the coordinate's did. The blob identity
// reaches one by a shorter route still: its String is written to the
// content_location and go_mod_location columns of every fact record. The
// snapshot's Source and Version are two of the vulnerability ledger's primary
// key columns and are passed as any to ExecContext, which is exactly the shape
// the compiler accepts and the run time does not — four such method values
// survived that conversion's clean build and were caught here.
var valueObjectAccessors = map[string]map[string]bool{
	modulePath + "/internal/coordinate.ModuleCoordinate": {
		"Path": true, "Version": true, "String": true, "IsLocal": true,
	},
	modulePath + "/internal/fetch/domain.ArtefactIdentity": {
		"Hash": true, "GoModOnly": true, "String": true, "IsZero": true,
	},
	modulePath + "/internal/fetch/domain.ModuleHash": {
		"Algorithm": true, "Value": true, "String": true, "IsZero": true,
	},
	modulePath + "/internal/fetch/ports.BlobIdentity": {
		"Kind": true, "Hash": true, "String": true, "IsZero": true,
	},
	modulePath + "/internal/vuln/domain.DatabaseSnapshot": {
		"Source": true, "Version": true, "RetrievedAt": true, "ContentHash": true,
		"String": true, "IsZero": true,
	},
}

// TestNoCoordinateAccessorMethodValues is the residual guard on unexporting the
// fields of the value objects above.
//
// Unexporting them turned every read of coord.Path into a call. The compiler
// catches almost all of the ones that were missed — a func() string will not
// concatenate, compare or pass as a string — but it accepts three shapes that
// fail only at run time: an argument typed any (a SQL query parameter, a
// structured-log field, an audit event's payload), a %v or %s verb (go vet
// catches those, and did), and a value stored into an interface field.
//
// This is not hypothetical. The coordinate conversion left 88 such method
// values behind: they built cleanly and vet passed on all but seven, and the
// first evidence was "sql: converting argument $1 type: unsupported type
// func() string" from the fact store. Nothing else in the toolchain rejects
// them, so the check lives here, and every later conversion is added to
// valueObjectAccessors rather than trusted to a clean build.
func TestNoCoordinateAccessorMethodValues(t *testing.T) {
	cfg := &packages.Config{
		Mode:  packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedName | packages.NeedFiles | packages.NeedDeps | packages.NeedImports,
		Tests: true,
		Dir:   "..",
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	reported := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			called := map[ast.Expr]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					called[c.Fun] = true
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || called[ast.Expr(sel)] {
					return true
				}
				selection := pkg.TypesInfo.Selections[sel]
				if selection == nil || selection.Kind() != types.MethodVal {
					return true
				}
				// Selections is the only reliable oracle here: the receiver type
				// says which value object this is, and a nil Selection means the
				// selector is not a method on a value at all.
				recv := strings.TrimPrefix(selection.Recv().String(), "*")
				if !valueObjectAccessors[recv][sel.Sel.Name] {
					return true
				}
				pos := pkg.Fset.Position(sel.Sel.Pos())
				msg := fmt.Sprintf("%s:%d:%d: %s.%s is used as a method value, not called — add the parentheses; a func() reaching an any-typed argument fails at run time, not at build time",
					pos.Filename, pos.Line, pos.Column, recv[strings.LastIndex(recv, ".")+1:], sel.Sel.Name)
				if !reported[msg] {
					reported[msg] = true
					t.Error(msg)
				}
				return true
			})
		}
	}
}

// TestNoInlineAnalysisEnvironments closes the shape three separate defects had:
// a Go child handed an environment assembled at the call site, missing one
// variable the builder beside it already sets. Every function that builds one by
// appending to os.Environ() must be a registered producer with a stated posture,
// and the registry must drain — an entry that no longer matches is as much a
// failure as an unregistered site.
func TestNoInlineAnalysisEnvironments(t *testing.T) {
	seen := map[string]bool{}
	for _, root := range []string{"../internal", "../cmd"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("walk %s: %w", path, err)
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			pkgDir := strings.TrimPrefix(filepath.ToSlash(filepath.Dir(path)), "../")
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || !buildsEnvironInline(fn.Body) {
					continue
				}
				key := pkgDir + " " + fn.Name.Name
				if _, registered := goenv.EnvBuilders[key]; !registered {
					t.Errorf("%s builds a process environment from os.Environ() inline; give it a stated posture "+
						"or route it through the producer that already has one", key)
					continue
				}
				seen[key] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	for key, posture := range goenv.EnvBuilders {
		if !seen[key] {
			t.Errorf("registered environment builder %q (%s) no longer builds one — remove the entry", key, posture)
		}
	}
}

// buildsEnvironInline reports whether body contains an append whose arguments
// include a call to os.Environ().
func buildsEnvironInline(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); !ok || ident.Name != "append" {
			return true
		}
		for _, arg := range call.Args {
			inner, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := inner.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Environ" {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" {
				found = true
			}
		}
		return true
	})
	return found
}

// execImportName returns the local name bound to "os/exec" in f, or "" when
// the file does not import it under a usable name. An aliased import is
// therefore still caught, and an unrelated package called exec is not.
func execImportName(f *ast.File) string {
	for _, spec := range f.Imports {
		if spec.Path.Value != `"os/exec"` {
			continue
		}
		if spec.Name == nil {
			return "exec"
		}
		if spec.Name.Name == "_" || spec.Name.Name == "." {
			return ""
		}
		return spec.Name.Name
	}
	return ""
}

// spawnsChildDirectly reports whether body calls exec.Command or
// exec.CommandContext, given the local name bound to os/exec in that file.
func spawnsChildDirectly(body *ast.BlockStmt, execName string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == execName {
			found = true
		}
		return true
	})
	return found
}

// TestEveryChildProcessIsHardened closes the class that regrew after the
// childproc wrapper was written: the wrapper bounds child lifetime, the sites
// that prompted it were converted, and twelve others went on calling os/exec
// directly — three of them without a context at all, so nothing could stop
// them, and the rest without the process group that makes a cancel reach the
// grandchildren.
//
// What the hardening buys is not interactive cancellation, which a child in the
// parent's own process group already gets from the terminal. It is the parent
// that dies WITHOUT sending anything: a SIGKILL, an OOM kill, a crash. No signal
// reaches the group then, and only PR_SET_PDEATHSIG reaps the child. A `go
// build` or a `go list -m all` orphaned that way keeps holding the working set
// that got its parent killed. TestUnhardenedChildOutlivesAKilledParent measures
// exactly that, beside the hardened case it is the control for.
//
// A function that starts a child with os/exec must therefore be registered in
// childproc.DirectSpawns with a reason. The map drains too: an entry naming a
// function that no longer spawns one fails, so a permission cannot outlive the
// call it was granted for.
//
// Test files are exempt. A fixture that runs `git init` or `go list` to build a
// tree for one test is not a child of the product, and nothing outlives the
// test binary that a hardening rule would protect.
func TestEveryChildProcessIsHardened(t *testing.T) {
	const wrapperDir = "internal/adapters/childproc"
	seen := map[string]bool{}
	for _, root := range []string{"../internal", "../cmd"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return fmt.Errorf("walk %s: %w", path, err)
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
			if perr != nil {
				return fmt.Errorf("parse imports of %s: %w", path, perr)
			}
			execName := execImportName(f)
			if execName == "" {
				return nil
			}
			f, perr = parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			pkgDir := strings.TrimPrefix(filepath.ToSlash(filepath.Dir(path)), "../")
			if pkgDir == wrapperDir {
				return nil // the wrapper is where os/exec is called from
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || !spawnsChildDirectly(fn.Body, execName) {
					continue
				}
				key := pkgDir + " " + fn.Name.Name
				if _, registered := childproc.DirectSpawns[key]; !registered {
					t.Errorf("%s starts a child with os/exec directly; build it with childproc.CommandContext "+
						"so a parent that dies without warning cannot orphan it, or register the exemption in "+
						"childproc.DirectSpawns with the reason the default cannot apply", key)
					continue
				}
				seen[key] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	for key, reason := range childproc.DirectSpawns {
		if !seen[key] {
			t.Errorf("childproc.DirectSpawns exempts %q (%s), which no longer starts a child with os/exec — remove the entry", key, reason)
		}
	}
}

// TestHardeningGuardCatchesANewDirectSpawn plants the violation the guard
// exists to catch and shows it caught. A guard whose detector is never run
// against a positive case is decoration: the one this replaces a hand-list with
// would pass just as quietly if spawnsChildDirectly matched nothing at all.
func TestHardeningGuardCatchesANewDirectSpawn(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "a new unhardened spawn",
			src:  "package p\nimport \"os/exec\"\nfunc scan() { _ = exec.Command(\"go\", \"list\") }\n",
			want: true,
		},
		{
			name: "a new unhardened spawn under an aliased import",
			src:  "package p\nimport osexec \"os/exec\"\nfunc scan() { _ = osexec.CommandContext(nil, \"go\", \"list\") }\n",
			want: true,
		},
		{
			name: "the hardened form the guard must not flag",
			src:  "package p\nimport \"github.com/eitanity/kanonarion/internal/adapters/childproc\"\nfunc scan() { _ = childproc.CommandContext(nil, \"go\", \"list\") }\n",
			want: false,
		},
		{
			name: "an unrelated package that happens to be called exec",
			src:  "package p\nimport \"example.com/exec\"\nfunc scan() { _ = exec.Command(\"go\") }\n",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "planted.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse planted source: %v", err)
			}
			execName := execImportName(f)
			got := false
			if execName != "" {
				for _, decl := range f.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && spawnsChildDirectly(fn.Body, execName) {
						got = true
					}
				}
			}
			if got != tc.want {
				t.Errorf("guard detected = %v, want %v", got, tc.want)
			}
		})
	}
}

// orderingFuncs are the sort entry points whose comparator this guard reads.
// sort.Strings, slices.Sort and the rest take no comparator: they order values
// that ARE their own key, so there is nothing to be keyed on incompletely.
var orderingFuncs = map[string]map[string]bool{
	"sort":   {"Slice": true, "SliceStable": true},
	"slices": {"SortFunc": true, "SortStableFunc": true},
}

// primitiveComparisons are the three-way comparison helpers that stand in for
// an operator. A call to one is a KEY, exactly as `a.X < b.X` is, and never a
// delegation to a named ordering.
var primitiveComparisons = map[string]bool{
	"cmp.Compare": true, "strings.Compare": true, "bytes.Compare": true,
}

// singleKeyComparators exempts an inline comparator that IS keyed on one field,
// where that field provably cannot repeat among the elements reaching the sort.
// The value states why. "Probably unique" is not a reason; the reason has to be
// a property of how the slice was built, visible at the call site.
//
// The map must drain: an entry whose site no longer exists, or no longer has a
// single-key comparator, fails as loudly as an unexempted one. Key is
// "<repo-relative file> <enclosing function>".
var singleKeyComparators = map[string]string{
	"internal/local/domain/local_context.go SnapshotModulePath": "the elements are the snapshot's own file-path map keys, so no value repeats, " +
		"and they are compared in full rather than on a field of themselves: two strings that tie ARE the same element",
}

// TestOrderingComparatorsAreTotal reads every sort in a domain package and
// fails the ones whose comparator is keyed on a single field.
//
// A comparator is an ordering only if it answers for every pair. Keyed on one
// field it does not: when two elements tie, it says neither is less, and
// sort.Slice — which is not stable — then puts them in whatever order the input
// happened to be in. The input order comes from a directory walk and from map
// iteration, so the result is not a property of the data, and every collection
// that reaches a content hash seals that arrangement.
//
// This is not a hypothetical. internal/iface/domain sorted a package's
// functions on Name alone; golang.org/x/tools ships testdata directories where
// two files each declare a function of one name; golang.org/x/tools@v0.49.0
// accumulated eight interface records under seven digests, five of them taken
// minutes apart, and the coordinate could never be served because no two
// extractions agreed.
//
// It lives here rather than in .golangci.yml for the reason
// TestNoWallClockInApplicationOrDomain does: `make lint` does not run
// golangci-lint, so `make test` is what gates CI.
//
// sort.SliceStable is read too, and is not an escape. Stability decides a tie by
// INPUT order, which is the input the sealed bytes must not depend on.
func TestOrderingComparatorsAreTotal(t *testing.T) {
	seen := map[string]bool{}
	err := filepath.Walk("../internal", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if _, layer := layerOfDir(filepath.Dir(path)); layer != "domain" {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rp := strings.TrimPrefix(filepath.ToSlash(path), "../")
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := rp + " " + fn.Name.Name
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, name, ok := orderingComparator(n)
				if !ok {
					return true
				}
				if comparatorDelegates(lit) {
					return true
				}
				keys := comparatorKeys(lit)
				if len(keys) >= 2 {
					return true
				}
				if _, exempt := singleKeyComparators[key]; exempt {
					seen[key] = true
					return true
				}
				pos := fset.Position(n.Pos())
				t.Errorf("%s:%d: the %s comparator in %s is keyed on %v — one key is not an ordering, "+
					"because two elements that tie are left to the sort and the sort reads them off a "+
					"directory walk or a map. Give the collection a named Less helper keyed on every "+
					"field it puts on the wire, as internal/callgraph/domain/ordering.go does, or exempt "+
					"it in singleKeyComparators with the reason the key cannot repeat",
					rp, pos.Line, name, fn.Name.Name, keys)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking ../internal: %v", err)
	}
	for key, reason := range singleKeyComparators {
		if !seen[key] {
			t.Errorf("singleKeyComparators exempts %q (%s), which no longer holds a single-key comparator — remove the entry", key, reason)
		}
	}
}

// layerOfDir reports the bounded context and layer for a directory path like
// "../internal/vuln/domain". Unlike layerOf it accepts any context name, since
// the ordering rule is about the layer and not about the closed context set.
func layerOfDir(dir string) (ctx, layer string) {
	parts := strings.Split(filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(dir), "../")), "/")
	if len(parts) < 3 || parts[0] != "internal" {
		return "", ""
	}
	return parts[1], parts[2]
}

// orderingComparator reports the function literal passed as a comparator to one
// of orderingFuncs, and the name of the call it was passed to.
func orderingComparator(n ast.Node) (*ast.FuncLit, string, bool) {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil, "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !orderingFuncs[pkg.Name][sel.Sel.Name] {
		return nil, "", false
	}
	lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
	if !ok {
		return nil, "", false
	}
	return lit, pkg.Name + "." + sel.Sel.Name, true
}

// comparatorDelegates reports whether the literal hands the whole decision to a
// named function — `return CallNodeLess(a, b)`, `return servesBefore(x, y)` —
// rather than making it inline.
//
// The test is the SHAPE, not the name: one return, one call. That is what makes
// the ordering reviewable and testable in one place, which is the property this
// guard is protecting; requiring the name to end in Less or Compare would fail
// the composition ladders, whose comparator is correctly named for what it
// decides. A three-way primitive — cmp.Compare and friends — is a comparison
// rather than a delegation, so `return cmp.Compare(a.ID, b.ID)` is still read as
// the single-key comparator it is.
func comparatorDelegates(lit *ast.FuncLit) bool {
	if len(lit.Body.List) != 1 {
		return false
	}
	ret, ok := lit.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	_, qualified := calleeName(call)
	return !primitiveComparisons[qualified]
}

// comparatorKeys returns the distinct fields the literal compares: the fields
// appearing as operands of a comparison operator or of a three-way primitive.
//
// An operand is named by its dotted path with array indices removed and the
// comparator's OWN parameters dropped, so that `x.Path` and `y.Path` are one key
// and `p.Funcs[i].Name` and `p.Funcs[j].Name` are one key. That is the point of
// the count: two sides of one comparison are one key, and a comparator that
// reaches only one key over its whole body has only one key.
func comparatorKeys(lit *ast.FuncLit) []string {
	params := map[string]bool{}
	for _, field := range lit.Type.Params.List {
		for _, name := range field.Names {
			params[name.Name] = true
		}
	}
	keys := map[string]bool{}
	record := func(e ast.Expr) {
		if name, ok := comparisonKey(e, params); ok {
			keys[name] = true
		}
	}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BinaryExpr:
			switch v.Op {
			case token.LSS, token.GTR, token.LEQ, token.GEQ, token.EQL, token.NEQ:
				record(v.X)
				record(v.Y)
			}
		case *ast.CallExpr:
			if _, qualified := calleeName(v); primitiveComparisons[qualified] && len(v.Args) == 2 {
				record(v.Args[0])
				record(v.Args[1])
			}
		}
		return true
	})
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// comparisonKey names the field an operand reads. A call taking no arguments —
// `a.Path()` — names the method. An operand that reads no field at all (a
// length, a literal, a loop index) is not a key.
func comparisonKey(e ast.Expr, params map[string]bool) (string, bool) {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		if inner, ok := comparisonKey(v.X, params); ok && inner != "" {
			return inner + "." + v.Sel.Name, true
		}
		return v.Sel.Name, true
	case *ast.CallExpr:
		if len(v.Args) == 0 {
			// A no-argument method on the element — `a.Path()` — names the field
			// it reads.
			return comparisonKey(v.Fun, params)
		}
		// A key COMPUTED from the element — `confRank(e.Confidence)`,
		// `strings.ToLower(e.Name)` — is keyed on what it was computed from.
		return comparisonKey(v.Args[0], params)
	case *ast.IndexExpr:
		return comparisonKey(v.X, params)
	case *ast.StarExpr:
		return comparisonKey(v.X, params)
	case *ast.ParenExpr:
		return comparisonKey(v.X, params)
	case *ast.Ident:
		if params[v.Name] {
			// The comparator's own parameter: the two sides of the comparison,
			// which name one key between them and not two.
			return "", true
		}
		// A slice of scalars compared whole: the element IS the key.
		return v.Name, true
	}
	return "", false
}

// calleeName returns the callee's bare name and, for a package-qualified call,
// its "pkg.Name" spelling.
func calleeName(call *ast.CallExpr) (name, qualified string) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, fn.Name
	case *ast.SelectorExpr:
		if pkg, ok := fn.X.(*ast.Ident); ok {
			return fn.Sel.Name, pkg.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name, fn.Sel.Name
	}
	return "", ""
}
