package staticcha

import (
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

func buildNode(fn *ssa.Function, mem moduleMembership, fset *token.FileSet, roots sourceRoots) domain.CallNode {
	pkgPath := funcPackagePath(fn)
	isExternal := !mem.contains(pkgPath)

	symbol := fn.Name()
	receiver := extractReceiverName(fn)

	pos := domain.SourcePosition{}
	if fn.Pos() != token.NoPos && fset != nil {
		if p := fset.Position(fn.Pos()); p.IsValid() {
			pos = roots.position(p)
		}
	}

	// A function with an enclosing function is never public API: no consumer can
	// name a closure, only reach it by calling what encloses it. See
	// isExportedAPI for the rest of the rule.
	isSynthetic := fn.Parent() != nil || hasSyntheticSymbolMarker(symbol)

	exportedAPI := isExportedAPI(isExternal, isSynthetic, symbol, pkgPath, isMainPkg(fn))

	modulePath := ""
	if !isExternal {
		modulePath = mem.path()
	}

	return domain.CallNode{
		ID:            nodeID(fn),
		Module:        modulePath,
		Package:       pkgPath,
		Symbol:        symbol,
		Receiver:      receiver,
		IsExternal:    isExternal,
		IsExportedAPI: exportedAPI,
		Position:      pos,
		IsTest:        isTestFunc(fn, fset, pkgPath),
	}
}

// isTestFunc reports whether fn is test-scope: declared in a _test.go file, or
// in an external test package.
//
// The position is taken from the object rather than the function when the
// function has none, which is the case for the synthetic wrappers SSA
// materialises for a method set. A wrapper around a test fake's method is test
// code, and attributing it to production would put it back in exactly the
// answer the role exists to keep separate.
func isTestFunc(fn *ssa.Function, fset *token.FileSet, pkgPath string) bool {
	if isTestPackagePath(pkgPath) {
		return true
	}
	if fset == nil {
		return false
	}
	pos := fn.Pos()
	if pos == token.NoPos {
		if obj := fn.Object(); obj != nil {
			pos = obj.Pos()
		}
	}
	if pos == token.NoPos {
		// A synthetic function with no object at all — a package initialiser or
		// a bound-method thunk. It inherits its parent's role when it has one.
		if parent := fn.Parent(); parent != nil {
			return isTestFunc(parent, fset, pkgPath)
		}
		return false
	}
	p := fset.Position(pos)
	return p.IsValid() && strings.HasSuffix(p.Filename, "_test.go")
}

// isTestDeclaration is the type-level form of isTestFunc, for a declaration
// identified by its position rather than by an SSA function.
func isTestDeclaration(pos token.Pos, fset *token.FileSet, pkgPath string) bool {
	if isTestPackagePath(pkgPath) {
		return true
	}
	if fset == nil || pos == token.NoPos {
		return false
	}
	p := fset.Position(pos)
	return p.IsValid() && strings.HasSuffix(p.Filename, "_test.go")
}

// isTestPackagePath reports whether an import path names an external test
// package, whose every declaration is test code.
func isTestPackagePath(pkgPath string) bool {
	return strings.HasSuffix(pkgPath, "_test")
}

// funcPackagePath returns the import path of the package a function belongs to.
//
// SSA leaves Package() nil for the synthetic wrappers it materialises for a
// method set — a value-receiver method reached through a pointer, a bound
// method value. Those wrappers are not package members, but they are not
// package-less either: they wrap a method declared in a real package, and the
// object records which. Reading only Package() attributed every one of them to
// no module and marked it external, which mis-scopes reachability rooting and
// module attribution for a symbol that is the module's own code.
func funcPackagePath(fn *ssa.Function) string {
	pkg := funcPackage(fn)
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

// funcPackage returns the package that declares a function, and is the single
// resolution every package-derived fact goes through — the import path a node
// is attributed to, and whether that package is a command.
//
// Package() is documented to be nil for the shared functions SSA synthesises:
// method wrappers, thunks, bound-method values, error.Error. Those functions
// are not package-less, they are shared, and the object records the method they
// stand for. Object() is nil in turn for a function literal and a synthetic
// init, and a literal inherits the package of whatever encloses it.
//
// It returns nil when nothing names the function, which every caller must read
// as the absence of an answer rather than as a package.
func funcPackage(fn *ssa.Function) *types.Package {
	if fn == nil {
		return nil
	}
	if pkg := fn.Package(); pkg != nil && pkg.Pkg != nil {
		return pkg.Pkg
	}
	if obj := fn.Object(); obj != nil && obj.Pkg() != nil {
		return obj.Pkg()
	}
	// A closure inherits the package of whatever encloses it.
	if parent := fn.Parent(); parent != nil {
		return funcPackage(parent)
	}
	return nil
}

// nodeID returns a stable, unique identifier for an SSA function.
// Format: "pkg/path.FuncName", "pkg/path.(*RecvType).MethodName", or, for an
// anonymous function, the enclosing function's identifier plus the SSA anon
// suffix: "pkg/path.(*RecvType).MethodName$1".
//
// A closure is identified through its parent rather than its own signature. Its
// signature has no receiver even when it is declared inside a method, and
// ssa.Function.Name() renders only the enclosing function's *simple* name, so
// deriving the ID from the closure alone drops the receiver — and two same-named
// methods on different receivers then collide on one ID, merging the edge sets
// of unrelated functions.
func nodeID(fn *ssa.Function) string {
	if fn.Package() == nil {
		return fn.String()
	}
	// Anonymous functions carry a parent; qualify them with its full ID so the
	// receiver is preserved. Recursion composes nested closures.
	if parent := fn.Parent(); parent != nil {
		if suffix, ok := anonSuffix(fn.Name(), parent.Name()); ok {
			return nodeID(parent) + suffix
		}
	}
	pkgPath := fn.Package().Pkg.Path()
	sig := fn.Signature
	if sig.Recv() != nil {
		recvTyp := recvTypeStr(sig.Recv().Type())
		return pkgPath + ".(" + recvTyp + ")." + fn.Name()
	}
	return pkgPath + "." + fn.Name()
}

// anonSuffix returns the SSA anon marker that distinguishes a closure's name
// from its parent's (e.g. "$1"), and whether the name had the expected shape.
// A name that does not extend the parent's is left to the caller to handle
// rather than being mangled by a blind trim.
func anonSuffix(name, parentName string) (string, bool) {
	if parentName == "" || !strings.HasPrefix(name, parentName) {
		return "", false
	}
	suffix := name[len(parentName):]
	if suffix == "" || !strings.HasPrefix(suffix, "$") {
		return "", false
	}
	return suffix, true
}

// recvTypeStr returns a concise representation of a receiver type.
func recvTypeStr(t types.Type) string {
	switch v := t.(type) {
	case *types.Pointer:
		if named, ok := v.Elem().(*types.Named); ok {
			return "*" + named.Obj().Name()
		}
		return "*" + v.Elem().String()
	case *types.Named:
		return v.Obj().Name()
	default:
		return t.String()
	}
}
func extractReceiverName(fn *ssa.Function) string {
	sig := fn.Signature
	if sig.Recv() == nil {
		return ""
	}
	return recvTypeStr(sig.Recv().Type())
}

// classifyConfidence resolves an edge's confidence tag. The second result is the
// reflect_dispatch attribute, and it marks an edge whose CALLEE IS IN PACKAGE
// reflect — nothing narrower. It is not a count of reflective dispatches: most
// of what it marks, reflect.TypeOf among it, has one callee and bounds
// perfectly. Such edges are folded into ConfidenceUnknown but carry the reflect
// provenance as an edge attribute.
func classifyConfidence(edge *callgraph.Edge) (domain.EdgeConfidence, bool) {
	if edge.Site == nil {
		return domain.ConfidenceUnknown, false
	}
	common := edge.Site.Common()
	if common.IsInvoke() {
		// An unrefined CHA interface over-approximation.
		return domain.ConfidenceCHAOverapprox, false
	}
	if common.StaticCallee() != nil {
		// Reflect-dispatched calls are unresolved edges tagged with the reflect
		// origin, not a distinct confidence rank.
		if edge.Callee.Func != nil && edge.Callee.Func.Package() != nil {
			if edge.Callee.Func.Package().Pkg.Path() == "reflect" {
				return domain.ConfidenceUnknown, true
			}
		}
		return domain.ConfidenceDirect, false
	}
	return domain.ConfidenceUnknown, false
}

// isExportedAPI reports whether a node is consumable public API of the module
// under analysis. It is the single definition of that rule: every node builder
// must use it, because IsExportedAPI feeds reachability rooting and a symbol
// that is API on one construction path and not on another makes the axis mean
// two things.
//
// token.IsExported inspects the first rune only, and an anonymous function's
// name is the enclosing function's name plus the SSA anon marker ("Method$1"),
// so without the synthetic guard every closure inside an exported function
// reads as exported and becomes a library reachability root that cannot
// actually be triggered; the same holds for bound-method and thunk wrappers.
// Package-main symbols are not consumable API either: nothing can import them.
//
// isSynthetic and isMain are passed in rather than derived because the callers
// hold different evidence — a builder working from go/types has no
// *ssa.Function to ask.
func isExportedAPI(isExternal, isSynthetic bool, symbol, pkgPath string, isMain bool) bool {
	return !isExternal &&
		len(symbol) > 0 &&
		!isSynthetic &&
		token.IsExported(symbol) &&
		!isInternalPkg(pkgPath) &&
		!isMain
}

// hasSyntheticSymbolMarker reports whether a symbol name carries the SSA marker
// that distinguishes a closure, bound-method or thunk wrapper from a declared
// function.
func hasSyntheticSymbolMarker(symbol string) bool {
	return strings.Contains(symbol, "$")
}

func isInternalPkg(path string) bool {
	return strings.Contains(path, "/internal/") ||
		strings.HasSuffix(path, "/internal")
}

// isMainPkg reports whether a function belongs to a command — a package nothing
// can import, and so nothing can call from outside the binary.
//
// It resolves the package through funcPackage rather than Package() alone. A
// value-receiver method on a package-main type, reached through a pointer, is
// carried by a synthetic wrapper whose own Package() is nil; reading only that
// answered "not main" and minted the method as exported library API, which is
// a false claim rather than a weaker one and roots library reachability at an
// entry no consumer could ever reach.
//
// Where no package can be resolved the guard fails closed and answers true: a
// symbol nothing can name is not library API by default. Failing open would
// trade a false root for a missing one, which is harder to notice because
// nothing appears.
func isMainPkg(fn *ssa.Function) bool {
	pkg := funcPackage(fn)
	if pkg == nil {
		return true
	}
	return pkg.Name() == "main"
}

// sourceRoots are the per-run directories a file the loader resolved may sit
// under, and rendering a path against them is what keeps the analysing host out
// of the record.
//
// It is not cosmetic, and the reason is the one moduleRelative states for
// failure detail: a node position is inside the record's canonical form, so a
// component that moves between two runs means no two analyses of an unchanged
// module ever produce the same record. Every repeat then appends a generation,
// for ever, and once two generations disagree the coordinate stops being
// readable at all.
//
// Four roots, each with its own answer:
//
//   - module is the extracted module, whose own files are recorded relative to
//     it — api.go, lib/hooks.go.
//   - buildCache is the Go build cache. A file under it is recorded with NO
//     position at all: the entry is content-addressed, so its path names no file
//     a reader can open and changes whenever the entry is rebuilt. Every
//     cgo-generated symbol and every synthetic .test main is positioned there.
//   - goroot holds the standard library, recorded relative to GOROOT —
//     src/fmt/print.go. It is tried before the module cache because a toolchain
//     fetched as a module lives INSIDE the cache, and spelling its files against
//     the cache would put the toolchain version into the position as well, where
//     the record already states it on its own axis.
//   - moduleCache is the GOMODCACHE the load resolved from, whose files are
//     recorded relative to IT, which spells a dependency's file as
//     github.com/json-iterator/go@v1.1.9/adapter.go: the module, its version and
//     the file, and nothing about where this host keeps them. It holds whichever
//     cache the run read — one it materialised, the operator's under
//     --from-modcache, or the host's — because the same analysis run two ways
//     has to record the same bytes.
type sourceRoots struct {
	module      string
	moduleCache []string
	goroot      []string
	buildCache  []string
}

// SourceDirs are the directories the toolchain THIS analysis drives resolves
// files from, as that toolchain itself names them: `go env GOROOT GOCACHE
// GOMODCACHE`.
//
// They are asked for rather than guessed. A build-cache path is recognised
// because the toolchain says where its cache is, never because a path contains
// "go-build": the cache moves with GOCACHE, and a rule that read a directory
// name would both miss a cache that had moved and claim one that had not.
//
// It is exported because the probe that fills it is implemented at the
// composition root — this package must not spawn processes — and a caller there
// has to be able to name what it is answering.
type SourceDirs struct {
	GOROOT      string
	BuildCache  string
	ModuleCache string
}

// newSourceRoots states the roots for one analysis.
//
// Both spellings of each root are held: the loader reports the path it resolved,
// which on a host whose directory is reached through a symlink is not the path
// this process or the toolchain named.
func newSourceRoots(module, moduleCache string, dirs SourceDirs) sourceRoots {
	return sourceRoots{
		module: module,
		// Both the cache the run named and the one the toolchain resolved: the same
		// directory whenever the run set GOMODCACHE itself, and different exactly
		// when the analysis reads a cache it did not create — the host's, or the
		// operator's under --from-modcache. Those have to be spelled the way a
		// materialised cache is, or one analysis run two ways records two records.
		moduleCache: append(bothSpellings(moduleCache), bothSpellings(dirs.ModuleCache)...),
		goroot:      bothSpellings(dirs.GOROOT),
		buildCache:  bothSpellings(dirs.BuildCache),
	}
}

// bothSpellings names a root the way it was given and the way the filesystem
// resolves it, so a loader that reports either one is recognised.
func bothSpellings(dir string) []string {
	if dir == "" {
		return nil
	}
	out := []string{dir}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil && resolved != dir {
		out = append(out, resolved)
	}
	return out
}

// rel renders one resolved path as the record states it, and reports whether the
// record states it at all. A false means the file has no position a reader could
// use and none is recorded — not an empty string in a field that elsewhere holds
// a path.
func (r sourceRoots) rel(path string) (string, bool) {
	if _, under := relativeToAny(r.buildCache, path); under {
		return "", false
	}
	if rel, ok := relativeToAny(r.goroot, path); ok {
		return rel, true
	}
	if rel, ok := relativeToAny(r.moduleCache, path); ok {
		return rel, true
	}
	if rel, ok := relativeToRoot(r.module, path); ok {
		return rel, true
	}
	// No root this run knows contains it. The path stays exactly as the loader
	// reported it, absolute leading separator and all. Trimming that separator is
	// what disguised an absolute path as a repo-relative one and hid this for as
	// long as it hid: a path that cannot be made relative must stay visibly
	// absolute, so a reader can see that it names a place on someone else's host.
	return path, true
}

// relativeToAny renders path against the first of roots that contains it.
func relativeToAny(roots []string, path string) (string, bool) {
	for _, root := range roots {
		if rel, ok := relativeToRoot(root, path); ok {
			return rel, true
		}
	}
	return "", false
}

// relativeToRoot renders path relative to root, and reports whether root
// contains it at all. An empty root contains nothing.
func relativeToRoot(root, path string) (string, bool) {
	if root == "" {
		return "", false
	}
	rel := strings.TrimPrefix(path, root+string(filepath.Separator))
	if rel == path || rel == "" {
		return "", false
	}
	return rel, true
}

// position renders one resolved source position as the record states it, or the
// zero position when the file it names is one no reader can open.
func (r sourceRoots) position(p token.Position) domain.SourcePosition {
	file, ok := r.rel(p.Filename)
	if !ok {
		return domain.SourcePosition{}
	}
	return domain.SourcePosition{File: file, Line: p.Line}
}
