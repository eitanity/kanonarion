// Package tinycgo loads a Go closure as TinyGo builds it. go list runs without
// compiling, so Go's cgo never sees TinyGo's packages; their files are parsed
// here, TinyGo's own cgo transform rewrites the C references, clang supplies
// the declarations, and go/types checks every package with TinyGo's sizes. The
// result has the shape go/packages returns, so the analysis downstream of the
// load runs unchanged.
package tinycgo

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
)

// Config is what a load under a TinyGo frame needs from the frame and from the
// analysis that runs it.
type Config struct {
	// SourceRoot is TINYGOROOT.
	SourceRoot string
	// Target and Triple name the TinyGo target and its LLVM triple.
	Target, Triple string
	GOOS, GOARCH   string
	Dir            string
	Env            []string
	BuildFlags     []string
	Tests          bool
	Fset           *token.FileSet
	// Step receives the analysis's progress lines; nil narrates nothing.
	Step func(string)
}

// Result is a load's roots, and every loaded package that is TinyGo's own.
type Result struct {
	Roots  []*packages.Package
	TinyGo []*packages.Package
}

// listMode asks go list for metadata only. Without NeedCompiledGoFiles nothing
// is compiled, and with CGO_ENABLED=1 in the environment the cgo files are
// listed among GoFiles.
const listMode = packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedDeps | packages.NeedModule

// Load lists patterns, then parses, transforms and type-checks every package
// of the closure in dependency order.
func Load(ctx context.Context, cfg Config, patterns ...string) (Result, error) {
	sizes, err := SizesFor(cfg.Triple)
	if err != nil {
		return Result{}, err
	}
	roots, err := packages.Load(&packages.Config{
		Mode: listMode, Dir: cfg.Dir, Context: ctx, Env: cfg.Env, BuildFlags: cfg.BuildFlags, Tests: cfg.Tests,
	}, patterns...)
	if err != nil {
		return Result{}, fmt.Errorf("listing the packages: %w", err)
	}
	l := &loader{cfg: cfg, sizes: sizes, srcRoot: resolvedSourceDir(cfg.SourceRoot),
		byPath: map[string]*packages.Package{}, checked: map[*packages.Package]bool{}}
	defer l.cleanup()
	packages.Visit(roots, nil, func(p *packages.Package) {
		if p.ID == p.PkgPath {
			l.byPath[p.PkgPath] = p
		}
	})
	res := Result{Roots: roots}
	packages.Visit(roots, nil, func(p *packages.Package) {
		if ctx.Err() != nil {
			return
		}
		l.ensure(ctx, p)
		if l.isTinyGo(p) {
			res.TinyGo = append(res.TinyGo, p)
		}
	})
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("loading under the TinyGo frame: %w", err)
	}
	return res, nil
}

type loader struct {
	cfg     Config
	sizes   types.Sizes
	srcRoot string
	// The C compiler and the target's flags, found when a file first needs them.
	comp    *compiler
	compErr error
	tmp     string
	nfiles  int
	// byPath is every production package of the closure by import path, and
	// checked those type-checked so far.
	byPath  map[string]*packages.Package
	checked map[*packages.Package]bool
}

// ensure type-checks p after everything it imports.
func (l *loader) ensure(ctx context.Context, p *packages.Package) {
	if l.checked[p] {
		return
	}
	l.checked[p] = true
	for _, ip := range p.Imports {
		l.ensure(ctx, ip)
	}
	l.check(ctx, p)
}

// generatedImports are the packages TinyGo's generated cgo file imports. go
// list does not add them to a standard package's imports, so they are resolved
// from the closure, as TinyGo's loader resolves every import from its program.
var generatedImports = []string{"syscall"}

func (l *loader) cleanup() {
	if l.tmp != "" {
		_ = os.RemoveAll(l.tmp)
	}
}

func (l *loader) step(text string) {
	if l.cfg.Step != nil {
		l.cfg.Step(text)
	}
}

// resolvedSourceDir is TINYGOROOT/src with its symlinks resolved, the form a
// package's resolved directory is compared against.
func resolvedSourceDir(root string) string {
	src := filepath.Join(root, "src")
	if r, err := filepath.EvalSymlinks(src); err == nil {
		return r
	}
	return filepath.Clean(src)
}

// isTinyGo reports whether p's directory, or any of its files, resolves under
// TINYGOROOT/src. The merged GOROOT links TinyGo's packages and Go's side by
// side, and a package like sync mixes files from both.
func (l *loader) isTinyGo(p *packages.Package) bool {
	if l.cfg.SourceRoot == "" {
		return false
	}
	if p.Dir != "" && l.underSourceRoot(p.Dir) {
		return true
	}
	for _, f := range p.GoFiles {
		if l.underSourceRoot(f) {
			return true
		}
	}
	return false
}

func (l *loader) underSourceRoot(path string) bool {
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(l.srcRoot, r)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// check parses, transforms and type-checks one package whose imports are
// checked already, filling the fields go/packages fills.
func (l *loader) check(ctx context.Context, p *packages.Package) {
	fset := l.cfg.Fset
	p.Fset = fset
	p.TypesSizes = l.sizes
	if p.PkgPath == "unsafe" {
		p.Types = types.Unsafe
		p.Syntax = []*ast.File{}
		p.TypesInfo = newTypesInfo()
		return
	}
	files := l.parse(p)
	extra := map[string]*packages.Package{}
	for _, f := range files {
		if importsC(f) {
			if gen := l.processCgo(ctx, p, files); gen != nil {
				files = append(files, gen)
				for _, path := range generatedImports {
					if ip := l.byPath[path]; ip != nil {
						l.ensure(ctx, ip)
						extra[path] = ip
					}
				}
			}
			break
		}
	}
	p.Syntax = files
	p.TypesInfo = newTypesInfo()
	p.Types = types.NewPackage(p.PkgPath, p.Name)
	tc := &types.Config{
		Importer: importerFor(p, extra),
		Sizes:    l.sizes,
		Error: func(err error) {
			var te types.Error
			if errors.As(err, &te) {
				p.TypeErrors = append(p.TypeErrors, te)
				p.Errors = append(p.Errors, packages.Error{Pos: te.Fset.Position(te.Pos).String(), Msg: te.Msg, Kind: packages.TypeError})
				return
			}
			p.Errors = append(p.Errors, packages.Error{Pos: "-", Msg: err.Error(), Kind: packages.UnknownError})
		},
	}
	if p.Module != nil && p.Module.GoVersion != "" {
		tc.GoVersion = "go" + p.Module.GoVersion
	}
	if err := types.NewChecker(tc, fset, p.Types, p.TypesInfo).Files(files); err != nil && len(p.Errors) == 0 {
		p.Errors = append(p.Errors, packages.Error{Pos: "-", Msg: err.Error(), Kind: packages.UnknownError})
	}
	p.IllTyped = len(p.Errors) > 0
}

func (l *loader) parse(p *packages.Package) []*ast.File {
	var files []*ast.File
	for _, name := range p.GoFiles {
		f, err := parser.ParseFile(l.cfg.Fset, name, nil, parser.AllErrors|parser.ParseComments|parser.SkipObjectResolution)
		var list scanner.ErrorList
		switch {
		case errors.As(err, &list):
			for _, e := range list {
				p.Errors = append(p.Errors, packages.Error{Pos: e.Pos.String(), Msg: e.Msg, Kind: packages.ParseError})
			}
		case err != nil:
			p.Errors = append(p.Errors, packages.Error{Pos: name + ":1", Msg: err.Error(), Kind: packages.ParseError})
		}
		if f != nil {
			files = append(files, f)
		}
	}
	return files
}

func newTypesInfo() *types.Info {
	return &types.Info{
		Types:        make(map[ast.Expr]types.TypeAndValue),
		Defs:         make(map[*ast.Ident]types.Object),
		Uses:         make(map[*ast.Ident]types.Object),
		Implicits:    make(map[ast.Node]types.Object),
		Instances:    make(map[*ast.Ident]types.Instance),
		Scopes:       make(map[ast.Node]*types.Scope),
		Selections:   make(map[*ast.SelectorExpr]*types.Selection),
		FileVersions: make(map[*ast.File]string),
	}
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// importerFor resolves p's imports through the metadata go list returned, so a
// test variant binds to the variants it was listed with.
func importerFor(p *packages.Package, extra map[string]*packages.Package) types.Importer {
	return importerFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		ip := p.Imports[path]
		if ip == nil {
			ip = extra[path]
		}
		if ip == nil {
			return nil, fmt.Errorf("no metadata for %s", path)
		}
		if ip.Types == nil {
			return nil, fmt.Errorf("%s was not type-checked", path)
		}
		return ip.Types, nil
	})
}

// processCgo applies TinyGo's cgo transform to files and returns the generated
// file declaring the C names they reference, or nil when they reference none.
func (l *loader) processCgo(ctx context.Context, p *packages.Package, files []*ast.File) *ast.File {
	dir := p.Dir
	if dir == "" {
		dir = filepath.Dir(l.cfg.Fset.File(files[0].Pos()).Name())
	}
	pkg := newCgoPackage(files, dir, p.PkgPath, l.cfg.GOOS, l.cfg.Fset)
	pkg.extractPreambles(files)
	if !hasCReferences(files) {
		return nil
	}
	defer func() {
		for _, e := range pkg.errors {
			var se scanner.Error
			if errors.As(e, &se) {
				p.Errors = append(p.Errors, packages.Error{Pos: positionString(se.Pos), Msg: se.Msg, Kind: packages.UnknownError})
				continue
			}
			p.Errors = append(p.Errors, packages.Error{Pos: "-", Msg: e.Error(), Kind: packages.UnknownError})
		}
	}()
	comp, err := l.compiler(ctx)
	declared := false
	for i, f := range files {
		if !hasCReferences([]*ast.File{f}) {
			continue
		}
		fileName := l.cfg.Fset.File(f.Pos()).Name()
		if err != nil {
			pkg.addErrorAt(token.Position{Filename: fileName}, fmt.Sprintf("package %s: %v", p.PkgPath, err))
			continue
		}
		cf, rerr := l.readPreamble(ctx, comp, pkg, f, i, dir)
		if rerr != nil {
			pkg.addErrorAt(token.Position{Filename: fileName}, rerr.Error())
			continue
		}
		if !declared {
			pkg.generated.Decls = append(pkg.generated.Decls, pkg.builtinTypeDecl())
			declared = true
		}
		astutil.Apply(f, func(c *astutil.Cursor) bool { return cf.walker(c, cf.names) }, nil)
	}
	pkg.unusedNoescapeErrors()
	if !declared {
		return nil
	}
	return pkg.generated
}

// positionString is a position as go/packages writes one, the file alone when
// there is no line.
func positionString(pos token.Position) string {
	if pos.Line == 0 {
		if pos.Filename == "" {
			return "-"
		}
		return pos.Filename
	}
	return pos.String()
}

// compiler finds clang and reads the target's flags, once per load. The chosen
// binary and its version go to the step log.
func (l *loader) compiler(ctx context.Context) (*compiler, error) {
	if l.comp != nil || l.compErr != nil {
		return l.comp, l.compErr
	}
	path, err := FindCompiler(envPath(l.cfg.Env))
	if err != nil {
		l.compErr = err
		return nil, err
	}
	spec, err := LoadTarget(l.cfg.SourceRoot, l.cfg.Target)
	if err != nil {
		l.compErr = err
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "kanonarion-cg-cgo-*")
	if err != nil {
		l.compErr = fmt.Errorf("creating a directory for the preambles: %w", err)
		return nil, l.compErr
	}
	l.tmp = tmp
	l.comp = &compiler{path: path, env: l.cfg.Env, flags: cFlags(spec, l.cfg.SourceRoot, l.cfg.Triple, l.cfg.GOARCH)}
	l.step(fmt.Sprintf("C compiler %s (%s)", path, l.comp.version(ctx)))
	return l.comp, nil
}

// readPreamble compiles one file's preamble for its declarations and macros
// and returns the file's cgo state, ready to walk.
func (l *loader) readPreamble(ctx context.Context, comp *compiler, pkg *cgoPackage, f *ast.File, index int, dir string) (*cgoFile, error) {
	l.nfiles++
	src := filepath.Join(l.tmp, strconv.Itoa(l.nfiles)+"-"+filepath.Base(l.cfg.Fset.File(f.Pos()).Name())+"!cgo.c")
	if err := os.WriteFile(src, []byte(pkg.cgoHeaders[index]), 0o600); err != nil {
		return nil, fmt.Errorf("writing the preamble: %w", err)
	}
	pre := []string{"-ffreestanding", "-I" + dir}
	astOut, err := comp.run(ctx, append(pre, "-fsyntax-only", "-Xclang", "-ast-dump=json", src)...)
	if err != nil {
		return nil, fmt.Errorf("clang rejected the preamble: %w", err)
	}
	macroOut, err := comp.run(ctx, append(pre, "-dM", "-E", src)...)
	if err != nil {
		return nil, fmt.Errorf("clang rejected the preamble: %w", err)
	}
	decls, names, err := parseTranslationUnit(astOut)
	if err != nil {
		return nil, err
	}
	decls.macros = parseMacros(macroOut)
	for name, m := range decls.macros {
		names[name] = cursor{macro: m}
	}
	if pkg.sizes == (cSizes{}) {
		if pkg.sizes, err = readSizes(decls.macros); err != nil {
			return nil, err
		}
	}
	cf := pkg.newCGoFile(f, index)
	cf.decls = decls
	cf.names = names
	for _, name := range builtinAliases {
		delete(cf.names, name)
	}
	cf.names["float"], cf.names["double"], cf.names["_Bool"] = cursor{}, cursor{}, cursor{}
	cf.enumProbe = func(spellings []string) ([]int, []bool, error) {
		probe := src + ".enums.c"
		if err := os.WriteFile(probe, []byte(pkg.cgoHeaders[index]+enumProbeSource(spellings)), 0o600); err != nil {
			return nil, nil, fmt.Errorf("writing the enum probe: %w", err)
		}
		out, err := comp.run(ctx, append(pre, "-fsyntax-only", "-Xclang", "-ast-dump=json", probe)...)
		if err != nil {
			return nil, nil, err
		}
		return readEnumProbe(out, len(spellings))
	}
	return cf, nil
}
