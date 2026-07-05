// Package builder implements ports.SymbolTableProber. It builds a probe binary
// from a local Go workspace with inlining disabled (-gcflags='all=-l') and
// reads the binary's symbol table via go tool nm.
//
// For binary targets (package main), the workspace binary is built directly.
// For library targets, a synthetic main package is generated inside the
// workspace under a _kanonarion_probe directory (excluded from./...) that
// takes references to all exported functions, preventing dead-code elimination.
package builder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/local/ports"
)

const probeHarnessDir = "_kanonarion_probe"

// Prober implements ports.SymbolTableProber.
type Prober struct {
	goBinary string
}

// New constructs a Prober. goBinary may be empty (uses "go" from PATH).
func New(goBinary string) *Prober { return &Prober{goBinary: goBinary} }

func (p *Prober) goBin() string {
	if p.goBinary == "" {
		return "go"
	}
	return p.goBinary
}

// Probe builds a probe binary from the workspace at root with inlining
// disabled and returns its symbol table.
func (p *Prober) Probe(ctx context.Context, root string) (ports.SymbolProbeResult, error) {
	mainPkgs, err := findMainPackages(ctx, root, p.goBin())
	if err != nil {
		return ports.SymbolProbeResult{}, fmt.Errorf("detecting workspace kind: %w", err)
	}

	tmpBin := filepath.Join(os.TempDir(), "kanonarion_probe_bin")

	var kind string
	var cleanup func()

	if len(mainPkgs) > 0 {
		kind = "binary"
		cleanup = func() { _ = os.Remove(tmpBin) }
		if err := buildBinary(ctx, root, mainPkgs[0], tmpBin, p.goBin()); err != nil {
			return ports.SymbolProbeResult{}, fmt.Errorf("building probe binary: %w", err)
		}
	} else {
		kind = "library"
		harnessDir := filepath.Join(root, probeHarnessDir)
		cleanup = func() {
			_ = os.RemoveAll(harnessDir)
			_ = os.Remove(tmpBin)
		}
		if err := buildLibraryProbe(ctx, root, harnessDir, tmpBin, p.goBin()); err != nil {
			_ = os.RemoveAll(harnessDir)
			return ports.SymbolProbeResult{}, fmt.Errorf("building library probe: %w", err)
		}
	}
	defer cleanup()

	symbols, err := readSymbolTable(ctx, root, tmpBin, p.goBin())
	if err != nil {
		return ports.SymbolProbeResult{}, fmt.Errorf("reading symbol table: %w", err)
	}

	return ports.SymbolProbeResult{BinarySymbols: symbols, Kind: kind}, nil
}

// goListPackage mirrors the fields we need from `go list -json`.
type goListPackage struct {
	ImportPath string
	Name       string
	Dir        string
	GoFiles    []string
}

// findMainPackages runs go list -json./... and returns the import paths of
// packages whose Name == "main".
func findMainPackages(ctx context.Context, root, goBin string) ([]string, error) {
	cmd := exec.CommandContext(ctx, goBin, "list", "-json", "./...") // #nosec G204
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("go list: %w\n%s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("go list: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var mains []string
	for {
		var pkg goListPackage
		if err := dec.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		if pkg.Name == "main" {
			mains = append(mains, pkg.ImportPath)
		}
	}
	return mains, nil
}

// buildBinary builds mainPkg into outBin with inlining disabled.
func buildBinary(ctx context.Context, root, mainPkg, outBin, goBin string) error {
	cmd := exec.CommandContext(ctx, goBin, "build", // #nosec G204
		"-gcflags=all=-l",
		"-o", outBin,
		mainPkg,
	)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// buildLibraryProbe generates a synthetic harness inside harnessDir and
// builds it into outBin with inlining disabled.
func buildLibraryProbe(ctx context.Context, root, harnessDir, outBin, goBin string) error {
	if err := os.MkdirAll(harnessDir, 0o700); err != nil {
		return fmt.Errorf("creating harness dir: %w", err)
	}

	// Enumerate all workspace packages.
	pkgs, err := listWorkspacePackages(ctx, root, goBin)
	if err != nil {
		return fmt.Errorf("listing workspace packages: %w", err)
	}

	// Parse exported functions from.go source files in each package.
	exports, err := enumerateExportedFuncs(pkgs)
	if err != nil {
		return fmt.Errorf("enumerating exported functions: %w", err)
	}

	// Write synthetic harness.
	code := generateHarness(pkgs, exports)
	mainPath := filepath.Join(harnessDir, "main.go")
	if err := os.WriteFile(mainPath, []byte(code), 0o600); err != nil {
		return fmt.Errorf("writing harness: %w", err)
	}

	// Build the harness.
	cmd := exec.CommandContext(ctx, goBin, "build", // #nosec G204
		"-gcflags=all=-l",
		"-o", outBin,
		"./"+probeHarnessDir,
	)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building harness: %w\n%s", err, out)
	}
	return nil
}

func listWorkspacePackages(ctx context.Context, root, goBin string) ([]goListPackage, error) {
	cmd := exec.CommandContext(ctx, goBin, "list", "-json", "./...") // #nosec G204
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("go list: %w\n%s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("go list: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	var pkgs []goListPackage
	for {
		var pkg goListPackage
		if err := dec.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parsing go list output: %w", err)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

// exportedFunc records one exported function or method reference for the harness.
type exportedFunc struct {
	receiver string // empty for top-level funcs; "*Type" or "Type" for methods
	name     string
}

// enumerateExportedFuncs parses the.go files in each package and collects
// exported function and method declarations.
func enumerateExportedFuncs(pkgs []goListPackage) (map[string][]exportedFunc, error) {
	// map: package import path → exported funcs
	result := make(map[string][]exportedFunc)
	fset := token.NewFileSet()

	for _, pkg := range pkgs {
		for _, goFile := range pkg.GoFiles {
			if strings.HasSuffix(goFile, "_test.go") {
				continue
			}
			fullPath := filepath.Join(pkg.Dir, goFile)
			f, err := parser.ParseFile(fset, fullPath, nil, 0)
			if err != nil {
				continue // skip unparseable files
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || !ast.IsExported(fd.Name.Name) {
					continue
				}
				ef := exportedFunc{name: fd.Name.Name}
				if fd.Recv != nil && len(fd.Recv.List) > 0 {
					ef.receiver = receiverTypeName(fd.Recv.List[0].Type)
					if ef.receiver == "" || !ast.IsExported(strings.TrimPrefix(ef.receiver, "*")) {
						continue // skip methods on unexported types
					}
				}
				result[pkg.ImportPath] = append(result[pkg.ImportPath], ef)
			}
		}
	}
	return result, nil
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return "*" + id.Name
		}
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic with one type param
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name // skip instantiation
		}
	case *ast.IndexListExpr: // generic with multiple type params
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

// generateHarness produces Go source code for the synthetic probe harness.
// It imports every workspace package and assigns exported function/method
// expressions to interface{} variables, preventing dead-code elimination.
func generateHarness(pkgs []goListPackage, exports map[string][]exportedFunc) string {
	// Assign deterministic aliases to avoid name collisions.
	type pkgEntry struct {
		importPath string
		alias      string
	}

	// Sort for determinism.
	sorted := make([]goListPackage, len(pkgs))
	copy(sorted, pkgs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ImportPath < sorted[j].ImportPath })

	entries := make([]pkgEntry, 0, len(sorted))
	aliasMap := make(map[string]string)
	for i, pkg := range sorted {
		alias := fmt.Sprintf("p%d", i)
		aliasMap[pkg.ImportPath] = alias
		entries = append(entries, pkgEntry{importPath: pkg.ImportPath, alias: alias})
	}

	var sb strings.Builder
	sb.WriteString("package main\n\nimport (\n")
	for _, e := range entries {
		if _, hasExports := exports[e.importPath]; !hasExports {
			continue
		}
		fmt.Fprintf(&sb, "\t%s %q\n", e.alias, e.importPath)
	}
	sb.WriteString(")\n\nvar _sinks []interface{}\n\nfunc init() {\n")

	for _, e := range entries {
		funcs, ok := exports[e.importPath]
		if !ok {
			continue
		}
		for _, ef := range funcs {
			var ref string
			switch {
			case ef.receiver == "":
				ref = fmt.Sprintf("%s.%s", e.alias, ef.name)
			case strings.HasPrefix(ef.receiver, "*"):
				// Method expression for a pointer receiver is
				// (*pkg.Type).Method, not (pkg.*Type).Method.
				ref = fmt.Sprintf("(*%s.%s).%s", e.alias, strings.TrimPrefix(ef.receiver, "*"), ef.name)
			default:
				ref = fmt.Sprintf("(%s.%s).%s", e.alias, ef.receiver, ef.name)
			}
			fmt.Fprintf(&sb, "\t_sinks = append(_sinks, %s)\n", ref)
		}
	}
	sb.WriteString("}\n\nfunc main() { _ = _sinks }\n")
	return sb.String()
}

// readSymbolTable runs go tool nm on binPath and returns the set of symbol names.
func readSymbolTable(ctx context.Context, root, binPath, goBin string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, goBin, "tool", "nm", binPath) // #nosec G204
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("go tool nm: %w\n%s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("go tool nm: %w", err)
	}

	symbols := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		symbols[fields[2]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning nm output: %w", err)
	}
	return symbols, nil
}

// Ensure Prober implements ports.SymbolTableProber at compile time.
var _ ports.SymbolTableProber = (*Prober)(nil)
