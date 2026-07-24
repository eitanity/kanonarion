package govulncheck

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// toolchainGoVersion reports the host toolchain's version in `go env GOVERSION`
// form, for the go directive of a synthesised go.mod.
//
// The module being scanned declared no language version — it predates the
// directive — so the host toolchain's own version is the only defensible
// choice: it is the version that will compile the module either way. An empty
// return means the toolchain could not be queried, and the caller omits the
// directive rather than inventing a version, since a wrong one silently changes
// which files build constraints select.
func toolchainGoVersion(ctx context.Context, env []string) string {
	cmd := exec.CommandContext(ctx, "go", "env", "GOVERSION")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// writeSynthesisedGoMod gives a module zip published before Go modules the
// go.mod govulncheck requires, so it can be analysed from source instead of
// being abandoned as unscannable.
//
// The file is written to the module root inside the scan's scratch directory —
// never to the module cache, never persisted, and never part of any artefact
// kanonarion records. An existing go.mod is never overwritten: this path runs
// only when none was found, and refusing to clobber keeps that guarantee local
// and checkable rather than relying on the caller.
// It returns the module root it wrote to, which becomes the scan directory:
// the extraction root is a prefix above the module's own source, and pointing
// govulncheck at that prefix would analyse no packages. It also returns any
// source file whose imports could not be read, so the caller can report a
// require set that was assembled from less than the whole module.
func writeSynthesisedGoMod(extractRoot string, coord coordinate.ModuleCoordinate, goVersion string, buildList map[coordinate.ModuleCoordinate]struct{}) (root string, skipped []string, err error) {
	root, err = moduleRoot(extractRoot)
	if err != nil {
		return "", nil, err
	}
	target := filepath.Join(root, "go.mod")
	if _, statErr := os.Stat(target); statErr == nil {
		return "", nil, fmt.Errorf("go.mod already exists at %s", target)
	}
	imports, skipped := collectImports(root)
	content := domain.SynthesiseGoMod(coord, goVersion, imports, buildList)
	if err := os.WriteFile(target, []byte(content), 0600); err != nil {
		return "", skipped, fmt.Errorf("write synthesised go.mod: %w", err)
	}
	return root, skipped, nil
}

// moduleRoot finds the directory holding the module's own source inside an
// extracted zip.
//
// A module zip nests its content under a "path@version/" prefix, so the
// extraction root is not the module root and a go.mod written there would
// describe the wrong directory. Descend through single-child directories until
// reaching one that holds Go source or branches, which is the prefix's end.
// The descent is bounded by the directory structure itself and stops at the
// first directory that could plausibly be a module root.
func moduleRoot(extractRoot string) (string, error) {
	dir := extractRoot
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", fmt.Errorf("read extracted module dir: %w", err)
		}
		var subdirs []string
		for _, e := range entries {
			if e.IsDir() {
				subdirs = append(subdirs, e.Name())
				continue
			}
			// Any Go source at this level means the module root is here: the
			// prefix directories of a module zip contain only directories.
			if filepath.Ext(e.Name()) == ".go" {
				return dir, nil
			}
		}
		if len(subdirs) != 1 {
			// Zero subdirectories means nothing was extracted; more than one
			// means this level already branches, so it is the module root.
			return dir, nil
		}
		dir = filepath.Join(dir, subdirs[0])
	}
}

// collectImports returns every package path the module's own source imports,
// deduplicated. It is the input to the require set of a synthesised go.mod.
//
// Test files are skipped: govulncheck's source scan does not load them by
// default, so their imports would add requirements the analysed build never
// needs — a test-only helper absent from the project's build list would
// otherwise fail a module whose real packages resolve perfectly well.
//
// Standard-library imports are dropped here rather than in the domain: they are
// recognised by the absence of a dot in the first path element, which is a fact
// about how the toolchain resolves paths, not about the build list.
//
// A file that cannot be read or parsed contributes nothing rather than failing
// the scan — one bad file must not cost the whole module its source analysis —
// but it is returned as the second value rather than dropped. The caller reports
// it, so a require missing because a file was skipped is attributable to that
// file instead of surfacing later as an unexplained unresolved package.
func collectImports(root string) (imports, skipped []string) {
	seen := make(map[string]struct{})
	fset := token.NewFileSet()
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			skipped = append(skipped, path)
			return nil //nolint:nilerr // recorded in skipped and reported by the caller; an unreadable entry must not fail the scan
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			skipped = append(skipped, path)
			return nil //nolint:nilerr // recorded in skipped and reported by the caller; one unparseable file must not fail the scan
		}
		paths, unreadable := importPathsFromFile(f)
		for _, p := range paths {
			seen[p] = struct{}{}
		}
		if len(unreadable) > 0 {
			skipped = append(skipped, path)
		}
		return nil
	})
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	sort.Strings(skipped)
	return out, skipped
}

// importPathsFromFile returns the non-stdlib import paths declared in f, and
// separately any import literal that could not be unquoted.
//
// A file the parser accepted has valid string literals, so unreadable is
// normally empty and this branch is defensive. It is returned rather than
// dropped because the consequence is identical to an unparseable file: a
// requirement missing from the synthesised go.mod, surfacing much later as an
// unresolved package with nothing connecting it back to the file that caused it.
//
// Standard-library imports are dropped here rather than in the domain: they are
// recognised by the absence of a dot in the first path element, which is a fact
// about how the toolchain resolves paths, not about the build list.
func importPathsFromFile(f *ast.File) (paths, unreadable []string) {
	for _, spec := range f.Imports {
		p, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil {
			unreadable = append(unreadable, spec.Path.Value)
			continue
		}
		first, _, _ := strings.Cut(p, "/")
		if !strings.Contains(first, ".") {
			continue // standard library
		}
		paths = append(paths, p)
	}
	return paths, unreadable
}
