// Package gosrc implements ports.GoDebugScanner by scanning a project's Go
// source tree for `//go:debug name=value` directives. It is pure parsing: it
// produces raw settings with file/line provenance and the applied flag, but
// performs no risk classification or policy evaluation (those are the domain
// and config concerns respectively, per).
//
// `//go:debug` only takes effect in the main package of the *main* module
// (Go 1.21+). The scanner therefore records a directive as Applied only when
// it sits in a `package main` file of the scanned module itself; a directive
// found under a vendored dependency tree is recorded Applied=false — it is a
// fact about a dependency, not the current build, and forbids
// silently dropping it.
package gosrc

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/godebug/ports"
	vendordomain "github.com/eitanity/kanonarion/internal/vendortree/domain"
	"golang.org/x/mod/modfile"
)

// Scanner implements ports.GoDebugScanner.
type Scanner struct {
	vendored ports.VendoredModuleLister
}

// New returns a Scanner that attributes vendored files to their module through
// vendored. A nil lister is legitimate but lossy: nothing then states which
// module owns a directory under vendor/, so every vendored directive reports
// vendordomain.ModuleUnresolved rather than a path prefix dressed up as a
// module. The applied flag does not depend on it — a directive under vendor/
// does not affect the current build whether or not its module can be named.
func New(vendored ports.VendoredModuleLister) *Scanner { return &Scanner{vendored: vendored} }

// goDebugLine matches a `//go:debug` compiler directive. The directive may
// carry a comma-separated list of settings: `//go:debug name=v,name2=v2`.
var goDebugLine = regexp.MustCompile(`^//go:debug\s+(.+)$`)

// packageClause captures the package name from a `package <name>` line.
var packageClause = regexp.MustCompile(`^package\s+(\w+)`)

// ScanProject reads goModPath for the module path then walks its directory
// tree collecting `//go:debug` settings from every `package main` source
// file (`.go` and the corpus's `.go.txt` test sources alike). A directive under
// vendor/ is attributed to the module vendor/modules.txt says owns it.
func (s *Scanner) ScanProject(ctx context.Context, goModPath string) (domain.ParseResult, error) {
	data, err := os.ReadFile(filepath.Clean(goModPath))
	if err != nil {
		return domain.ParseResult{}, fmt.Errorf("reading go.mod %q: %w", goModPath, err)
	}
	modPath := modfile.ModulePath(data)

	root := filepath.Dir(goModPath)

	// modules.txt is the authoritative mapping from a directory under vendor/
	// to a module path, and it is read by the vendor context's one parser of
	// that file rather than by a second one here.
	var vendoredPaths []string
	if s.vendored != nil {
		var lerr error
		vendoredPaths, lerr = s.vendored.VendoredModulePaths(ctx, goModPath)
		if lerr != nil {
			return domain.ParseResult{}, fmt.Errorf("listing vendored modules for %q: %w", goModPath, lerr)
		}
	}
	index := vendordomain.NewVendoredModuleIndex(vendoredPaths)

	var settings []domain.Setting

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDir(path, d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !isGoSource(d.Name()) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		found, ferr := scanFile(path)
		if ferr != nil {
			return ferr
		}
		if len(found) == 0 {
			return nil
		}

		vendored, depMod := index.Vendored(rel)
		mod := modPath
		applied := !vendored
		if vendored {
			mod = depMod
		}
		for _, fs := range found {
			settings = append(settings, domain.Setting{
				Name:    fs.name,
				Value:   fs.value,
				Source:  rel,
				Line:    fs.line,
				Module:  mod,
				Applied: applied,
			})
		}
		return nil
	})
	if walkErr != nil {
		return domain.ParseResult{}, fmt.Errorf("walking source tree %q: %w", root, walkErr)
	}

	return domain.ParseResult{ProjectModulePath: modPath, Settings: settings}, nil
}

// skipDir reports whether a sub-directory must not be descended into,
// mirroring `go build` package selection so a project scan sees exactly what
// the toolchain compiles:
//
// - a directory carrying its own go.mod is a *separate module* — `go build
// ./...` never crosses that boundary, so neither do we (this is what
// keeps a scan of the kanonarion repo from flagging its own nested
// test-corpus modules);
// - `testdata`, and directories beginning with `.` or `_`, are ignored by
// the Go toolchain and are not build inputs.
//
// `vendor/` is deliberately *not* skipped: a vendored dependency's
// `//go:debug` is a recorded (not-applied) fact, not a separate module to
// exclude.
func skipDir(path, name string) bool {
	if name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return true
	}
	if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
		return true
	}
	return false
}

// isGoSource reports whether name is a Go source file the scanner reads. The
// corpus stores fixture sources as `.go.txt` (the pre-commit linter would
// otherwise typecheck them against the main module); detection is on text, so
// the extension does not matter — see test/fixtures/supplychain/README.md.
func isGoSource(name string) bool {
	return strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".go.txt")
}

type foundSetting struct {
	name  string
	value string
	line  int
}

// scanFile returns the `//go:debug` settings in a `package main` source file.
// A file whose package is not main is skipped: `//go:debug` is only valid
// there, so a non-main occurrence is dead text the Go toolchain itself
// rejects — recording it would be noise, not a missed fact.
func scanFile(path string) ([]foundSetting, error) {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // corpus + project sources, walked from a known root
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var (
		pending []foundSetting
		isMain  bool
		lineNo  int
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if m := goDebugLine.FindStringSubmatch(line); m != nil {
			pending = append(pending, parseSettings(m[1], lineNo)...)
			continue
		}
		if m := packageClause.FindStringSubmatch(line); m != nil {
			isMain = m[1] == "main"
			break // package clause ends the directive-bearing prologue
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	if !isMain {
		return nil, nil
	}
	return pending, nil
}

// parseSettings splits a `//go:debug` body into its name=value settings. The
// directive permits a comma-separated list; a malformed fragment (no `=`) is
// skipped rather than guessed at.
func parseSettings(body string, line int) []foundSetting {
	var out []foundSetting
	for frag := range strings.SplitSeq(body, ",") {
		frag = strings.TrimSpace(frag)
		k, v, ok := strings.Cut(frag, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		out = append(out, foundSetting{name: k, value: strings.TrimSpace(v), line: line})
	}
	return out
}
