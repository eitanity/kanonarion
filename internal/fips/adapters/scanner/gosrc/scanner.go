// Package gosrc implements ports.FIPSScanner by reading a project's
// go.mod toolchain directive and walking its source tree for FIPS-relevant
// import paths. It is pure parsing: it produces raw findings with file/line
// provenance and the cgo flag, but performs no policy evaluation (that is
// the application's concern, per).
//
// Scope: toolchain string from go.mod, non-FIPS algorithm imports
// (catalogue-driven), direct crypto/rand usage, and cgo crypto dependencies
// (heuristic — a Go source under a dependency that imports "C").
// Binary-authoritative FIPS-mode detection from runtime/debug.BuildInfo is
// intentionally out of scope for this source-only scanner.
package gosrc

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/fips/domain"
	"golang.org/x/mod/modfile"
)

// Scanner implements ports.FIPSScanner.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// ScanProject reads goModPath for the project module path and toolchain
// directive, then walks the directory tree collecting FIPS-relevant import
// findings from every `.go` / `.go.txt` source file.
func (s *Scanner) ScanProject(goModPath string) (domain.ParseResult, error) {
	data, err := os.ReadFile(filepath.Clean(goModPath))
	if err != nil {
		return domain.ParseResult{}, fmt.Errorf("reading go.mod %q: %w", goModPath, err)
	}
	mf, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return domain.ParseResult{}, fmt.Errorf("parsing go.mod %q: %w", goModPath, err)
	}
	modPath := ""
	if mf.Module != nil {
		modPath = mf.Module.Mod.Path
	}

	root := filepath.Dir(goModPath)
	// Toolchain detection. Variant strings ("X:boringcrypto",
	// "X:fipscapable") only appear in runtime/debug.BuildInfo.GoVersion,
	// not in go.mod. A source-only scanner cannot bind a built binary, so
	// the scanner optionally reads a `buildinfo.txt` sidecar with a
	// `GoVersion: …` line (the same shape Go's `go version -m` emits).
	// For projects in the wild, the user generates the sidecar from their
	// build output and commits it.
	// Falling back to go.mod's go/toolchain directive when no sidecar is
	// present is honest: it is the only signal we have, and stock Go
	// never carries a FIPS variant string so the assessment cleanly
	// reads "not capable" rather than fabricating a verdict.
	toolchain := readBuildInfoGoVersion(filepath.Join(root, "buildinfo.txt"))
	if toolchain == "" {
		if mf.Toolchain != nil {
			toolchain = mf.Toolchain.Name
		} else if mf.Go != nil {
			toolchain = "go" + mf.Go.Version
		}
	}

	// Native FIPS 140-3 facts: the `go` directive version gates availability
	// of the Go Cryptographic Module; the `//go:debug fips140=…` directive is
	// the declarative, source-visible request to enable it. The domain
	// combines the two — the scanner only surfaces the raw values.
	goVersion := ""
	if mf.Go != nil {
		goVersion = mf.Go.Version
	}
	fips140 := ""
	for _, gd := range mf.Godebug {
		if gd.Key == "fips140" {
			fips140 = gd.Value
		}
	}

	var findings []domain.Finding

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

		fileFindings, ferr := scanFile(path, rel, modPath)
		if ferr != nil {
			return ferr
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if walkErr != nil {
		return domain.ParseResult{}, fmt.Errorf("walking source tree %q: %w", root, walkErr)
	}

	return domain.ParseResult{
		ProjectModulePath: modPath,
		ToolchainRaw:      toolchain,
		GoVersion:         goVersion,
		FIPS140:           fips140,
		Findings:          findings,
	}, nil
}

// readBuildInfoGoVersion parses the first `GoVersion: …` line out of a
// `go version -m`-style sidecar. Returns "" when the file is absent or the
// header is missing — both are honest signals that the scanner record will
// carry, never silently substituted.
func readBuildInfoGoVersion(path string) string {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // sidecar path is derived from the scan root
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "GoVersion:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// skipDir mirrors the godebug scanner's rules: nested modules (own go.mod),
// testdata, and dot/underscore directories are not build inputs. vendor/ is
// deliberately not skipped — vendored deps are part of the closure we want
// to assess.
func skipDir(path, name string) bool {
	if name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return true
	}
	if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
		return true
	}
	return false
}

// isGoSource reports whether name is a Go source file the scanner reads.
// The corpus stores fixture sources as `.go.txt` to avoid pre-commit
// typechecking nested fixtures (see test/fixtures/supplychain/README.md).
func isGoSource(name string) bool {
	return strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".go.txt")
}

// vendorModule maps a vendored path under vendor/ to its module path
// (first two segments, matching Go's domain/owner layout). Returns the
// project module path for non-vendored files.
func vendorModule(rel, projectModule string) string {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		if p != "vendor" {
			continue
		}
		rest := parts[i+1:]
		switch {
		case len(rest) >= 2:
			return strings.Join(rest[:2], "/")
		case len(rest) == 1:
			return rest[0]
		default:
			return ""
		}
	}
	return projectModule
}

// scanFile parses imports from a single Go source file, emitting findings
// for non-FIPS algorithm imports, direct crypto/rand imports, and a single
// cgo-crypto finding when the file imports `"C"` from under a dependency
// that also imports a non-FIPS algorithm (heuristic: cgo + crypto-shaped
// dep). The `.go.txt` fixture extension is handled by deferring to a
// permissive parser pass — go/parser accepts any byte source.
func scanFile(path, rel, projectModule string) ([]domain.Finding, error) {
	fset := token.NewFileSet()
	// Parse imports only — keep parser cost down on large vendor trees.
	src, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // walked from a known root
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	file, err := parser.ParseFile(fset, path, src, parser.ImportsOnly)
	if err != nil {
		// A `.go.txt` fixture may not be a valid compilation unit. Fall
		// back to a line scanner; this never crashes on un-parseable
		// fixture-style content.
		return scanImportsViaLine(path, rel, projectModule, src)
	}

	mod := vendorModule(rel, projectModule)
	var findings []domain.Finding
	var hasCgo bool
	var hasCryptoShapedImport bool
	for _, imp := range file.Imports {
		raw := strings.Trim(imp.Path.Value, `"`)
		line := fset.Position(imp.Pos()).Line
		findings = appendFindingForImport(findings, raw, rel, line, mod)
		if raw == "C" {
			hasCgo = true
		}
		if strings.Contains(raw, "crypto") || strings.Contains(raw, "ssl") {
			hasCryptoShapedImport = true
		}
	}
	if hasCgo && (hasCryptoShapedImport || isCryptoShapedModule(mod)) && isUnderVendor(rel) {
		findings = append(findings, domain.Finding{
			Kind:   domain.FindingCgoCrypto,
			Module: mod,
			Source: rel,
			Line:   1,
		})
	}
	return findings, nil
}

// scanImportsViaLine handles `.go.txt` fixtures that go/parser would
// reject. It is a bufio.Scanner over `import "…"` and `_ "…"` lines —
// sufficient because we only ever read import paths.
func scanImportsViaLine(_, rel, projectModule string, src []byte) ([]domain.Finding, error) {
	mod := vendorModule(rel, projectModule)
	var findings []domain.Finding
	var hasCgo, hasCryptoShape bool
	sc := bufio.NewScanner(strings.NewReader(string(src)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		raw, ok := extractImportLine(l)
		if !ok {
			continue
		}
		findings = appendFindingForImport(findings, raw, rel, line, mod)
		if raw == "C" {
			hasCgo = true
		}
		if strings.Contains(raw, "crypto") || strings.Contains(raw, "ssl") {
			hasCryptoShape = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanning %q: %w", rel, err)
	}
	if hasCgo && (hasCryptoShape || isCryptoShapedModule(mod)) && isUnderVendor(rel) {
		findings = append(findings, domain.Finding{
			Kind: domain.FindingCgoCrypto, Module: mod, Source: rel, Line: 1,
		})
	}
	return findings, nil
}

// extractImportLine returns the quoted import path from one of:
//
//	import "path"
//	import _ "path"
//	import name "path"
//	"path" (inside a block)
//	_ "path"
//
// The grammar is conservative: an unrecognised line returns "", false.
func extractImportLine(l string) (string, bool) {
	l = strings.TrimPrefix(l, "import ")
	l = strings.TrimSpace(l)
	// Drop a leading alias / blank identifier.
	if strings.HasPrefix(l, "_") {
		l = strings.TrimSpace(strings.TrimPrefix(l, "_"))
	}
	// "name" preceding the path — skip a single Go ident.
	if !strings.HasPrefix(l, `"`) && len(l) > 0 {
		// strip ident up to first space
		sp := strings.IndexByte(l, ' ')
		if sp <= 0 {
			return "", false
		}
		l = strings.TrimSpace(l[sp:])
	}
	if !strings.HasPrefix(l, `"`) {
		return "", false
	}
	end := strings.IndexByte(l[1:], '"')
	if end <= 0 {
		return "", false
	}
	return l[1 : 1+end], true
}

// appendFindingForImport classifies one import path and appends a finding
// if it is FIPS-relevant. crypto/rand becomes a "direct random" surface
// fact; a path on the catalogue becomes a non-FIPS algorithm finding.
func appendFindingForImport(findings []domain.Finding, importPath, rel string, line int, mod string) []domain.Finding {
	switch {
	case importPath == "crypto/rand":
		return append(findings, domain.Finding{
			Kind: domain.FindingDirectRandom, Package: importPath,
			Module: mod, Source: rel, Line: line,
		})
	case domain.IsNonFIPSAlgorithmPackage(importPath):
		return append(findings, domain.Finding{
			Kind: domain.FindingAlgorithm, Package: importPath,
			Module: mod, Source: rel, Line: line,
		})
	}
	return findings
}

// isCryptoShapedModule reports whether a module path is shaped like a
// crypto library binding (contains "ssl", "crypto", "boring", or "fips").
// The cgo-crypto heuristic uses it so a vendored cgo binding under
// e.g. github.com/openssl/openssl-go is flagged even when its Go file
// imports only "C" with no Go-side crypto import.
func isCryptoShapedModule(mod string) bool {
	low := strings.ToLower(mod)
	return strings.Contains(low, "ssl") ||
		strings.Contains(low, "crypto") ||
		strings.Contains(low, "boring") ||
		strings.Contains(low, "fips")
}

// isUnderVendor reports whether the slash-path lies under a vendor/
// segment. The cgo-crypto heuristic deliberately scopes itself to vendored
// deps — `import "C"` in the project's own code is out of scope for this
// scanner and belongs to a separate cgo-usage analysis.
func isUnderVendor(rel string) bool {
	for _, p := range strings.Split(rel, "/") {
		if p == "vendor" {
			return true
		}
	}
	return false
}
