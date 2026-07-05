// Package localfs implements ports.VendorScanner against the local
// filesystem. It is pure scanning: it parses vendor/modules.txt, the main
// go.mod require set and go.sum, enumerates the module directories present
// under vendor/, and recomputes each vendored module's tree hash using the
// canonical dirhash algorithm. It performs no reconciliation or policy (those
// are the domain and config concerns respectively, per) and never
// contacts the proxy — the closure is resolved entirely from modules.txt, so
// an airgapped scan completes with no network.
package localfs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/sumdb/dirhash"
)

// Scanner implements ports.VendorScanner.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// ScanProject reads the vendored project rooted at goModPath. It returns
// ports.ErrNotVendored when there is no vendor/modules.txt — the closure
// cannot be resolved from the vendored tree, which the caller handles per the
// requested mode.
func (s *Scanner) ScanProject(goModPath string, vendorOnly bool) (domain.ParseResult, error) {
	root := filepath.Dir(goModPath)
	vendorDir := filepath.Join(root, "vendor")
	modulesTxtPath := filepath.Join(vendorDir, "modules.txt")

	if _, err := os.Stat(modulesTxtPath); err != nil {
		return domain.ParseResult{}, ports.ErrNotVendored
	}

	gomodData, err := os.ReadFile(filepath.Clean(goModPath))
	if err != nil {
		return domain.ParseResult{}, fmt.Errorf("reading go.mod %q: %w", goModPath, err)
	}
	projectPath := modfile.ModulePath(gomodData)
	requires, err := parseRequires(goModPath, gomodData)
	if err != nil {
		return domain.ParseResult{}, err
	}

	modules, err := parseModulesTxt(modulesTxtPath)
	if err != nil {
		return domain.ParseResult{}, err
	}

	goSum, err := parseGoSum(filepath.Join(root, "go.sum"))
	if err != nil {
		return domain.ParseResult{}, err
	}

	present := map[string]bool{}
	computed := map[string]string{}
	for _, m := range modules {
		dir := filepath.Join(vendorDir, filepath.FromSlash(m.Path))
		if !dirHasFiles(dir) {
			continue
		}
		present[m.Path] = true
		h, herr := dirhash.HashDir(dir, m.Path+"@"+m.Version, dirhash.Hash1)
		if herr != nil {
			return domain.ParseResult{}, fmt.Errorf("hashing vendored module %q: %w", m.Path, herr)
		}
		computed[m.Path] = h
	}
	// Also surface module directories present under vendor/ that
	// modules.txt never lists, so the domain can flag extra-in-vendor.
	for _, p := range extraVendoredModules(vendorDir, modules) {
		present[p] = true
	}

	return domain.ParseResult{
		ProjectModulePath: projectPath,
		VendorDir:         "vendor",
		VendorOnly:        vendorOnly,
		ModulesTxt:        modules,
		GoModRequires:     requires,
		GoSum:             goSum,
		PresentDirs:       present,
		ComputedHashes:    computed,
	}, nil
}

// parseRequires returns the main module's require set (path → version).
func parseRequires(name string, data []byte) (map[string]string, error) {
	f, err := modfile.Parse(name, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod %q: %w", name, err)
	}
	out := make(map[string]string, len(f.Require))
	for _, r := range f.Require {
		out[r.Mod.Path] = r.Mod.Version
	}
	return out, nil
}

// parseModulesTxt parses vendor/modules.txt. Module entries are `# path
// version` lines; an immediately-following `## explicit` marks a direct
// dependency. Package lines and replacement targets are not module entries.
func parseModulesTxt(path string) ([]domain.VendoredModule, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var mods []domain.VendoredModule
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "## "):
			if len(mods) > 0 && strings.Contains(line, "explicit") {
				mods[len(mods)-1].Explicit = true
			}
		case strings.HasPrefix(line, "# "):
			fields := strings.Fields(strings.TrimPrefix(line, "# "))
			if len(fields) < 2 {
				continue
			}
			// `# path version [=> replacement...]` — record the
			// left-hand module identity; reconciling the replacement target
			// against a reproducible vendor tree is out of scope for this
			// scanner.
			mods = append(mods, domain.VendoredModule{Path: fields[0], Version: fields[1]})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	return mods, nil
}

// parseGoSum parses go.sum into "path@version" → module h1 hash. The
// `/go.mod` hash lines are skipped: vendored-tree integrity is verified
// against the module hash, not the go.mod hash. A missing go.sum is not an
// error (the domain reports affected modules as Unverified per).
func parseGoSum(path string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("reading go.sum %q: %w", path, err)
	}
	out := map[string]string{}
	for _, ln := range strings.Split(string(data), "\n") {
		fields := strings.Fields(ln)
		if len(fields) != 3 {
			continue
		}
		path, ver, hash := fields[0], fields[1], fields[2]
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}
		out[path+"@"+ver] = hash
	}
	return out, nil
}

// dirHasFiles reports whether dir exists and contains at least one regular
// file anywhere in its tree.
func dirHasFiles(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = true
		}
		return nil
	})
	return found
}

// extraVendoredModules returns module-path-shaped directories under vendor/
// that modules.txt does not list. It walks until it finds a directory whose
// path matches a listed module prefix or contains source, capping depth at
// the conventional domain/owner/repo (3) layout.
func extraVendoredModules(vendorDir string, listed []domain.VendoredModule) []string {
	known := map[string]bool{}
	for _, m := range listed {
		known[m.Path] = true
	}
	var extra []string
	entries, err := os.ReadDir(vendorDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		walkVendorDomain(vendorDir, e.Name(), known, &extra)
	}
	return extra
}

// walkVendorDomain descends a vendor/ host directory looking for module roots
// (a directory holding source files) not present in the known set.
func walkVendorDomain(vendorDir, host string, known map[string]bool, extra *[]string) {
	const maxDepth = 3
	var recur func(rel string, depth int)
	recur = func(rel string, depth int) {
		modPath := filepath.ToSlash(rel)
		if known[modPath] {
			return
		}
		full := filepath.Join(vendorDir, rel)
		if hasDirectSourceFile(full) && !known[modPath] {
			*extra = append(*extra, modPath)
			return
		}
		if depth >= maxDepth {
			return
		}
		entries, err := os.ReadDir(full)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				recur(filepath.Join(rel, e.Name()), depth+1)
			}
		}
	}
	recur(host, 1)
}

// hasDirectSourceFile reports whether dir directly contains a file (not in a
// subdirectory) — the marker of a module/package root in vendor/.
func hasDirectSourceFile(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}
