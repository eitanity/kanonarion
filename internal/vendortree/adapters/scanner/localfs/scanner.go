// Package localfs implements ports.VendorScanner against the local
// filesystem. It is pure scanning: it parses vendor/modules.txt, the main
// go.mod require set and go.sum, enumerates the module directories present
// under vendor/, and digests every file each vendored module holds alongside
// the files that module's go.sum-verified zip publishes. It performs no
// reconciliation or policy (those are the domain and config concerns
// respectively, per) and never contacts the proxy — the closure is resolved
// entirely from modules.txt, so an airgapped scan completes with no network.
//
// It deliberately does not hash the vendored directory as a whole. `go mod
// vendor` prunes each module to the packages the build imports and strips its
// test files and go.mod, while go.sum's h1 covers the complete published zip, so
// a whole-tree hash has no value to be compared against and reported nearly
// every intact module as drifted. The comparison that is well-defined over a
// pruned subset is per file, which is what this scanner measures.
package localfs

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/vendortree/domain"
	"github.com/eitanity/kanonarion/internal/vendortree/ports"
	"golang.org/x/mod/modfile"
)

// Scanner implements ports.VendorScanner.
type Scanner struct {
	zips ports.VerifiedModuleZipSource
}

// New returns a Scanner that compares vendored files against the module zips
// zips holds. A nil source is legitimate — nothing is held, so every module
// with a go.sum entry is reported unverified rather than clean.
func New(zips ports.VerifiedModuleZipSource) *Scanner { return &Scanner{zips: zips} }

// ScanProject reads the vendored project rooted at goModPath. It returns
// ports.ErrNotVendored when there is no vendor/modules.txt — the closure
// cannot be resolved from the vendored tree, which the caller handles per the
// requested mode.
func (s *Scanner) ScanProject(ctx context.Context, goModPath string, vendorOnly bool) (domain.ParseResult, error) {
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

	listedPaths := make(map[string]bool, len(modules))
	for _, m := range modules {
		listedPaths[m.Path] = true
	}

	present := map[string]bool{}
	files := map[string]domain.ModuleFiles{}
	for _, m := range modules {
		dir := filepath.Join(vendorDir, filepath.FromSlash(m.Path))
		vendored, err := digestVendoredModule(dir, m.Path, listedPaths)
		if err != nil {
			return domain.ParseResult{}, err
		}
		if len(vendored) == 0 {
			continue
		}
		present[m.Path] = true

		mf := domain.ModuleFiles{Vendored: vendored}
		if h1 := goSum[m.Path+"@"+m.Version]; h1 != "" && s.zips != nil {
			published, found, zerr := s.zips.PublishedFiles(ctx, m.Path, m.Version, h1)
			if zerr != nil {
				return domain.ParseResult{}, fmt.Errorf("reading the verified module zip for %s@%s: %w", m.Path, m.Version, zerr)
			}
			mf.ZipHeld, mf.Zip = found, published
		}
		files[m.Path] = mf
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
		Files:             files,
	}, nil
}

// digestVendoredModule maps every file under a vendored module's directory to
// the digest of its bytes, keyed by the module-relative slash-separated path.
// It returns an empty map (not an error) when the directory does not exist:
// modules.txt listing a module the tree does not hold is a finding the domain
// raises, not a scan failure.
//
// Subtrees that are themselves listed modules are excluded. Module paths nest —
// github.com/go-chi/chi/v5 lives inside the directory of github.com/go-chi/chi —
// and attributing the nested module's files to its parent would report every one
// of them as a file the parent's zip never published.
func digestVendoredModule(dir, modulePath string, listed map[string]bool) (map[string]string, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return map[string]string{}, nil //nolint:nilerr // an absent directory is the domain's missing-from-vendor finding
	}

	out := map[string]string{}
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking vendored module %q: %w", modulePath, err)
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return fmt.Errorf("resolving %q under vendored module %q: %w", path, modulePath, rerr)
		}
		slashRel := filepath.ToSlash(rel)
		if d.IsDir() {
			if slashRel != "." && listed[modulePath+"/"+slashRel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			// A symlink or other irregular file is recorded, not skipped: the
			// published module zip holds only regular files, so whatever this
			// is, it is not what the module published — and skipping it would
			// silently exempt exactly the kind of substitution the drift axis
			// exists to catch (a symlink resolves at build time to bytes this
			// scan never measured).
			out[slashRel] = irregularMarker(d.Type())
			return nil
		}
		digest, derr := digestFile(path)
		if derr != nil {
			return derr
		}
		out[slashRel] = digest
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("digesting vendored module %q: %w", modulePath, walkErr)
	}
	return out, nil
}

// irregularMarker names a non-regular directory entry in the digest position.
// It can never equal a "sha256:<hex>" digest, so the domain reports the file as
// drift rather than comparing content that was never read.
func irregularMarker(mode os.FileMode) string {
	if mode&os.ModeSymlink != 0 {
		return domain.DigestIrregularPrefix + "symlink"
	}
	return domain.DigestIrregularPrefix + "non-regular-file"
}

// digestFile returns the "sha256:<hex>" digest of a file's bytes.
func digestFile(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("opening vendored file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing vendored file %q: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
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
			// `# path => target version` (no version on the left) is the
			// trailing replacement-directive footer go mod vendor appends, not
			// a module entry — the module it names already has its own
			// `# path version => …` line above. Taking the footer as an entry
			// fabricates a module whose version is the literal "=>".
			if fields[1] == "=>" {
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
	for ln := range strings.SplitSeq(string(data), "\n") {
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
