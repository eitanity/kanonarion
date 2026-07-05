package domain

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// AnalysisLevel identifies the depth of analysis performed on the local workspace.
type AnalysisLevel string

const (
	// AnalysisLevelImport is the default level. It identifies which packages
	// from each dependency module are imported by the workspace (go list -json).
	AnalysisLevelImport AnalysisLevel = "import"
	// AnalysisLevelSymbol additionally identifies which exported symbols from
	// each imported package are referenced (go/packages type-check, ~2-5s).
	AnalysisLevelSymbol AnalysisLevel = "symbol"
)

// ImportedModule records which packages and symbols from one dependency module
// are actually used by the local workspace.
type ImportedModule struct {
	// Path is the module path (e.g. "golang.org/x/mod").
	Path string
	// Version is the module version (e.g. "v0.35.0").
	Version string
	// ImportedPackages lists the import paths of packages from this module
	// that are directly imported by workspace packages. Sorted.
	ImportedPackages []string
	// UsedSymbols lists "pkg/path.Symbol" qualified names of exported symbols
	// from this module that are referenced in the workspace. Sorted. Nil
	// unless the analysis level is AnalysisLevelSymbol or higher.
	UsedSymbols []string
}

// LocalContext is the result of a local workspace analysis run.
type LocalContext struct {
	// Root is the absolute path of the workspace directory.
	Root string
	// ModulePath is the Go module path declared in the workspace's go.mod.
	ModulePath string
	// VersionID is a deterministic pseudo-version computed from the snapshot
	// contents. Can be used as a cache key.
	VersionID string
	// AnalysisLevel is the level of analysis performed.
	AnalysisLevel AnalysisLevel
	// Modules contains one entry per imported dependency module, sorted by path.
	Modules []ImportedModule
}

// SortModules sorts mods in place by Path for deterministic output.
func SortModules(mods []ImportedModule) {
	sort.Slice(mods, func(i, j int) bool {
		return mods[i].Path < mods[j].Path
	})
}

// SnapshotModulePath extracts the Go module path declared in a Snapshot's
// go.mod content. When multiple go.mod files exist (e.g. nested test
// fixtures), the one closest to the workspace root — i.e. the one with the
// shortest path — wins; map iteration order is non-deterministic and would
// otherwise pick an arbitrary nested module. Returns an error if no go.mod
// is found or the module directive is missing.
func SnapshotModulePath(snap Snapshot) (string, error) {
	candidates := make([]string, 0)
	for path := range snap.Files {
		if filepath.Base(path) == "go.mod" {
			candidates = append(candidates, path)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no go.mod found in snapshot")
	}
	// Prefer the go.mod nearest the workspace root: shortest path, tie-break
	// lexicographically for determinism.
	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i]) != len(candidates[j]) {
			return len(candidates[i]) < len(candidates[j])
		}
		return candidates[i] < candidates[j]
	})
	for _, path := range candidates {
		mp, err := parseGoModModulePath(snap.Files[path])
		if err != nil {
			continue
		}
		return mp, nil
	}
	return "", fmt.Errorf("no parseable go.mod found in snapshot")
}

// parseGoModModulePath scans go.mod bytes for the module directive and returns
// the declared module path. It does not import golang.org/x/mod.
func parseGoModModulePath(content []byte) (string, error) {
	for _, line := range bytes.Split(content, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("module ")) {
			continue
		}
		path := strings.TrimSpace(string(line[len("module "):]))
		if idx := strings.Index(path, "//"); idx >= 0 {
			path = strings.TrimSpace(path[:idx])
		}
		if path != "" {
			return path, nil
		}
	}
	return "", fmt.Errorf("module directive not found")
}
