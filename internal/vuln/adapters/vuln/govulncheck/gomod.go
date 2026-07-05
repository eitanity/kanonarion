package govulncheck

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/modfile"
)

// neutraliseLocalReplaces rewrites the go.mod at path to drop filesystem
// (local-path) replace directives, returning whether the file was modified.
//
// A module scanned in isolation is its own main module, so govulncheck honours
// its replace directives. A multi-module repository member ships development-time
// replaces pointing at sibling directories — for example
// go.opentelemetry.io/otel/trace declares `replace go.opentelemetry.io/otel =>
// ../`. Those targets are absent from the published module zip, so honouring them
// fails the build and the module is reported unscannable, even though a real
// consumer — which ignores a dependency's replaces — resolves the sibling from
// the module cache and builds cleanly. Dropping the local replaces reproduces the
// consumer's view: the required module resolves from GOMODCACHE instead.
//
// Module-to-module (versioned) replaces are left intact; they name a resolvable
// coordinate.
func neutraliseLocalReplaces(path string) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is our own extracted go.mod
	if err != nil {
		return false, fmt.Errorf("read go.mod: %w", err)
	}
	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return false, fmt.Errorf("parse go.mod: %w", err)
	}

	// Collect targets first: DropReplace mutates f.Replace, so dropping while
	// ranging over it would skip entries.
	type oldRef struct{ path, version string }
	var toDrop []oldRef
	for _, r := range f.Replace {
		if isLocalReplacePath(r.New.Path) {
			toDrop = append(toDrop, oldRef{r.Old.Path, r.Old.Version})
		}
	}
	if len(toDrop) == 0 {
		return false, nil
	}
	for _, d := range toDrop {
		if err := f.DropReplace(d.path, d.version); err != nil {
			return false, fmt.Errorf("drop replace %s: %w", d.path, err)
		}
	}
	f.Cleanup()
	out, err := f.Format()
	if err != nil {
		return false, fmt.Errorf("format go.mod: %w", err)
	}
	// Module-zip entries are extracted with their archive mode, which is
	// read-only for go.mod; make it writable before overwriting.
	if err := os.Chmod(path, 0o600); err != nil { // #nosec G302,G703 -- our own extracted go.mod, path sanitised at extraction
		return false, fmt.Errorf("chmod go.mod: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil { // #nosec G703 -- our own extracted go.mod, path sanitised at extraction
		return false, fmt.Errorf("write go.mod: %w", err)
	}
	return true, nil
}

// isLocalReplacePath reports whether a replace target is a filesystem path
// rather than a module path. Local paths start with "." or "/".
func isLocalReplacePath(path string) bool {
	return strings.HasPrefix(path, "./") ||
		strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, "/") ||
		path == "." ||
		path == ".."
}
