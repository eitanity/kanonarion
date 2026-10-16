package staticcha

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"

	"golang.org/x/mod/modfile"
)

// dropLocalReplaces removes the replace directives in an extracted module's own
// go.mod that cannot resolve in the extraction, and reports what it removed.
//
// It runs only for a module extracted from a published zip, where the analysis
// makes that module the MAIN module of a build for the first time in its life. A
// replace directive is ignored by the go command in any module that is not the
// main module, so a directive in a published artefact has never applied to any
// consumer's build; the extraction is the one context that applies it. Two kinds
// cannot resolve here, and both are dropped:
//
//   - a target OUTSIDE the extracted tree. "replace example.com/mod/creds =>
//     ../creds/" names a sibling checkout of a monorepo, and a zip holds one
//     module. Measured on github.com/aws/aws-sdk-go-v2/config@v1.32.25: fifteen
//     packages of the dependency closure in error with the twelve directives
//     present, none without them.
//   - an ABSENT target inside the tree whose replaced path is a nested module of
//     this module: "replace go.opentelemetry.io/otel/metric => ./metric" in
//     go.opentelemetry.io/otel. The zip format leaves every nested module out of
//     its parent's zip, so the directory is absent by construction, while the
//     nested module is published separately and resolves like any requirement.
//
// Dropping them is not a repair of the module. It restores the build every real
// consumer already gets, and the record states what was dropped, on the same
// terms the synthesised-go.mod path states the file it wrote.
//
// Every other filesystem target is kept. One inside the tree that exists — a
// nested module the zip carries, "replace example.com/dep => ./dep" — resolves
// exactly as published. One inside the tree that is absent and names any other
// module path is a true statement about the published bytes: the go command
// reports it, and that report belongs on the record as the module's own fault.
//
// The outside test is lexical and never consults the filesystem: the extraction
// directory sits under the system temp root, so "../" names that root, and a stray
// go.mod there must not be pulled into the analysis of an unrelated module. The
// absence test runs only on a target already known to be inside the tree.
//
// A replace whose target names a MODULE VERSION is left untouched: it resolves
// from the module graph with no filesystem involved. A go.mod that is absent, or
// that does not parse, is left exactly as it is; the load reports a parse failure
// in its own terms, with a line number this cannot produce.
func dropLocalReplaces(dir, modulePath string) ([]domain.DroppedReplace, error) {
	path := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(path) /* #nosec G304 -- dir is an extraction directory this process created and owns */
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	f := parsedGoModOrNil(path, data)
	if f == nil {
		return nil, nil
	}

	var dropped []domain.DroppedReplace
	for _, r := range f.Replace {
		if !isFilesystemReplace(r) {
			continue
		}
		drop, derr := unresolvableHere(dir, modulePath, r)
		if derr != nil {
			return nil, derr
		}
		if !drop {
			continue
		}
		dropped = append(dropped, domain.DroppedReplace{
			Path:    r.Old.Path,
			Version: r.Old.Version,
			Target:  r.New.Path,
		})
	}
	if len(dropped) == 0 {
		// Nothing to write. The published bytes stay exactly as published, which is
		// what makes this a no-op for every module that does not carry one.
		return nil, nil
	}
	for _, d := range dropped {
		if derr := f.DropReplace(d.Path, d.Version); derr != nil {
			return nil, fmt.Errorf("dropping replace %s in %s: %w", d, path, derr)
		}
	}
	f.Cleanup()
	out, err := f.Format()
	if err != nil {
		return nil, fmt.Errorf("formatting %s: %w", path, err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil { /* #nosec G703 -- path is <dir>/go.mod, and dir is an extraction directory this process created and owns */
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	domain.SortDroppedReplaces(dropped)
	return dropped, nil
}

// parsedGoModOrNil parses a go.mod, or reports that it could not by returning
// nil.
//
// The parse error is deliberately discarded rather than propagated. The load is
// about to report a malformed go.mod in its own terms, with a line number this
// cannot produce, and turning it into an error here would replace that diagnosis
// with a worse one raised a step earlier.
func parsedGoModOrNil(path string, data []byte) *modfile.File {
	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil
	}
	return f
}

// isFilesystemReplace reports whether a replace directive's target is a
// filesystem path rather than a module version.
//
// The go.mod grammar decides it, not a spelling test: a replacement naming a
// module version carries that version, and one naming a directory must omit it.
// So an empty replacement version IS the filesystem form, and matching on "../"
// or a leading slash would be a second, weaker spelling of a rule the file format
// already states.
func isFilesystemReplace(r *modfile.Replace) bool {
	return r != nil && r.New.Version == ""
}

// unresolvableHere reports whether a filesystem replace cannot resolve in the
// extraction: its target escapes the tree, or it is absent and the replaced path
// is a nested module of modulePath. See dropLocalReplaces.
func unresolvableHere(root, modulePath string, r *modfile.Replace) (bool, error) {
	if escapesModuleRoot(root, r.New.Path) {
		return true, nil
	}
	if !isNestedModulePath(modulePath, r.Old.Path) {
		return false, nil
	}
	target := filepath.Join(root, filepath.FromSlash(r.New.Path))
	_, err := os.Lstat(target)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, fs.ErrNotExist), pathElementIsFile(root, target):
		return true, nil
	default:
		return false, fmt.Errorf("checking replace target %s: %w", target, err)
	}
}

// pathElementIsFile reports whether the nearest existing ancestor of target,
// stopping at root, is not a directory: then the target is absent. It replaces
// a syscall.ENOTDIR test, which the extraction packages may not import.
func pathElementIsFile(root, target string) bool {
	for dir := filepath.Dir(target); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err == nil {
			return !info.IsDir()
		}
		if dir == root || dir == filepath.Dir(dir) {
			return false
		}
	}
}

// isNestedModulePath reports whether path lies under modulePath on a "/"
// boundary: example.com/mod/sub is nested in example.com/mod, example.com/modx
// is not, and neither is example.com/mod itself.
func isNestedModulePath(modulePath, path string) bool {
	return modulePath != "" && strings.HasPrefix(path, modulePath+"/")
}

// escapesModuleRoot reports whether a replace target names a directory outside
// the extracted module tree.
//
// It is lexical on purpose — see dropLocalReplaces. An absolute target always
// escapes: it names a directory on the machine that published the module, and
// resolving it against this host would be worse than failing.
func escapesModuleRoot(root, target string) bool {
	local := filepath.FromSlash(target)
	if !filepath.IsAbs(local) {
		local = filepath.Join(root, local)
	}
	rel, err := filepath.Rel(root, local)
	if err != nil {
		// Two paths with no relation between them: on this platform that means
		// different volumes, which is as far outside the tree as it gets.
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
