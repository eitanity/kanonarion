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

// dropLocalReplaces removes every replace directive in an extracted module's own
// go.mod whose target is a directory OUTSIDE the extracted tree, and reports what
// it removed.
//
// It runs only for a module extracted from a published zip, where the analysis
// makes that module the MAIN module of a build for the first time in its life. A
// replace directive is ignored by the go command in any module that is not the
// main module, so a directive in a published artefact has never applied to any
// consumer's build; the extraction is the one context that applies it, and — for
// a module published out of a monorepo — the one context where it cannot possibly
// resolve. "replace example.com/mod/creds => ../creds/" names a sibling checkout,
// and a zip holds one module. Every requirement so replaced dangles, the packages
// importing it fail to type-check, and the record files that as the module's own
// source failing to compile. Measured on
// github.com/aws/aws-sdk-go-v2/config@v1.32.25: fifteen packages of the
// dependency closure in error with the twelve directives present, none without
// them.
//
// Dropping them is not a repair of the module. It restores the build every real
// consumer already gets, and the record states what was dropped, on the same
// terms the synthesised-go.mod path states the file it wrote.
//
// OUTSIDE is the whole rule, and it is narrower than "is a filesystem path" for a
// reason that is not hypothetical: a zip can carry a nested module and replace
// onto it — "replace example.com/dep => ./dep" — and that directive resolves
// exactly as published, inside the tree the analysis reads. Dropping it would
// send the load hunting for a version of a module that is sitting in the zip.
//
// A target inside the tree that does not EXIST is kept too, and deliberately.
// The go command then says "replacement directory ./dep does not exist", which is
// a true statement about the published bytes and belongs on the record as the
// module's own fault. Dropping it would replace that diagnosis with a search for
// a module nobody published.
//
// The containment test is lexical and never consults the filesystem for the
// decision. The extraction directory sits under the system temp root, so "../"
// names that root: were the test "does the directory exist", a stray go.mod there
// would be silently pulled into the analysis of an unrelated module. A directive
// that cannot mean what it says must not be allowed to mean something else.
//
// A replace whose target names a MODULE VERSION is left untouched. It resolves
// from the module graph with no filesystem involved, so the extraction does not
// break it, and it is a real statement about what this module's own build
// selects.
//
// A go.mod that is absent, or that does not parse, is left exactly as it is. The
// load is about to report the parse failure in its own terms, with a line number
// this cannot produce, and pre-empting it would replace a real diagnosis with a
// worse one.
func dropLocalReplaces(dir string) ([]domain.DroppedReplace, error) {
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
		if !isFilesystemReplace(r) || !escapesModuleRoot(dir, r.New.Path) {
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
		if err := f.DropReplace(d.Path, d.Version); err != nil {
			return nil, fmt.Errorf("dropping replace %s in %s: %w", d, path, err)
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
