package staticcha

import (
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

// maxNamedPackages bounds how many resolved package paths a diagnosis lists. It
// is a readability bound on a message, never a bound on what was measured: the
// count that precedes the list is the whole population.
const maxNamedPackages = 5

// declaredModulePath reports the module path the tree about to be analysed
// declares for itself, and whether it declares one at all.
//
// The path a module publishes under and the path it declares are not always the
// same string. A fork republished at a new path that never rewrote its module
// directive keeps declaring the original — github.com/cortezaproject/gval
// declares github.com/PaesslerAG/gval — and the consumer that depends on it does
// so through a replace directive, so every import in every consumer names the
// DECLARED path. Testing package membership against the coordinate therefore
// matched nothing, the target set came back empty, and the module was recorded
// with an empty graph and the words "no packages successfully loaded".
//
// A malformed go.mod is not an error here. The load is about to report it in its
// own terms, with a line number this cannot produce, and refusing early would
// replace that diagnosis with a worse one.
func declaredModulePath(dir string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod")) /* #nosec G304 -- dir is an extraction directory this process created and owns */
	if err != nil {
		return "", false
	}
	path := modfile.ModulePath(data)
	if path == "" {
		return "", false
	}
	return path, true
}

// targetCoordinate is the coordinate the package-membership tests use: the
// coordinate as requested, with its path replaced by the one the analysed tree
// declares when the two disagree.
//
// The version is unchanged, and the RECORD keeps the requested coordinate — the
// record is about the artefact that was asked for. What changes is only the
// question "does this package belong to the module being analysed", which the
// declared path is the sole authority on.
//
// A tree that declares nothing (a module published before modules, whose
// synthesis was declined) is answered with the requested coordinate, exactly as
// before: there is no better answer available and inventing one would be worse
// than the coordinate.
func targetCoordinate(dir string, coord coordinate.ModuleCoordinate) coordinate.ModuleCoordinate {
	declared, ok := declaredModulePath(dir)
	if !ok || declared == coord.Path() {
		return coord
	}
	target, err := coordinate.NewModuleCoordinate(declared, coord.Version())
	if err != nil {
		return coord
	}
	return target
}

// metaLoadErrors collects every error the metadata load attached to a package,
// deduplicated and in a stable order.
//
// go/packages returns a nil error when the driver ran and reported failures
// through the packages themselves, so a load that resolved nothing can look
// entirely successful to a caller that only checks the returned error. These
// strings are the toolchain's own account of what went wrong — a missing go.sum
// line, a replace directive pointing at a directory the zip does not carry, a
// module lookup it was not permitted to make — and they were being discarded.
func metaLoadErrors(pkgs []*packages.Package) []string {
	seen := map[string]bool{}
	var out []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			// An error carrying no message of its own renders as a bare position
			// marker. It is not being suppressed as noise — there is nothing in it to
			// suppress, and a detail listing "-:" three times crowds out the errors
			// that do say something.
			if strings.TrimSpace(e.Msg) == "" {
				continue
			}
			msg := strings.TrimSpace(e.Error())
			if seen[msg] {
				continue
			}
			seen[msg] = true
			out = append(out, msg)
		}
	})
	sort.Strings(out)
	return out
}

// resolvedPackagePaths lists the import paths the metadata load resolved, sorted
// and without the empty path go/packages uses for a synthesised error package.
func resolvedPackagePaths(pkgs []*packages.Package) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range pkgs {
		if p == nil || p.PkgPath == "" || seen[p.PkgPath] {
			continue
		}
		seen[p.PkgPath] = true
		out = append(out, p.PkgPath)
	}
	sort.Strings(out)
	return out
}

// describeEmptyTargetSet says why the analysis has nothing to analyse.
//
// It is the message that replaced "no packages successfully loaded" for the case
// that produced it most often: the loader ran, returned packages, and not one of
// them belonged to the module under analysis. Three facts settle it between
// them — what the loader was looking for, what it found, and what it said went
// wrong — and none of them was being reported.
func describeEmptyTargetSet(target coordinate.ModuleCoordinate, pkgs []*packages.Package, loadErrs []string) string {
	paths := resolvedPackagePaths(pkgs)
	var b strings.Builder
	fmt.Fprintf(&b, "no package under %s: the loader resolved %d package(s)", target.Path(), len(paths))
	switch {
	case len(paths) == 0:
		b.WriteString(" with an import path")
	case len(paths) > maxNamedPackages:
		fmt.Fprintf(&b, " (%s, +%d more)", strings.Join(paths[:maxNamedPackages], ", "), len(paths)-maxNamedPackages)
	default:
		fmt.Fprintf(&b, " (%s)", strings.Join(paths, ", "))
	}
	if len(loadErrs) > 0 {
		b.WriteString("; the loader reported: " + joinFirst(loadErrs, 3))
	}
	return b.String()
}

// platformFrame names the target platform the load resolved build constraints
// against.
//
// A module that ships only Windows source has no packages on this host, and
// "no packages found" reads as a statement about the artefact when it is a
// statement about the artefact AND the frame it was read in — the same
// distinction every platform-scoped answer in this tool is required to carry.
// github.com/yusufpapurcu/wmi is the whole of its Go source behind a windows
// build tag.
//
// It reads go/build's resolved context rather than runtime, because that is
// what the loader itself honours: a GOOS in the environment moves the frame,
// and a message naming the compiled-in platform would then name the wrong one.
func platformFrame() string {
	return build.Default.GOOS + "/" + build.Default.GOARCH
}
