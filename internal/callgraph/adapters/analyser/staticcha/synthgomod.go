package staticcha

import (
	"errors"
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// synthesisedGoDirective is the language version written into every go.mod
// kanonarion synthesises. It is a constant, not a default, because it decides
// what the graph says.
//
// 1.16 is chosen for one reason: it is exactly what the toolchain already
// assumes for a module whose go.mod states no go directive. Every module this
// applies to predates modules entirely, so 1.16 is also the newest semantics its
// authors could not have been writing against. The alternative — tracking the
// host toolchain — would silently move a module across the 1.22 loop-variable
// boundary, changing the SSA and therefore the call graph, and two runs of the
// same tool on the same bytes would disagree with no field saying why.
//
// Changing this value changes graphs. It belongs on the record (see
// domain.SynthesisedGoMod.GoDirective) so a stored graph names the semantics it
// was built under rather than inheriting whatever this constant says today.
const synthesisedGoDirective = "1.16"

// errGoModPresent reports that the extracted module already ships a go.mod, so
// nothing was synthesised.
var errGoModPresent = errors.New("module ships its own go.mod")

// errNeedsDependencyResolution reports that the module ships no go.mod AND
// imports packages a synthesised one could not pin, so nothing was synthesised.
//
// A go.mod with no require list is only honest for a module that needs none. For
// a module that imports third-party packages it is a file that states something
// false: the load would go looking for versions nobody chose, and any edge it
// did produce would name coordinates that join nothing else in the ledger. The
// requesting walk's resolved build list answers that for the imports it covers;
// an import it does not cover leaves the same false file, so synthesis still
// refuses — all of them or none.
var errNeedsDependencyResolution = errors.New("module ships no go.mod and imports packages outside the standard library")

// unresolvableImportsError carries the imports that made synthesis refuse, so
// the record can name them instead of reporting an unattributed empty graph. It
// also names the build list that failed to pin them, because "no build list was
// offered" and "the offered build list does not contain these" are different
// facts about the same refusal.
type unresolvableImportsError struct {
	Imports []string
	// BuildListSource is the walk whose resolved versions were consulted, empty
	// when the request offered none.
	BuildListSource string
	// BuildListSize is how many coordinates that walk resolved.
	BuildListSize int
}

func (e *unresolvableImportsError) Error() string {
	out := errNeedsDependencyResolution.Error() + ": " + strings.Join(e.Imports, ", ")
	if e.BuildListSource == "" {
		return out + " (no resolved build list was offered to pin them)"
	}
	return out + " (not pinnable from the " + strconv.Itoa(e.BuildListSize) +
		" versions resolved by walk " + e.BuildListSource + ")"
}

func (e *unresolvableImportsError) Unwrap() error { return errNeedsDependencyResolution }

// synthesiseGoMod writes a minimal go.mod into an extracted module directory
// that shipped none, and reports what it wrote.
//
// A module published before Go modules carries no go.mod in its zip. Extracted
// into a bare directory, it loads OUTSIDE any module: no package carries the
// module's import path, so nothing matches the coordinate, so the target set is
// empty and the module is recorded with an empty graph. Every such coordinate
// fails, and the failure is a property of the extraction, not of the module.
//
// It refuses to touch a directory that already holds a go.mod. Modules that ship
// one and still fail to load are failing for their own reasons — an unresolvable
// require, a directive the toolchain rejects — and overwriting the published file
// would replace a real diagnosis with a fabricated tree. Refusing is what keeps
// this change from masking them.
//
// The module path written is coord.Path() verbatim. It is never derived from the
// version: a +incompatible module publishes a v2-or-later version under a path
// with NO major-version suffix, and adding one produces a graph whose every node
// ID names a module that does not exist.
//
// When the module's own packages import third-party code, the require directives
// are PINNED from the requesting walk's resolved build list — the versions that
// build actually selected — and written into the file. Nothing is resolved by the
// toolchain: the load runs offline against the local module cache, so a version
// nobody chose can never enter the graph. If any one import cannot be pinned,
// synthesis refuses outright rather than writing a file that names some
// dependencies and sends the loader hunting for the rest.
func synthesiseGoMod(
	dir string,
	coord coordinate.ModuleCoordinate,
	inputs domain.AnalysisInputs,
) (domain.SynthesisedGoMod, error) {
	goModPath := filepath.Join(dir, "go.mod")
	switch _, err := os.Lstat(goModPath); {
	case err == nil:
		return domain.SynthesisedGoMod{}, errGoModPresent
	case !errors.Is(err, fs.ErrNotExist):
		return domain.SynthesisedGoMod{}, fmt.Errorf("checking for go.mod in %s: %w", dir, err)
	}

	// A synthesised go.mod carries only the require directives kanonarion can name
	// from a build that already resolved them. An import left unpinned would send
	// the loader looking for whatever is latest, producing edges into coordinates
	// nobody selected, so one unpinnable import refuses the whole file.
	external, err := importsOutsideStandardLibrary(dir, coord.Path())
	if err != nil {
		return domain.SynthesisedGoMod{}, err
	}
	pinned, unpinned := domain.PinRequires(coord, external, inputs)
	if len(unpinned) > 0 {
		return domain.SynthesisedGoMod{}, &unresolvableImportsError{
			Imports:         unpinned,
			BuildListSource: inputs.Source,
			BuildListSize:   len(inputs.BuildList),
		}
	}

	vendored, err := hasVendorTree(dir)
	if err != nil {
		return domain.SynthesisedGoMod{}, err
	}

	synth := domain.SynthesisedGoMod{
		ModulePath:        coord.Path(),
		GoDirective:       synthesisedGoDirective,
		VendorTreePresent: vendored,
		Requires:          pinned,
	}
	if err := os.WriteFile(goModPath, []byte(renderSynthesisedGoMod(synth)), 0o600); err != nil {
		return domain.SynthesisedGoMod{}, fmt.Errorf("writing synthesised go.mod in %s: %w", dir, err)
	}
	return synth, nil
}

// renderSynthesisedGoMod writes the file the record describes, so what was
// recorded and what was loaded cannot drift apart.
func renderSynthesisedGoMod(synth domain.SynthesisedGoMod) string {
	var b strings.Builder
	b.WriteString("module " + synth.ModulePath + "\n\ngo " + synth.GoDirective + "\n")
	if len(synth.Requires) > 0 {
		b.WriteString("\nrequire (\n")
		for _, r := range synth.Requires {
			b.WriteString("\t" + r.Path + " " + r.Version + "\n")
		}
		b.WriteString(")\n")
	}
	return b.String()
}

// importsOutsideStandardLibrary lists, sorted and deduplicated, the import paths
// in the module's own production packages that a go.mod with no require list
// could not satisfy: everything that is neither the standard library nor the
// module itself.
//
// Only production files are read. A third-party import that appears solely in
// _test.go declarations costs the test axis — the load records TestScopeExcluded
// or a failed test package and says so — but it does not stop the module's own
// packages from type-checking, so it is not a reason to leave the module with no
// graph at all.
//
// Build constraints are honoured against the host, because that is what the
// loader will do: a file excluded for this GOOS is never type-checked and its
// imports are never resolved, so counting them would refuse modules that load
// perfectly well.
func importsOutsideStandardLibrary(root, modulePath string) ([]string, error) {
	buildCtx := build.Default
	fset := token.NewFileSet()
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walking %s: %w", path, walkErr)
		}
		if d.IsDir() {
			return skipNonPackageDir(root, path, d)
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		// A file the host build context excludes is not part of the load, so its
		// imports are not part of what has to resolve. MatchFile reads the file, and
		// an unreadable one is a genuine error rather than a file to skip: silently
		// dropping it would understate what the module needs.
		match, mErr := buildCtx.MatchFile(filepath.Dir(path), name)
		if mErr != nil {
			return fmt.Errorf("evaluating build constraints on %s: %w", path, mErr)
		}
		if !match {
			return nil
		}
		file, pErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if pErr != nil {
			// A file that will not parse will not type-check either, and the load
			// reports that on its own terms. It is not evidence of a missing
			// dependency, so it must not be the reason this module is refused.
			return nil //nolint:nilerr // a parse failure is the load's finding to report, not a synthesis precondition
		}
		for _, spec := range file.Imports {
			ip, uErr := strconv.Unquote(spec.Path.Value)
			if uErr != nil {
				continue
			}
			if isStandardLibraryPath(ip) || ip == modulePath || strings.HasPrefix(ip, modulePath+"/") {
				continue
			}
			seen[ip] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning %s for imports: %w", root, err)
	}

	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

// skipNonPackageDir skips the directories whose .go files are not part of this
// module's packages: vendored copies, testdata, the toolchain's ignored "_" and
// "." prefixes, and any nested module, which declares its own go.mod and is
// therefore a different module's code.
func skipNonPackageDir(root, path string, d fs.DirEntry) error {
	if path == root {
		return nil
	}
	name := d.Name()
	if name == "vendor" || name == "testdata" || strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
		return filepath.SkipDir
	}
	if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
		return filepath.SkipDir
	}
	return nil
}

// isStandardLibraryPath reports whether an import path names a standard library
// package. The toolchain's own rule is used: a first path element with no dot in
// it cannot be a module domain, so it is the standard library.
func isStandardLibraryPath(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}

// hasVendorTree reports whether dir holds a vendor directory. A go.mod beside
// one makes the toolchain auto-select -mod=vendor, so the load has to say
// explicitly which of the two it means.
func hasVendorTree(dir string) (bool, error) {
	info, err := os.Stat(filepath.Join(dir, "vendor"))
	switch {
	case err == nil:
		return info.IsDir(), nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("checking for vendor tree in %s: %w", dir, err)
	}
}

// analysisEnv is the process environment every packages.Load for one analysis
// runs under.
//
// It disables vendor mode when a go.mod was synthesised beside a vendor tree.
// Automatic vendoring would make the graph describe the vendored copies rather
// than the module's own dependency set — and a synthesised go.mod requires
// nothing, so vendor/modules.txt cannot be consistent with it and the load fails
// on that instead. Neither outcome is the analysis that was asked for, so the
// choice is made here and recorded on the record rather than left to the
// toolchain's default.
// It also pins the load offline whenever require directives were synthesised.
// Those versions came from a build that already resolved them, and the module
// cache the analyser documents as its precondition is where they live; letting
// the toolchain reach a proxy would let it substitute something the walk never
// selected, and would put a network call on a path that had none. GOSUMDB is
// disabled with it because a synthesised module has no go.sum and no published
// checksum line to check one against — the artefact's own integrity was already
// established by the fetch that stored it.
func analysisEnv(synth domain.SynthesisedGoMod) []string {
	env := isolatedModuleEnv()
	if len(synth.Requires) > 0 {
		// GOPROXY=off is the whole point: the versions are already chosen, so the
		// only legitimate source for them is the local module cache. GOSUMDB=off
		// keeps the checksum database — a network service — out of a load that must
		// not make one, for a go.mod that no published go.sum corresponds to.
		env = append(env, "GOPROXY=off", "GOSUMDB=off")
	}
	if synth.VendorTreePresent || len(synth.Requires) > 0 {
		// Appended last: os/exec keeps the final occurrence of a duplicate key, so
		// this also overrides an inherited GOFLAGS selecting vendor mode, and lets
		// the toolchain write the go.sum lines for the pinned requires from the
		// cache rather than refusing the load for want of a file the module never
		// published.
		env = append(env, "GOFLAGS=-mod=mod")
	}
	return env
}
