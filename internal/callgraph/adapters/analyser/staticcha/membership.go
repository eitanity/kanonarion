package staticcha

import (
	"sort"
	"strings"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"

	"golang.org/x/tools/go/packages"
)

// moduleMembership answers one question — does this import path belong to the
// analysed module — for every part of the analysis that needs it.
//
// It exists because the question was previously answered in four places by the
// same hand-rolled rule: "the path equals the coordinate, or begins with the
// coordinate plus a slash". That rule is wrong, and wrong in a way no amount of
// care at the call sites fixes, because Go module paths NEST. cloud.google.com/go
// and cloud.google.com/go/auth are separate modules, published and versioned
// independently; the prefix test cannot tell them apart, so one module's code was
// recorded as another module's own — with IsExternal false, and in places with
// IsExportedAPI true, naming a dependency's method as the analysed module's
// public surface.
//
// The go command already knows the answer. go/packages reports it as
// Package.Module.Path when the loader is asked for packages.NeedModule, and that
// answer is correct by definition: kanonarion reports on what the build contains,
// it does not get to define it.
//
// The prefix rule survives as a FALLBACK, not as an equal. A module that predates
// modules ships no go.mod, so the loader places its packages in no module at all,
// and that population is real. Where the loader has no answer the prefix test is
// the only one available — and every path it decides that way is recorded, on
// PrefixAttributedPackages, so a reconstruction is never mistaken for a
// measurement.
type moduleMembership struct {
	// coord is the coordinate the membership is measured against: the module path
	// the analysed tree DECLARES, not necessarily the one it is published under.
	coord coordinate.ModuleCoordinate
	// pkgModule maps an import path to the module path the loader reported for it.
	// A key present with an empty value is a package the loader placed in NO
	// module — the pre-modules case, and the standard library. A key that is
	// absent was never seen by the loader at all. The two are different states and
	// contains treats them the same way only because the fallback is the same for
	// both; the distinction is preserved so prefixAttributed can name the first.
	pkgModule map[string]string
	// pkgVersion maps an import path to the module VERSION the loader resolved
	// for it, keyed the same way as pkgModule. It is kept because a foreign
	// module held inside this record is only nameable with the version the build
	// gave it: the path alone names a module the record is not about, at a
	// version nobody stated.
	pkgVersion map[string]string
	// stdlib switches the rule to the standard library's own, where neither the
	// loader's module answer nor a path prefix can decide: the toolchain places
	// every std package in no module, and no std import path begins with
	// "stdlib". Membership is then the `std` pattern's own closure — the go
	// command's answer to "what is the standard library" — so a package the
	// loader resolved under it belongs to the coordinate and nothing else does.
	stdlib bool
}

// newModuleMembership records what the loader reported about every package it
// resolved, including the transitive dependencies, so membership can be decided
// for any package that reaches the SSA program.
func newModuleMembership(coord coordinate.ModuleCoordinate, loaded []*packages.Package) moduleMembership {
	m := moduleMembership{
		coord:      coord,
		pkgModule:  make(map[string]string, len(loaded)*8),
		pkgVersion: make(map[string]string, len(loaded)*8),
	}
	for _, p := range loaded {
		packages.Visit([]*packages.Package{p}, nil, func(dp *packages.Package) {
			if dp.PkgPath == "" {
				return
			}
			modPath, modVersion := "", ""
			if dp.Module != nil {
				modPath, modVersion = dp.Module.Path, dp.Module.Version
			}
			// The internal test variant of a package shares its import path with the
			// production package and reports the same module, so a later empty value
			// must not overwrite an earlier real one.
			if existing, ok := m.pkgModule[dp.PkgPath]; ok && existing != "" {
				return
			}
			m.pkgModule[dp.PkgPath] = modPath
			m.pkgVersion[dp.PkgPath] = modVersion
		})
	}
	return m
}

// newStdlibMembership records the standard library's own package set, taken
// from what the loader resolved for the `std` pattern.
//
// It is a measurement and not a reconstruction: `std` is the go command's own
// name for the standard library, and the closure it returns is the toolchain's
// answer to which packages are in it. The prefix fallback cannot be used here at
// all — no std import path begins with "stdlib" — and the loader's module answer
// is empty for every one of them, so without this rule the analysis would call
// the entire standard library external and record an empty graph.
func newStdlibMembership(coord coordinate.ModuleCoordinate, loaded []*packages.Package) moduleMembership {
	m := newModuleMembership(coord, loaded)
	m.stdlib = true
	return m
}

// membershipByPrefix is the membership of a coordinate about which the loader
// said nothing: every decision falls back to the path prefix. It knows no
// package universe, so it can name no package as prefix-attributed either — it
// is for callers that hold no load result, and the analysis never uses it.
func membershipByPrefix(coord coordinate.ModuleCoordinate) moduleMembership {
	return moduleMembership{coord: coord}
}

// path is the module path membership is measured against.
func (m moduleMembership) path() string { return m.coord.Path() }

// contains reports whether pkgPath is part of the analysed module.
func (m moduleMembership) contains(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	if m.stdlib {
		_, resolved := m.pkgModule[pkgPath]
		return resolved
	}
	if modPath, ok := m.pkgModule[pkgPath]; ok && modPath != "" {
		return modPath == m.coord.Path()
	}
	return m.byPrefix(pkgPath)
}

// byPrefix is the pre-loader rule, kept as the fallback for packages the
// toolchain places in no module.
//
// It is the fallback and not the rule for a second reason beyond nesting: the
// external test package of the module's ROOT package is "<path>_test", which
// shares the module path as a prefix but not as a path SEGMENT, so this test
// declines it and the module's own root-level test declarations came back
// foreign. Where the loader answers, they do not — go list places a test variant
// in the module it belongs to.
func (m moduleMembership) byPrefix(pkgPath string) bool {
	return pkgPath == m.coord.Path() || strings.HasPrefix(pkgPath, m.coord.Path()+"/")
}

// prefixAttributed is the sorted, deduplicated set of import paths this
// membership admits to the module by path prefix alone, because the loader
// placed them in no module. It is the label on the reconstruction: an empty
// result means every in-module package was named by the toolchain itself.
//
// Only packages the loader actually resolved are listed. A membership built with
// no loader answer at all (membershipByPrefix) knows no package paths, so it
// reports none — which is why the analysis builds the real one from the load.
func (m moduleMembership) prefixAttributed() []string {
	if m.stdlib {
		// Nothing was attributed by prefix: the standard library's membership is
		// the toolchain's own `std` closure, so there is no reconstruction to name.
		return nil
	}
	var out []string
	for pkgPath, modPath := range m.pkgModule {
		if modPath != "" {
			continue
		}
		if m.byPrefix(pkgPath) {
			out = append(out, pkgPath)
		}
	}
	sort.Strings(out)
	return out
}

// stdlibPackages is the sorted set of standard-library import paths this load
// resolved — the build's standard-library closure, measured by the go command
// rather than reconstructed.
//
// It is what lets a later read know which standard-library code is actually IN
// a build. A call graph records a dependency's functions only where an edge
// touches them, so the graph alone cannot distinguish a package the build links
// and never calls from one it does not link at all — and the difference decides
// whether a CHA over-approximation into that package describes a call that
// could happen or a function the binary does not contain.
func (m moduleMembership) stdlibPackages() []string {
	var out []string
	for pkgPath, modPath := range m.pkgModule {
		if modPath != "" || !isStdlibPackagePath(pkgPath) {
			continue
		}
		out = append(out, pkgPath)
	}
	sort.Strings(out)
	return out
}

// isStdlibPackagePath is the callgraph domain's rule, named here so the one
// statement of it serves both the analysis and the reads.
func isStdlibPackagePath(pkgPath string) bool { return domain.IsStdlibPackage(pkgPath) }

// foreignModules names every module other than the analysed one that the loader
// placed one of pkgPaths in, with the version it resolved, sorted and
// deduplicated.
//
// Only the loader's own answer counts. A package the loader placed in NO module
// is decided by path prefix elsewhere, and a prefix cannot tell a nested module
// from the analysed one — which is the exact confusion this set exists to state
// rather than reproduce. Such a package is therefore never reported as foreign:
// the record's prefix-attribution list is where a reconstruction is named.
func (m moduleMembership) foreignModules(pkgPaths []string) []domain.ForeignModule {
	seen := make(map[domain.ForeignModule]struct{})
	for _, pkgPath := range pkgPaths {
		modPath := m.pkgModule[pkgPath]
		if modPath == "" || modPath == m.coord.Path() {
			continue
		}
		seen[domain.ForeignModule{Path: modPath, Version: m.pkgVersion[pkgPath]}] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]domain.ForeignModule, 0, len(seen))
	for fm := range seen {
		out = append(out, fm)
	}
	sort.Slice(out, func(i, j int) bool { return domain.ForeignModuleLess(out[i], out[j]) })
	return out
}
