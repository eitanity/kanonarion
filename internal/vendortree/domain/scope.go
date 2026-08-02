package domain

import "sort"

// Reasons a module in the vendored tree is outside what a document describes.
// They are prose because they are read by a person deciding whether the gap
// matters; the machine-readable discriminator is the module list itself.
const (
	// ReasonNoPackages — the module heading is in vendor/modules.txt but no
	// package line follows it, so no package of the build imports anything
	// from it. `go mod vendor` vendors no directory for such a module, and a
	// document describing the build's code has nothing of it to describe.
	// This is out of scope by construction, never a gap.
	ReasonNoPackages = "contributes no package to the build; vendor/modules.txt names the module but no package under it, so the tree holds no code for it"
	// ReasonNotDescribed — vendor/modules.txt lists packages under the module
	// and the document does not describe it. This one is a gap, and naming it
	// is the whole point of stating scope.
	//
	// It states what was counted — package LINES in modules.txt — and not
	// build membership, which this measurement cannot establish. `go mod
	// vendor` writes a package line for every package reachable under ANY
	// build constraint, so a module can carry lines that no build selects: a
	// `//go:build modhack` shim importing a sibling module is exactly that
	// shape, vendored and never compiled. Reading a line count as "contributes
	// packages to the build" turns a tag-independent count into a claim about
	// one build's import graph, which is a different measurement and a
	// stronger one than anything here performed.
	ReasonNotDescribed = "vendor/modules.txt lists package lines under it that this document does not describe"
)

// UncoveredVendoredModule is one module of the vendored tree a document does
// not describe, with the reason it does not.
type UncoveredVendoredModule struct {
	Path    string
	Version string
	Reason  string
	// PackageLines is how many packages vendor/modules.txt lists under this
	// module — the number the reason is stating, carried separately so it can
	// be read without parsing prose.
	//
	// It is a count of what `go mod vendor` wrote, across all build
	// constraints, not a count of what any build compiles. Zero is the only
	// value that settles build membership, and it settles it downwards: a
	// module with no vendored package under any constraint has none under a
	// particular one either.
	PackageLines int
}

// VendorScope states what a document covers of the vendored tree it was made
// from: how many modules the tree holds, how many the document describes, and
// every module it does not, each with its reason.
//
// The vendored tree IS the build in an air-gapped project — there is no proxy
// to consult — so a document that lists fewer modules than the tree and says
// nothing about the difference cannot be told apart from a complete one except
// by walking modules.txt by hand. Stating the scope is what makes a correct
// narrowing legible as a narrowing rather than as completeness.
type VendorScope struct {
	// TreeModules is the number of module entries in vendor/modules.txt.
	TreeModules int
	// Covered is how many of them the document describes.
	Covered int
	// Uncovered names the remainder, sorted by module path. Empty means the
	// document covers the whole tree — which the reader is told explicitly
	// rather than left to infer from silence.
	Uncovered []UncoveredVendoredModule
}

// FullyCovered reports whether the document describes every module the
// vendored tree holds.
func (s VendorScope) FullyCovered() bool { return len(s.Uncovered) == 0 }

// ScopeOverTree states a document's coverage of the vendored tree mods came
// from. covered reports whether the document describes a given module; a nil
// covered predicate treats a module as covered exactly when the tree holds
// code for it (the reconciliation's own scope).
//
// A module the predicate rejects is reported as out of scope by construction
// when it contributes no package, and as a gap when it does — the same absence,
// two different facts, and conflating them is what turns a correct omission
// into false drift.
func ScopeOverTree(mods []VendoredModule, covered func(VendoredModule) bool) VendorScope {
	if covered == nil {
		covered = func(m VendoredModule) bool { return m.PackageCount > 0 }
	}
	scope := VendorScope{TreeModules: len(mods)}
	for _, m := range mods {
		if covered(m) {
			scope.Covered++
			continue
		}
		reason := ReasonNotDescribed
		if m.PackageCount == 0 {
			reason = ReasonNoPackages
		}
		scope.Uncovered = append(scope.Uncovered, UncoveredVendoredModule{
			Path: m.Path, Version: m.Version, Reason: reason,
			PackageLines: m.PackageCount,
		})
	}
	sort.Slice(scope.Uncovered, func(i, j int) bool {
		if scope.Uncovered[i].Path != scope.Uncovered[j].Path {
			return scope.Uncovered[i].Path < scope.Uncovered[j].Path
		}
		return scope.Uncovered[i].Version < scope.Uncovered[j].Version
	})
	return scope
}
