package domain

import (
	"sort"
	"strings"
)

// DeriveEffectiveLicenseSet computes the effective license set for a module
// from its extracted license file entries. Root-level non-vendored files
// contribute to RootSPDXs; all non-root-level files (whether under vendor/ or
// in embedded subdirectories like snappy/) are grouped by component prefix
// into Components. AllSPDXs is the sorted, deduped union of both.
//
// Notice files (NOTICE, NOTICE.txt) are excluded — they are attribution
// documents, not license declarations.
//
// EffectiveSet is derived data: recompute from LicenseFiles whenever needed
// rather than storing it separately, so it is always consistent.
func DeriveEffectiveLicenseSet(entries []LicenseFileEntry) EffectiveLicenseSet {
	rootSeen := make(map[string]bool)
	var rootSPDXs []string

	compMap := make(map[string]map[string]bool) // prefix → set of SPDXs

	for _, e := range entries {
		if e.SPDX == "" || exprIsNoticeName(e.Path) {
			continue
		}
		if !e.IsVendored && exprIsRootLevel(e.Path) {
			if !rootSeen[e.SPDX] {
				rootSeen[e.SPDX] = true
				rootSPDXs = append(rootSPDXs, e.SPDX)
			}
		} else if !exprIsRootLevel(e.Path) {
			// Non-root files (vendored or subdirectory embedded components).
			prefix := embeddedComponentPrefix(e.Path)
			if compMap[prefix] == nil {
				compMap[prefix] = make(map[string]bool)
			}
			compMap[prefix][e.SPDX] = true
		}
	}

	sort.Strings(rootSPDXs)

	prefixes := make([]string, 0, len(compMap))
	for p := range compMap {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	components := make([]EmbeddedComponent, 0, len(prefixes))
	for _, p := range prefixes {
		spdxSet := compMap[p]
		spdxs := make([]string, 0, len(spdxSet))
		for s := range spdxSet {
			spdxs = append(spdxs, s)
		}
		sort.Strings(spdxs)
		components = append(components, EmbeddedComponent{PathPrefix: p, SPDXs: spdxs})
	}

	// AllSPDXs = union of root and component SPDXs, sorted.
	allSeen := make(map[string]bool)
	for _, s := range rootSPDXs {
		allSeen[s] = true
	}
	allSPDXs := make([]string, 0, len(allSeen))
	allSPDXs = append(allSPDXs, rootSPDXs...)
	for _, comp := range components {
		for _, s := range comp.SPDXs {
			if !allSeen[s] {
				allSeen[s] = true
				allSPDXs = append(allSPDXs, s)
			}
		}
	}
	sort.Strings(allSPDXs)

	return EffectiveLicenseSet{
		RootSPDXs:  rootSPDXs,
		Components: components,
		AllSPDXs:   allSPDXs,
	}
}

// embeddedComponentPrefix returns the directory portion of a vendored path,
// i.e. the path without the trailing filename.
// e.g. "vendor/github.com/google/snappy/LICENSE" → "vendor/github.com/google/snappy"
func embeddedComponentPrefix(relPath string) string {
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		return relPath[:idx]
	}
	return relPath
}

// IsUnbuiltPath reports whether a path prefix names a directory the Go
// toolchain never compiles, at any depth:
//
//   - a "testdata" segment,
//   - a segment beginning with "_",
//   - a segment beginning with "." (other than "." itself).
//
// These are the go tool's own ignore rules, not a guess about what a
// distributor ships. Nothing under such a directory is built, imported or
// linked into any binary, so a licence file found there governs a fixture — a
// sample graph, a captured document, a scanner test corpus — and not a
// component of the artefact.
//
// Two neighbouring cases are deliberately NOT covered, because the toolchain
// does build them: an "examples" directory is an ordinary package that can be
// imported and linked, and a nested "vendor" directory holds exactly the code
// that IS linked. Excluding either would be a judgement about distribution
// rather than a fact about the artefact.
//
// The predicate is applied where a consumer asks about the artefact — NOTICE
// generation and the compatibility engine — rather than in
// DeriveEffectiveLicenseSet, so the derived set stays a faithful account of
// what the module zip contains and each consumer states its own scope.
func IsUnbuiltPath(prefix string) bool {
	for _, seg := range strings.Split(prefix, "/") {
		if seg == "testdata" {
			return true
		}
		if len(seg) > 1 && (seg[0] == '_' || seg[0] == '.') {
			return true
		}
	}
	return false
}
