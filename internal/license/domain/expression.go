package domain

import (
	"sort"
	"strings"
)

// DeriveExpression computes the SPDX license expression for a module from its
// detected license file entries. The expression distinguishes:
//
// - Single license → bare SPDX identifier (e.g. "MIT")
// - Compound file (one file, multiple full license texts at near-equal
// coverage, e.g. yaml.v3) → OR expression (consumer picks one)
// - Multiple root files with dual-license naming (LICENSE-MIT + LICENSE-APACHE)
// → OR expression (consumer picks one)
// - Multiple root files with genuinely distinct licenses → AND expression
// (all apply)
// - No identified license → empty string
func DeriveExpression(entries []LicenseFileEntry) string {
	var roots []LicenseFileEntry
	for _, e := range entries {
		if !e.IsVendored && exprIsRootLevel(e.Path) && !exprIsNoticeName(e.Path) && e.SPDX != "" {
			roots = append(roots, e)
		}
	}
	if len(roots) == 0 {
		return ""
	}

	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Confidence > roots[j].Confidence
	})

	primary := roots[0]

	if len(roots) == 1 {
		// Filter pseudo-identifiers emitted by licensecheck that are not real
		// SPDX identifiers (e.g. "GooglePatentClause" for X.org patent disclaimers).
		// Including them in an expression produces semantically meaningless output.
		realAlts := filterRealSPDX(primary.AltMatches)
		if len(realAlts) > 0 {
			delta := primary.Confidence - realAlts[0].Confidence
			// Compound file: multiple full license texts at near-equal coverage.
			// Only treat as dual-licensed (OR) when there is exactly one
			// alternative — genuine dual-licensing offers exactly two choices
			// (e.g. yaml.v3: MIT OR Apache-2.0, gioui.org: MIT OR Unlicense).
			// Files with 2+ alts at identical confidence are omnibus attribution
			// files that bundle third-party license texts for compliance (e.g.
			// apache/arrow, klauspost/compress); their primary SPDX id is correct.
			if delta <= exprCompoundDelta && len(realAlts) == 1 {
				return buildORExpression(primary.SPDX, realAlts)
			}
		}
		return primary.SPDX
	}

	// Multiple root files: collect distinct SPDX identifiers.
	seen := make(map[string]bool)
	var distinct []string
	for _, r := range roots {
		if !seen[r.SPDX] {
			seen[r.SPDX] = true
			distinct = append(distinct, r.SPDX)
		}
	}
	if len(distinct) == 1 {
		return distinct[0]
	}

	sort.Strings(distinct)
	// Dual-license naming (e.g. LICENSE-MIT + LICENSE-APACHE) signals the
	// consumer may choose one. Otherwise, all licenses genuinely apply.
	if hasDualLicenseNaming(roots) {
		return strings.Join(distinct, " OR ")
	}
	return strings.Join(distinct, " AND ")
}

// buildORExpression constructs "primary OR alt1 OR alt2..." sorted and deduped.
func buildORExpression(primary string, alts []AltMatch) string {
	seen := map[string]bool{primary: true}
	ids := []string{primary}
	for _, a := range alts {
		if a.SPDX != "" && !seen[a.SPDX] {
			seen[a.SPDX] = true
			ids = append(ids, a.SPDX)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, " OR ")
}

// hasDualLicenseNaming reports whether any root entry uses a license file name
// that indicates the module is dual-licensed (e.g. LICENSE-MIT, COPYING-BSD).
// Modules with such names intend the consumer to select one license.
func hasDualLicenseNaming(entries []LicenseFileEntry) bool {
	for _, e := range entries {
		base := e.Path
		if idx := strings.LastIndex(e.Path, "/"); idx >= 0 {
			base = e.Path[idx+1:]
		}
		upper := strings.ToUpper(base)
		for _, prefix := range []string{"LICENSE-", "LICENCE-", "COPYING-"} {
			if strings.HasPrefix(upper, prefix) {
				return true
			}
		}
	}
	return false
}

// licenseCheckPseudoIDs is the set of identifiers emitted by
// google/licensecheck that are not registered SPDX identifiers. They must be
// excluded from expressions to avoid producing semantically invalid output.
var licenseCheckPseudoIDs = map[string]bool{
	"GooglePatentClause": true, // X.org patent disclaimer, not an SPDX id
}

// filterRealSPDX returns only those AltMatches whose SPDX field is a real
// SPDX identifier (i.e. not a licensecheck-specific pseudo-identifier).
func filterRealSPDX(alts []AltMatch) []AltMatch {
	out := alts[:0:0]
	for _, a := range alts {
		if a.SPDX != "" && !licenseCheckPseudoIDs[a.SPDX] {
			out = append(out, a)
		}
	}
	return out
}

// exprCompoundDelta mirrors application.compoundConfDelta without importing
// the application package (which would violate the dependency rule). The value
// must stay in sync with the application layer constant.
const exprCompoundDelta = 0.005

// exprIsRootLevel reports whether relPath has no directory separator.
func exprIsRootLevel(relPath string) bool {
	return !strings.Contains(relPath, "/")
}

// exprIsNoticeName reports whether the path's base name is a NOTICE file.
func exprIsNoticeName(relPath string) bool {
	base := relPath
	if idx := strings.LastIndex(relPath, "/"); idx >= 0 {
		base = relPath[idx+1:]
	}
	return strings.EqualFold(base, "NOTICE") ||
		strings.EqualFold(base, "NOTICE.txt") ||
		strings.EqualFold(base, "NOTICE.md")
}
