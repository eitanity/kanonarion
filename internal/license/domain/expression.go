package domain

import (
	"sort"
	"strings"
)

// ExpressionResult is the licence expression for a module together with the
// basis on which its operator was chosen. An expression's operator is a legal
// claim — under OR a redistributor elects one licence, under AND every licence
// governs — so the record says what settled it rather than leaving a reader to
// assume the pipeline knew.
type ExpressionResult struct {
	// Expression is the SPDX expression, e.g. "MIT", "MIT OR Unlicense",
	// "Apache-2.0 AND MIT". Empty when no licence was identified.
	Expression string
	// PrimarySPDX names the module's own licence when the reading establishes
	// it and the detector's most-covered match is not it — a bundled grant can
	// cover more of a file than the module's own licence does. Empty when the
	// detector's primary stands.
	PrimarySPDX string
	// Basis states how the operator was chosen: the shape read from the file
	// and the evidence that decided it. Empty when there was nothing to
	// decide — a single grant needs no operator.
	Basis string
	// BundledSPDXs lists grants carried in the licence file that cover
	// somebody else's code. They are deliberately absent from Expression: a
	// consumer must not read them as licences of this module, in either
	// direction — not as an arm they may elect, and not as an obligation the
	// module imposes.
	BundledSPDXs []string
}

// DeriveExpression computes the SPDX license expression for a module from its
// detected license file entries. See DeriveExpressionResult, of which this is
// the expression alone. texts maps a licence file's path to its verbatim
// content; a path absent from the map is read as text unavailable.
func DeriveExpression(entries []LicenseFileEntry, texts map[string]string) string {
	return DeriveExpressionResult(entries, texts).Expression
}

// DeriveExpressionResult computes the SPDX license expression for a module
// from its detected license file entries and the text of those files. The
// expression distinguishes:
//
// - Single license → bare SPDX identifier (e.g. "MIT")
// - Compound file (one file carrying several full licence texts at near-equal
// coverage) → whatever the file's own prose says the relationship is; see
// ReadCompoundFile. The count of texts decides nothing.
// - Multiple root files with dual-license naming (LICENSE-MIT + LICENSE-APACHE)
// → OR expression (consumer picks one)
// - Multiple root files with genuinely distinct licenses → AND expression
// (all apply)
// - No identified license → empty string
func DeriveExpressionResult(entries []LicenseFileEntry, texts map[string]string) ExpressionResult {
	var roots []LicenseFileEntry
	for _, e := range entries {
		if !e.IsVendored && exprIsRootLevel(e.Path) && !exprIsNoticeName(e.Path) && e.SPDX != "" {
			roots = append(roots, e)
		}
	}
	if len(roots) == 0 {
		return ExpressionResult{}
	}

	sortSlice(roots, RootCandidateLess)

	primary := roots[0]

	if len(roots) == 1 {
		// Filter pseudo-identifiers emitted by licensecheck that are not real
		// SPDX identifiers (e.g. "GooglePatentClause" for X.org patent disclaimers).
		// Including them in an expression produces semantically meaningless output.
		realAlts := filterRealSPDX(primary.AltMatches)
		if len(realAlts) > 0 {
			delta := primary.Confidence - realAlts[0].Confidence
			// A compound file carries several full licence texts at near-equal
			// coverage. Below the delta the alternative is a partial match
			// against one text, not a second grant, and the primary stands.
			if delta <= exprCompoundDelta {
				return readCompoundResult(primary, realAlts, texts[primary.Path])
			}
		}
		return ExpressionResult{Expression: primary.SPDX}
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
		return ExpressionResult{Expression: distinct[0]}
	}

	sort.Strings(distinct)
	// Dual-license naming (e.g. LICENSE-MIT + LICENSE-APACHE) signals the
	// consumer may choose one. Otherwise, all licenses genuinely apply.
	if hasDualLicenseNaming(roots) {
		return ExpressionResult{
			Expression: strings.Join(distinct, " OR "),
			Basis:      "election: one file per licence (" + strings.Join(rootPaths(roots), ", ") + ")",
		}
	}
	return ExpressionResult{
		Expression: strings.Join(distinct, " AND "),
		Basis:      "split: one file per licence, none naming a choice",
	}
}

// readCompoundResult turns the prose of a compound licence file into an
// expression. The alternatives say which texts are in the file; only the file
// says how they relate, and where it does not say, the reading is stated as
// conservative rather than made silently.
func readCompoundResult(primary LicenseFileEntry, alts []AltMatch, text string) ExpressionResult {
	ids := make([]string, 0, len(alts)+1)
	ids = append(ids, primary.SPDX)
	for _, a := range alts {
		ids = append(ids, a.SPDX)
	}
	if len(dedupeSorted(ids)) < 2 {
		// The alternative names the same licence as the primary: one grant,
		// matched twice, and no relationship to state.
		return ExpressionResult{Expression: primary.SPDX}
	}

	if text == "" {
		// The text was not available to read. Say so and take the
		// conservative reading: every grant in the file applies.
		return ExpressionResult{
			Expression: strings.Join(dedupeSorted(ids), " AND "),
			Basis:      "conservative: several grants, file text unavailable to read",
		}
	}

	reading := ReadCompoundFile(text, ids)
	basis := reading.Shape.String() + ": " + reading.Evidence
	switch reading.Shape {
	case ShapeElection:
		return ExpressionResult{
			Expression: strings.Join(reading.Own, " OR "),
			Basis:      basis,
		}
	case ShapeBundledGrant:
		res := ExpressionResult{
			Expression:   strings.Join(reading.Own, " AND "),
			Basis:        basis + " — bundled: " + strings.Join(reading.Bundled, ", "),
			BundledSPDXs: reading.Bundled,
		}
		// The most-covered text in the file can be the bundled one: a full
		// BSD-3-Clause carried beside a short MIT grant covers more of the
		// file than the grant the module actually makes. The module's own
		// licence is the one it makes, so the primary follows the reading.
		if len(reading.Own) == 1 && reading.Own[0] != primary.SPDX {
			res.PrimarySPDX = reading.Own[0]
		}
		return res
	case ShapeSplit:
		return ExpressionResult{
			Expression: strings.Join(reading.Own, " AND "),
			Basis:      basis,
		}
	case ShapeUnstated:
		return ExpressionResult{
			Expression: strings.Join(reading.Own, " AND "),
			Basis:      "conservative: " + reading.Evidence,
		}
	}
	return ExpressionResult{Expression: primary.SPDX}
}

// rootPaths lists the entries' paths in order for a basis string.
func rootPaths(roots []LicenseFileEntry) []string {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		out = append(out, r.Path)
	}
	sort.Strings(out)
	return out
}

// DisjunctionArms returns the distinct arms of a purely disjunctive SPDX
// expression ("A OR B", "A OR B OR C"): the licences the consumer may elect
// between. It returns nil for an empty expression, a single identifier, or an
// expression carrying any non-OR operator (AND/WITH) — those are conjunctive
// obligations, not an election.
func DisjunctionArms(expr string) []string {
	if expr == "" || strings.Contains(expr, " AND ") || strings.Contains(expr, " WITH ") {
		return nil
	}
	parts := strings.Split(expr, " OR ")
	seen := make(map[string]bool, len(parts))
	arms := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		arms = append(arms, p)
	}
	if len(arms) < 2 {
		return nil
	}
	sort.Strings(arms)
	return arms
}

// ConjunctionArms returns the distinct arms of a purely conjunctive SPDX
// expression ("A AND B", "A AND B AND C"): the licences a consumer must satisfy
// together. It returns nil for an empty expression, a single identifier, or an
// expression carrying any non-AND operator (OR/WITH) — a mixed expression names
// an election this cannot fold, and a WITH exception qualifies an arm rather
// than adding one.
//
// It is the counterpart of DisjunctionArms, and the two are exclusive by
// construction: an expression yields arms to at most one of them.
func ConjunctionArms(expr string) []string {
	if expr == "" || strings.Contains(expr, " OR ") || strings.Contains(expr, " WITH ") {
		return nil
	}
	parts := strings.Split(expr, " AND ")
	seen := make(map[string]bool, len(parts))
	arms := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		arms = append(arms, p)
	}
	if len(arms) < 2 {
		return nil
	}
	sort.Strings(arms)
	return arms
}

// SoleIdentifier returns the one licence identifier an expression names, or ""
// when it is empty or carries any operator (OR/AND/WITH). It answers a question
// DisjunctionArms cannot: an expression such as "Apache-2.0" derived from a
// module whose status is Multiple — an omnibus attribution file bundling
// third-party texts — names a single determined licence, and a consumer of the
// expression should read it as such rather than as an unsettled identity.
func SoleIdentifier(expr string) string {
	expr = strings.TrimSpace(expr)
	if expr == "" ||
		strings.Contains(expr, " OR ") ||
		strings.Contains(expr, " AND ") ||
		strings.Contains(expr, " WITH ") {
		return ""
	}
	return expr
}

// hasDualLicenseNaming reports whether any root entry uses a license file name
// that indicates the module is dual-licensed. Modules with such names intend
// the consumer to select one license. Three naming conventions signal this:
// a stem-prefixed name (LICENSE-MIT, COPYING-BSD), the reversed form
// (MIT-LICENSE, MIT-LICENSE.txt, GO-LICENSE), and a bare licence-name
// shorthand (GPLv2, GPLv3, APLv2, APACHE-LICENSE-2.0) — each names the
// specific licence the file grants, which is the per-licence naming a
// dual-licensed module uses (gorhill/cronexpr ships APLv2 beside GPLv3;
// sergi/go-diff ships APACHE-LICENSE-2.0 beside a plain MIT LICENSE).
func hasDualLicenseNaming(entries []LicenseFileEntry) bool {
	for _, e := range entries {
		base := e.Path
		if idx := strings.LastIndex(e.Path, "/"); idx >= 0 {
			base = e.Path[idx+1:]
		}
		upper := strings.ToUpper(base)
		switch upper {
		case "GPLV2", "GPLV3", "APLV2", "APACHE-LICENSE-2.0":
			return true
		}
		for _, prefix := range []string{"LICENSE-", "LICENCE-", "COPYING-"} {
			if strings.HasPrefix(upper, prefix) {
				return true
			}
		}
		// Reversed form: <NAME>-LICENSE[.ext] names the licence in NAME.
		for _, stem := range []string{"LICENSE", "LICENCE"} {
			idx := strings.Index(upper, "-"+stem)
			if idx <= 0 {
				continue
			}
			rest := upper[idx+1+len(stem):]
			if rest == "" || strings.HasPrefix(rest, ".") {
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

// IsNoticeFileName reports whether the path's base name is a NOTICE file.
// A NOTICE file is an attribution document, not a licence grant: it carries no
// identifier of its own, and Apache-2.0 section 4(d) requires it to travel with
// the work, so a consumer reproduces it verbatim without labelling it a licence.
func IsNoticeFileName(relPath string) bool { return exprIsNoticeName(relPath) }

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
