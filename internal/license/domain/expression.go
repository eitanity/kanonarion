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
// - Multiple root files each naming the licence it grants (LICENSE-MIT +
// LICENSE-APACHE) → OR expression (consumer picks one); see
// fileNamesElectLicence
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
	// One file per licence, each file naming its own licence, is how a module
	// offers a choice. Otherwise, all licences genuinely apply.
	if fileNamesElectLicence(roots) {
		return ExpressionResult{
			Expression: strings.Join(distinct, " OR "),
			Basis:      "election: one file per licence (" + strings.Join(rootPaths(roots), ", ") + ")",
		}
	}
	return ExpressionResult{
		Expression: strings.Join(distinct, " AND "),
		Basis:      BasisSeparateGrants,
	}
}

// BasisSeparateGrants is the ExpressionBasis of a conjunction whose arms were
// each read off their own root licence file — LICENSE beside LICENSE.docs,
// LICENSE.libyaml, LICENSE.Golang. It is written here and read by
// ArmsAreSeparatelyGranted so the producer and the consumer of the fact cannot
// drift apart over a string literal.
const BasisSeparateGrants = "split: one file per licence, none naming a choice"

// ArmsAreSeparatelyGranted reports whether a conjunction's arms were granted
// one file each, which decides what may be said about the obligations.
//
// It answers from the recorded basis alone, never from the file list: the
// basis is the pipeline's statement of what it read, and re-deriving the shape
// from the files would be a second reading free to disagree with the one the
// record carries.
//
// The distinction is not cosmetic. Where each arm has its own file, the file
// names what that arm covers — LICENSE.docs is documentation, LICENSE.libyaml
// is vendored C — and whether a consumer owes that arm depends on whether the
// artefact it covers reaches their binary, which nothing here can determine.
// Merging those arms into one set would assert that the consumer owes all of
// them. Where one file grants several licences, nothing attributes coverage to
// anything, every grant in it governs the module's code, and the merged set is
// the honest answer.
func ArmsAreSeparatelyGranted(basis string) bool {
	return basis == BasisSeparateGrants
}

// ArmGrants maps each identifier a conjunctive expression names to the root
// licence files that grant it, so an arm can be published with the coverage
// evidence already in the record rather than as a bare identifier.
//
// The candidate filter is the one DeriveExpressionResult used to build the
// expression, so a path here is a file that actually contributed an arm — a
// vendored file, a NOTICE, or a nested licence is no more a grant of an arm
// now than it was then. Paths are sorted, and an arm no root file accounts for
// is absent rather than mapped to nothing.
func ArmGrants(expr string, entries []LicenseFileEntry) map[string][]string {
	arms := ConjunctionArms(expr)
	if len(arms) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(arms))
	for _, a := range arms {
		wanted[a] = true
	}
	out := make(map[string][]string, len(arms))
	for _, e := range entries {
		if e.IsVendored || e.SPDX == "" || !exprIsRootLevel(e.Path) || exprIsNoticeName(e.Path) {
			continue
		}
		if !wanted[e.SPDX] {
			continue
		}
		out[e.SPDX] = append(out[e.SPDX], e.Path)
	}
	if len(out) == 0 {
		return nil
	}
	for _, paths := range out {
		sort.Strings(paths)
	}
	return out
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

// fileNamesElectLicence reports whether the root files' names offer the
// consumer a choice: at least one file names the licence it grants, and no
// file carrying a licence-file stem names something else. A stem-prefixed or
// stem-suffixed name that is not a licence name — LICENSE-SQLITE_VEC,
// LICENSE-THIRD-PARTY — names the component the file covers, which is the
// opposite claim to an election, so one such file withdraws it for the module.
func fileNamesElectLicence(entries []LicenseFileEntry) bool {
	elects := false
	for _, e := range entries {
		if fileNameNamesItsLicence(e) {
			elects = true
			continue
		}
		if _, hasStem := licenceNameToken(e.Path); hasStem {
			return false
		}
	}
	return elects
}

// fileNameNamesItsLicence reports whether a root licence file's name names the
// licence the detector matched in that file. Only a name that resolves to that
// file's own identifier is evidence of per-licence naming; a name that resolves
// to anything else is naming something other than a licence.
func fileNameNamesItsLicence(e LicenseFileEntry) bool {
	token, _ := licenceNameToken(e.Path)
	if token == "" || e.SPDX == "" {
		return false
	}
	return resolveLicenceNameToken(token) == normaliseLicenceToken(e.SPDX)
}

// licenceNameToken returns the part of a root licence file's base name that
// would name a licence, and whether the name carries a licence-file stem.
// Three naming conventions put a licence name in a file name: a stem-prefixed
// name (LICENSE-MIT, COPYING-BSD), the reversed form (MIT-LICENSE.txt,
// APACHE-LICENSE-2.0), and a bare licence-name shorthand (GPLv3, APLv2). A
// generic name names no licence and is returned as no token at all.
//
// name is a root-level path, which is a base name: every caller reads it off a
// list exprIsRootLevel has already filtered.
func licenceNameToken(name string) (token string, hasStem bool) {
	upper := strings.ToUpper(name)
	for _, ext := range licenceFileTextExtensions {
		if strings.HasSuffix(upper, ext) {
			upper = upper[:len(upper)-len(ext)]
			break
		}
	}
	if licenceFileGenericNames[upper] {
		return "", false
	}
	for _, stem := range []string{"LICENSE-", "LICENCE-", "COPYING-"} {
		if strings.HasPrefix(upper, stem) {
			return upper[len(stem):], true
		}
	}
	for _, stem := range []string{"-LICENSE", "-LICENCE"} {
		if idx := strings.Index(upper, stem); idx > 0 {
			return upper[:idx] + upper[idx+len(stem):], true
		}
	}
	return upper, false
}

// licenceFileGenericNames are the names a module gives its licence file when it
// is not naming one licence among several. Beside a file that names one they
// decide nothing, in either direction.
var licenceFileGenericNames = map[string]bool{
	"LICENSE":   true,
	"LICENCE":   true,
	"COPYING":   true,
	"COPYRIGHT": true,
	"UNLICENSE": true,
}

// licenceFileTextExtensions are the extensions a licence file carries that are
// not part of its name. An unrecognised dotted suffix is left in place: it is
// as likely to be what the file covers (LICENSE.libyaml) as an extension.
var licenceFileTextExtensions = []string{".TXT", ".MD", ".MARKDOWN", ".RST", ".TEXT", ".HTML"}

// licenceNameAliases maps a normalised file-name token to the normalised SPDX
// identifier it names, for the short forms a file name uses in place of the
// identifier. A token absent here stands for itself.
var licenceNameAliases = map[string]string{
	"APACHE":     "APACHE20",
	"APACHE2":    "APACHE20",
	"APACHE20":   "APACHE20",
	"APLV2":      "APACHE20",
	"BSD":        "BSD3CLAUSE",
	"BSD3":       "BSD3CLAUSE",
	"BSD3CLAUSE": "BSD3CLAUSE",
	"BSD2":       "BSD2CLAUSE",
	"BSD2CLAUSE": "BSD2CLAUSE",
	"GPLV2":      "GPL20",
	"GPLV3":      "GPL30",
	"GO":         "BSD3CLAUSE",
	"SIL":        "OFL11",
	"OFL":        "OFL11",
}

// resolveLicenceNameToken returns the normalised SPDX identifier a file-name
// token names.
func resolveLicenceNameToken(token string) string {
	n := normaliseLicenceToken(token)
	if id, ok := licenceNameAliases[n]; ok {
		return id
	}
	return n
}

// normaliseLicenceToken upper-cases a token and drops the separators a file
// name and an SPDX identifier spell differently.
func normaliseLicenceToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', '_', '.', ' ':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
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
