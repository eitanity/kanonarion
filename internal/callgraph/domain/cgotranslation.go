package domain

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// CgoTranslationGap is a TinyGo cgo package that failed to type-check because
// kanonarion's translation of its C declarations refused some of them. It is
// kanonarion's limit, like a lowering gap, so it files no cause of its own.
type CgoTranslationGap struct {
	// Packages failed on the gap alone; Mixed also have their own compile errors.
	Packages, Mixed []string
	// Legacy is a record written before the gap had a clause: its detail quotes a
	// refusal and filed it as the module's.
	Legacy bool
}

// cgoRefusal matches every refusal of the TinyGo cgo translation that tinygo
// itself would not make, after the position the loader prefixes; group 2 is
// the C name a refusal names. A macro that is not a constant is left out:
// TinyGo refuses it too.
var cgoRefusal = regexp.MustCompile(`(?:^|: )(C\.(\S+): .+ is a C type this analysis does not translate` +
	`|#cgo CFLAGS lines are not read by this analysis` +
	`|reading the integer types of the preamble's enums: .*` +
	`|internal error: did not find Go type for C type \S+)$`)

// cgoRefusalPhrases are the refusals' fixed words, which a detail truncated to
// its first errors still carries.
var cgoRefusalPhrases = []string{
	" is a C type this analysis does not translate",
	"#cgo CFLAGS lines are not read by this analysis",
	"reading the integer types of the preamble's enums: ",
	"internal error: did not find Go type for C type ",
}

const cgoGapLead = "kanonarion's cgo translation does not cover what "

var cgoGapClause = regexp.MustCompile(regexp.QuoteMeta(cgoGapLead) + `(\S+) uses(, beside its own compile errors)?: `)

// SplitCgoTranslationErrors sorts one package's load errors into the
// translation's refusals (as stated, without position), the type errors that
// follow from them, and the rest. A follower names the identifier _Cgo_<name>
// of a refused C name: only the rewrite of C.<name> spells it, and the refusal
// is why it has no declaration.
func SplitCgoTranslationErrors(errs []string) (refusals, followers, rest []string) {
	var names []string
	for _, e := range errs {
		m := cgoRefusal.FindStringSubmatch(e)
		if m == nil {
			continue
		}
		if !slices.Contains(refusals, m[1]) {
			refusals = append(refusals, m[1])
		}
		if m[2] != "" {
			names = append(names, regexp.QuoteMeta("_Cgo_"+m[2]))
		}
	}
	var follower *regexp.Regexp
	if len(names) > 0 {
		follower = regexp.MustCompile(`(?:^|[^\w$!])(?:` + strings.Join(names, "|") + `)(?:$|[^\w])`)
	}
	for _, e := range errs {
		switch {
		case cgoRefusal.MatchString(e):
		case follower != nil && follower.MatchString(e):
			followers = append(followers, e)
		default:
			rest = append(rest, e)
		}
	}
	return refusals, followers, rest
}

// CgoTranslationGapClause states the gap for one package; mixed says the
// package also has compile errors of its own, which the detail goes on to give.
func CgoTranslationGapClause(pkg string, refusals []string, mixed bool) string {
	beside := ""
	if mixed {
		beside = ", beside its own compile errors"
	}
	shown := refusals
	more := ""
	if len(shown) > 3 {
		shown, more = shown[:3], " and "+strconv.Itoa(len(refusals)-3)+" more"
	}
	return cgoGapLead + pkg + " uses" + beside + ": " + strings.Join(shown, "; ") + more
}

// ReadCgoTranslationGap reads the gap out of a record's failure detail.
func ReadCgoTranslationGap(detail string) (CgoTranslationGap, bool) {
	var g CgoTranslationGap
	for _, m := range cgoGapClause.FindAllStringSubmatch(detail, -1) {
		if m[2] != "" {
			g.Mixed = append(g.Mixed, m[1])
		} else {
			g.Packages = append(g.Packages, m[1])
		}
	}
	if len(g.Packages)+len(g.Mixed) > 0 {
		return g, true
	}
	for _, p := range cgoRefusalPhrases {
		if strings.Contains(detail, p) {
			return CgoTranslationGap{Legacy: true}, true
		}
	}
	return CgoTranslationGap{}, false
}

// Statement says whose gap it is. A read prints it without the detail, so it
// points at callgraph-show, which names the declarations.
func (g CgoTranslationGap) Statement() string {
	return "The gap is in kanonarion's cgo translation, not in the source: it does not translate C declarations the package uses (callgraph-show names them)."
}

// Remedy says what closes it, and that nothing in the source does.
func (g CgoTranslationGap) Remedy() string {
	return "No change to the source is owed. A kanonarion whose translation covers them re-measures this record on its next run."
}

// DroppedBy reports whether pkg's edges are missing because of the gap alone.
func (g CgoTranslationGap) DroppedBy(pkg string) bool {
	return slices.Contains(g.Packages, pkg)
}
